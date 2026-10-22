package httpui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/solkin/sebastian/internal/fileops"
	"github.com/solkin/sebastian/internal/gateway"
)

const defaultPageSize = 100
const maxPageSize = 1000

// listBatch is how many directory entries one read returns while listing.
const listBatch = 4096

// fileEntry represents a single file or directory in a listing response.
type fileEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

// listResponse is the JSON response for directory listings.
type listResponse struct {
	Path    string      `json:"path"`
	Entries []fileEntry `json:"entries"`
	Total   int         `json:"total"`
}

// errNULByte rejects a path no file can have before it reaches the filesystem,
// where it would fail as an I/O error.
var errNULByte = errors.New("path contains a NUL byte")

// resolvePath validates a client path and returns its cleaned root-relative
// form ("" for the root itself) and the full filesystem path. It returns an
// error for paths that escape rootDir or enter a reserved namespace.
func (g *Gateway) resolvePath(relPath string) (rel, full string, err error) {
	if strings.IndexByte(relPath, 0) >= 0 {
		return "", "", errNULByte
	}
	return gateway.SafePath(g.rootDir, relPath)
}

// handleList returns a paginated JSON listing of a directory.
// Query parameters: path, offset (default 0), limit (default 100, max 1000).
// Entries are sorted: directories first, then files, by name within each group.
// Only the entries on the requested page are stat'ed.
func (g *Gateway) handleList(w http.ResponseWriter, r *http.Request) {
	dirPath := r.URL.Query().Get("path")
	offset := parseIntParam(r, "offset", 0)
	limit := parseIntParam(r, "limit", defaultPageSize)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > maxPageSize {
		limit = defaultPageSize
	}

	dirRel, fullPath, err := g.resolvePath(dirPath)
	if err != nil {
		g.invalidPath(w, dirPath, err)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		if invalidName(err) {
			g.invalidPath(w, dirPath, err)
			return
		}
		jsonError(w, http.StatusNotFound, "directory not found")
		return
	}
	if !info.IsDir() {
		jsonError(w, http.StatusBadRequest, "not a directory")
		return
	}

	// Reading a directory of hundreds of thousands of names costs real time and
	// memory, and every page reads it whole. Bound how many run at once so a
	// burst of requests cannot take the server's memory with it; the rest wait
	// for a slot unless the client goes away.
	select {
	case g.listSem <- struct{}{}:
		defer func() { <-g.listSem }()
	case <-r.Context().Done():
		return
	}

	dirs, files, err := g.visibleNames(fullPath, dirRel)
	if err != nil {
		g.logger.Error("list failed", "path", dirRel, "error", err)
		jsonError(w, http.StatusInternalServerError, "failed to read directory")
		return
	}

	total := len(dirs) + len(files)

	// Build the page slice from the logical concatenation dirs+files.
	// Only stat the entries on the current page.
	var result []fileEntry
	end := offset + limit
	if end > total {
		end = total
	}
	for i := offset; i < end; i++ {
		name, isDir := "", i < len(dirs)
		if isDir {
			name = dirs[i]
		} else {
			name = files[i-len(dirs)]
		}
		fi, err := os.Lstat(filepath.Join(fullPath, name))
		if err != nil {
			continue
		}
		result = append(result, fileEntry{
			Name:    name,
			IsDir:   isDir,
			Size:    fi.Size(),
			ModTime: fi.ModTime().UTC().Format(time.RFC3339),
		})
	}

	cleanPath := filepath.ToSlash(filepath.Clean(dirPath))
	if cleanPath == "." || cleanPath == "/" {
		cleanPath = ""
	}
	cleanPath = strings.TrimPrefix(cleanPath, "/")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listResponse{
		Path:    cleanPath,
		Entries: result,
		Total:   total,
	})
}

// visibleNames returns the names of the visible subdirectories and of the
// other visible entries of the directory at fullPath, each sorted by name as
// os.ReadDir sorts them. dirRel is the directory's root-relative path, already
// validated by SafePath.
//
// Visibility is decided from the name and the entry type the directory read
// returned, without a stat per entry; only a symlink is looked up, because
// where it leads decides whether it may be shown. Entries are read in batches
// and only the names of visible ones are kept.
func (g *Gateway) visibleNames(fullPath, dirRel string) (dirs, files []string, err error) {
	d, err := os.Open(fullPath)
	if err != nil {
		return nil, nil, err
	}
	defer d.Close()
	for {
		batch, err := d.ReadDir(listBatch)
		for _, e := range batch {
			name := e.Name()
			if !g.visibleName(dirRel, name) {
				continue
			}
			typ := e.Type()
			if typ&fs.ModeSymlink != 0 && !gateway.IsClientVisiblePath(g.rootDir, filepath.Join(fullPath, name)) {
				continue
			}
			if typ.IsDir() {
				dirs = append(dirs, name)
			} else {
				files = append(files, name)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}
	slices.Sort(dirs)
	slices.Sort(files)
	return dirs, files, nil
}

// visibleName applies the namespace rules of gateway.IsClientVisiblePath to
// one entry of a listed directory, from its name alone: the reserved state
// directory at the root and the scratch files anywhere. For anything but a
// symlink the two agree exactly (TestList_VisibleNameMatchesGateway keeps
// them so). No directory entry can hold a NUL; it is refused all the same.
func (g *Gateway) visibleName(dirRel, name string) bool {
	return gateway.ClientVisibleName(dirRel, name)
}

func parseIntParam(r *http.Request, name string, defaultVal int) int {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

// handleDownload serves a file for download.
func (g *Gateway) handleDownload(w http.ResponseWriter, r *http.Request) {
	filePath := strings.TrimPrefix(r.URL.Path, "/_api/dl/")

	rel, fullPath, err := g.resolvePath(filePath)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	f, err := os.Open(fullPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || invalidName(err) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		g.logger.Error("download failed", "path", rel, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		g.logger.Error("download failed", "path", rel, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if info.IsDir() {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Build the header via mime.FormatMediaType so a filename containing quotes,
	// control characters, or non-ASCII cannot break out of the header value
	// (header injection) — it is properly quoted/encoded, with a safe fallback.
	name := filepath.Base(fullPath)
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": name})
	if disposition == "" {
		disposition = "attachment"
	}
	w.Header().Set("Content-Disposition", disposition)
	g.serveDownload(w, r, rel, info.ModTime(), f)
}

// serveDownload streams content and logs how the transfer ended. ServeContent
// reports nothing itself. A failed read of the file is the server's failure; a
// client that stops reading is routine — browsers cancel and re-request ranges
// all the time — and is not worth more than Debug.
func (g *Gateway) serveDownload(w http.ResponseWriter, r *http.Request, rel string, modTime time.Time, content io.ReadSeeker) {
	tracked := &readFailures{ReadSeeker: content}
	http.ServeContent(w, r, path.Base(rel), modTime, tracked)

	switch err := tracked.failure(); {
	case err != nil:
		g.logger.Error("download read failed", "path", rel, "error", err)
	case r.Context().Err() != nil:
		g.logger.Debug("download aborted by client", "path", rel, "error", context.Cause(r.Context()))
	}
}

// readFailures records the first failure reading the served file. It may be
// read from a goroutine ServeContent leaves behind for a multi-range response.
type readFailures struct {
	io.ReadSeeker
	mu  sync.Mutex
	err error
}

func (c *readFailures) Read(p []byte) (int, error) {
	n, err := c.ReadSeeker.Read(p)
	if err != nil && err != io.EOF {
		c.record(err)
	}
	return n, err
}

func (c *readFailures) Seek(offset int64, whence int) (int64, error) {
	n, err := c.ReadSeeker.Seek(offset, whence)
	if err != nil {
		c.record(err)
	}
	return n, err
}

func (c *readFailures) record(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
}

func (c *readFailures) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// handleMkdir creates a directory.
func (g *Gateway) handleMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Path == "" {
		jsonError(w, http.StatusBadRequest, "path is required")
		return
	}

	rel, fullPath, err := g.resolvePath(req.Path)
	if err != nil {
		g.invalidPath(w, req.Path, err)
		return
	}

	if err := fileops.Mkdir(g.rootDir, fullPath, 0o755, true); err != nil {
		g.mutationFailed(w, "mkdir", rel, err, "failed to create directory")
		return
	}

	g.logger.Info("directory created", "path", req.Path)
	jsonOK(w)
}

// handleRename renames a file or directory.
func (g *Gateway) handleRename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.From == "" || req.To == "" {
		jsonError(w, http.StatusBadRequest, "from and to are required")
		return
	}

	fromRel, fromFull, err := g.resolvePath(req.From)
	if err != nil {
		g.logger.Debug("rename refused", "from", req.From, "error", err)
		jsonError(w, http.StatusBadRequest, "invalid source path")
		return
	}

	toRel, toFull, err := g.resolvePath(req.To)
	if err != nil {
		g.logger.Debug("rename refused", "to", req.To, "error", err)
		jsonError(w, http.StatusBadRequest, "invalid destination path")
		return
	}

	// A path such as "apps/.." cleans to the root itself, which is never
	// renamed and never replaced.
	if fromRel == "" {
		jsonError(w, http.StatusBadRequest, "cannot rename root directory")
		return
	}
	if toRel == "" {
		jsonError(w, http.StatusBadRequest, "invalid destination path")
		return
	}

	if _, err := os.Stat(fromFull); err != nil {
		if invalidName(err) {
			g.mutationFailed(w, "rename", fromRel, err, "")
			return
		}
		jsonError(w, http.StatusNotFound, "source not found")
		return
	}

	// Ensure parent directory of destination exists.
	if err := fileops.Mkdir(g.rootDir, filepath.Dir(toFull), 0o755, true); err != nil {
		g.mutationFailed(w, "rename", toRel, err, "failed to create parent directory")
		return
	}

	if err := fileops.Rename(g.rootDir, fromFull, toFull); err != nil {
		g.mutationFailed(w, "rename", fromRel+" -> "+toRel, err, "rename failed")
		return
	}

	g.logger.Info("renamed", "from", req.From, "to", req.To)
	jsonOK(w)
}

// handleDelete deletes a file or directory.
func (g *Gateway) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.Path == "" || req.Path == "/" || req.Path == "." {
		jsonError(w, http.StatusBadRequest, "cannot delete root directory")
		return
	}

	rel, fullPath, err := g.resolvePath(req.Path)
	if err != nil {
		g.invalidPath(w, req.Path, err)
		return
	}
	// "apps/.." and the like clean to the root itself. Removing it would
	// delete the whole served directory.
	if rel == "" {
		jsonError(w, http.StatusBadRequest, "cannot delete root directory")
		return
	}

	if _, err := os.Stat(fullPath); err != nil {
		if invalidName(err) {
			g.mutationFailed(w, "delete", rel, err, "")
			return
		}
		jsonError(w, http.StatusNotFound, "not found")
		return
	}

	if err := fileops.Remove(g.rootDir, fullPath, true); err != nil {
		g.mutationFailed(w, "delete", rel, err, "delete failed")
		return
	}

	g.logger.Info("deleted", "path", req.Path)
	jsonOK(w)
}

// invalidPath answers a path that resolvePath refused. Its reason stays in the
// log: it can name absolute paths.
func (g *Gateway) invalidPath(w http.ResponseWriter, requested string, err error) {
	g.logger.Debug("invalid path", "path", requested, "error", err)
	jsonError(w, http.StatusBadRequest, "invalid path")
}

// mutationFailed answers a failed change to the volume. The client gets a
// status that says whose mistake it was and a message without filesystem
// paths (see failureStatus); the log gets the error itself — at Error when the
// server failed, at Debug when the request could never have succeeded.
func (g *Gateway) mutationFailed(w http.ResponseWriter, op, name string, err error, fallback string) {
	status, msg := failureStatus(err, fallback)
	if status >= http.StatusInternalServerError {
		g.logger.Error(op+" failed", "path", name, "error", err)
	} else {
		g.logger.Debug(op+" refused", "path", name, "status", status, "error", err)
	}
	jsonError(w, status, msg)
}

// failureStatus maps a failed filesystem operation to a status and a generic
// message. The error text itself is never sent: it names absolute paths. A
// name the volume cannot hold is a bad request and a clash with what is there
// is a conflict; anything else is the server's failure, reported as fallback.
func failureStatus(err error, fallback string) (int, string) {
	switch {
	case invalidName(err):
		return http.StatusBadRequest, "invalid path"
	case errors.Is(err, fs.ErrNotExist):
		return http.StatusNotFound, "not found"
	case errors.Is(err, fs.ErrExist), errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.EISDIR):
		return http.StatusConflict, "conflicts with an existing file or directory"
	}
	if fallback == "" {
		fallback = "operation failed"
	}
	return http.StatusInternalServerError, fallback
}

// invalidName reports whether err says a name cannot exist on the volume: it
// holds a NUL byte, or the filesystem refuses it (EINVAL, ENAMETOOLONG, EILSEQ
// for bytes it cannot store).
func invalidName(err error) bool {
	return errors.Is(err, errNULByte) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENAMETOOLONG) ||
		errors.Is(err, syscall.EILSEQ)
}

func jsonOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
