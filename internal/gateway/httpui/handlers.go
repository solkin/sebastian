package httpui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
)

const defaultPageSize = 100
const maxPageSize = 1000

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

// resolvePath validates a relative path and returns the full filesystem path.
// Returns an error for paths that escape rootDir.
func (g *Gateway) resolvePath(relPath string) (string, error) {
	_, fullPath, err := gateway.SafePath(g.rootDir, relPath)
	return fullPath, err
}

// handleList returns a paginated JSON listing of a directory.
// Query parameters: path, offset (default 0), limit (default 100, max 1000).
// Entries are sorted: directories first, then files, alphabetically within each group.
// Info() (stat syscall) is only called for entries on the current page.
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

	fullPath, err := g.resolvePath(dirPath)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		jsonError(w, http.StatusNotFound, "directory not found")
		return
	}
	if !info.IsDir() {
		jsonError(w, http.StatusBadRequest, "not a directory")
		return
	}

	rawEntries, err := os.ReadDir(fullPath)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to read directory")
		return
	}

	var dirs, files []os.DirEntry
	for _, e := range rawEntries {
		if e.IsDir() {
			dirs = append(dirs, e)
		} else {
			files = append(files, e)
		}
	}

	total := len(dirs) + len(files)

	var result []fileEntry
	end := offset + limit
	if end > total {
		end = total
	}
	for i := offset; i < end; i++ {
		var e os.DirEntry
		if i < len(dirs) {
			e = dirs[i]
		} else {
			e = files[i-len(dirs)]
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		result = append(result, fileEntry{
			Name:    e.Name(),
			IsDir:   e.IsDir(),
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

	fullPath, err := g.resolvePath(filePath)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil || info.IsDir() {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	f, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(fullPath)))
	http.ServeContent(w, r, filepath.Base(fullPath), info.ModTime(), f)
}

// handleUpload accepts multipart file uploads.
func (g *Gateway) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<30) // 1 GB limit

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonError(w, http.StatusBadRequest, "failed to parse upload")
		return
	}

	targetDir := r.FormValue("path")
	dirFullPath, err := g.resolvePath(targetDir)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := os.MkdirAll(dirFullPath, 0o755); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create directory")
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		jsonError(w, http.StatusBadRequest, "no files provided")
		return
	}

	relpaths := r.MultipartForm.Value["relpaths"]

	absSync, _ := filepath.Abs(g.rootDir)

	for i, fh := range files {
		name := fh.Filename
		if i < len(relpaths) && relpaths[i] != "" {
			name = relpaths[i]
		}

		cleanName := filepath.ToSlash(filepath.Clean(name))
		cleanName = strings.TrimPrefix(cleanName, "/")
		if cleanName == "" || cleanName == "." || strings.HasPrefix(cleanName, "../") {
			jsonError(w, http.StatusBadRequest, "invalid file name")
			return
		}

		destPath := filepath.Join(dirFullPath, filepath.FromSlash(cleanName))
		absDest, _ := filepath.Abs(destPath)
		if !strings.HasPrefix(absDest, absSync+string(filepath.Separator)) {
			jsonError(w, http.StatusBadRequest, "invalid file name")
			return
		}

		destDir := filepath.Dir(destPath)
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to create directory")
			return
		}

		src, err := fh.Open()
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "failed to read uploaded file")
			return
		}

		tmpPath := filepath.Join(destDir, ".seb-tmp-upload-"+filepath.Base(destPath))
		dst, err := os.Create(tmpPath)
		if err != nil {
			src.Close()
			jsonError(w, http.StatusInternalServerError, "failed to create file")
			return
		}

		_, copyErr := io.Copy(dst, src)
		src.Close()
		dst.Close()

		if copyErr != nil {
			os.Remove(tmpPath)
			jsonError(w, http.StatusInternalServerError, "failed to write file")
			return
		}

		if err := os.Rename(tmpPath, destPath); err != nil {
			os.Remove(tmpPath)
			jsonError(w, http.StatusInternalServerError, "failed to save file")
			return
		}

		g.logger.Info("file uploaded", "name", cleanName, "dir", targetDir)
	}

	jsonOK(w)
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

	fullPath, err := g.resolvePath(req.Path)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := os.MkdirAll(fullPath, 0o755); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create directory")
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

	fromFull, err := g.resolvePath(req.From)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid source: "+err.Error())
		return
	}

	toFull, err := g.resolvePath(req.To)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid destination: "+err.Error())
		return
	}

	if _, err := os.Stat(fromFull); err != nil {
		jsonError(w, http.StatusNotFound, "source not found")
		return
	}

	if err := os.MkdirAll(filepath.Dir(toFull), 0o755); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create parent directory")
		return
	}

	if err := os.Rename(fromFull, toFull); err != nil {
		jsonError(w, http.StatusInternalServerError, "rename failed: "+err.Error())
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

	fullPath, err := g.resolvePath(req.Path)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := os.Stat(fullPath); err != nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}

	if err := os.RemoveAll(fullPath); err != nil {
		jsonError(w, http.StatusInternalServerError, "delete failed: "+err.Error())
		return
	}

	g.logger.Info("deleted", "path", req.Path)
	jsonOK(w)
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
