package webdav

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/solkin/sebastian/internal/fileops"
	"github.com/solkin/sebastian/internal/gateway"
)

// errUploadTooLarge is returned by the COPY copier when the configured upload
// cap would be exceeded.
var errUploadTooLarge = errors.New("upload exceeds maximum size")
var errDestinationExists = errors.New("destination already exists")
var errRecursiveReplacement = errors.New("destination is inside the source")

// propEntry holds the properties for a single resource in a PROPFIND response.
type propEntry struct {
	Href         string
	DisplayName  string
	IsDir        bool
	Size         int64
	LastModified time.Time
	ContentType  string
}

// --- WebDAV method handlers ---

// handleOptions responds with supported WebDAV methods and DAV compliance class.
func (g *Gateway) handleOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", davMethods)
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("MS-Author-Via", "DAV")
	w.WriteHeader(http.StatusOK)
}

// handlePropfind lists properties for a resource and optionally its children.
// Depth: 0 = resource only, 1 = resource + immediate children, infinity = all.
func (g *Gateway) handlePropfind(w http.ResponseWriter, r *http.Request) {
	relName, fullPath, err := g.resolvePath(r.URL.Path)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if err != nil {
		g.logger.Error("propfind stat failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "1"
	}

	// Stream the multistatus response: write the parent entry, then page through
	// children with ReadDir(n) so a directory with very many entries is not fully
	// buffered in memory. The 207 status is committed before iterating, so any
	// mid-stream read error can only be logged, not turned into a 500.
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?>`)
	io.WriteString(w, `<D:multistatus xmlns:D="DAV:">`)

	writePropResponse(w, makePropEntry(relName, info))

	if info.IsDir() && depth != "0" {
		f, derr := os.Open(fullPath)
		if derr != nil {
			g.logger.Error("propfind open dir failed", "path", relName, "error", derr)
		} else {
			defer f.Close()
			for {
				children, rerr := f.ReadDir(512)
				for _, child := range children {
					childRel := child.Name()
					if relName != "" {
						childRel = relName + "/" + childRel
					}
					if !gateway.IsClientVisiblePath(g.rootDir, filepath.Join(fullPath, child.Name())) {
						continue
					}
					childInfo, ierr := child.Info()
					if ierr != nil {
						continue
					}
					writePropResponse(w, makePropEntry(childRel, childInfo))
				}
				if rerr != nil {
					if rerr != io.EOF {
						g.logger.Error("propfind readdir failed", "path", relName, "error", rerr)
					}
					break
				}
			}
		}
	}

	io.WriteString(w, `</D:multistatus>`)
	g.logger.Debug("propfind", "path", relName, "depth", depth)
}

// handleProppatch accepts property changes. This is a stub that acknowledges
// all changes without persisting them (sufficient for macOS Finder and most clients).
func (g *Gateway) handleProppatch(w http.ResponseWriter, r *http.Request) {
	relName, fullPath, err := g.resolvePath(r.URL.Path)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if g.lockBlocked(w, r, relName) {
		return
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	href := hrefFromPath(relName, false)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>`)
	fmt.Fprint(w, `<D:multistatus xmlns:D="DAV:">`)
	fmt.Fprintf(w, `<D:response><D:href>%s</D:href>`, xmlEscapeString(href))
	fmt.Fprint(w, `<D:propstat><D:prop/>`)
	fmt.Fprint(w, `<D:status>HTTP/1.1 200 OK</D:status>`)
	fmt.Fprint(w, `</D:propstat></D:response>`)
	fmt.Fprint(w, `</D:multistatus>`)
}

// handleGet serves file content. Uses http.ServeContent (not ServeFile)
// to avoid the built-in /index.html redirect.
func (g *Gateway) handleGet(w http.ResponseWriter, r *http.Request) {
	relName, fullPath, err := g.resolvePath(r.URL.Path)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if err != nil {
		g.logger.Error("get stat failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if info.IsDir() {
		http.Error(w, "Not a file", http.StatusMethodNotAllowed)
		return
	}

	f, err := os.Open(fullPath)
	if err != nil {
		g.logger.Error("get open failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	g.logger.Debug("serving file", "path", relName, "size", info.Size())
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, filepath.Base(fullPath), info.ModTime(), f)
}

// handleHead returns metadata for a resource.
func (g *Gateway) handleHead(w http.ResponseWriter, r *http.Request) {
	relName, fullPath, err := g.resolvePath(r.URL.Path)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if err != nil {
		g.logger.Error("head stat failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if info.IsDir() {
		w.Header().Set("Content-Type", "httpd/unix-directory")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	}
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
}

// handlePut writes a file (atomic via temp file + rename).
func (g *Gateway) handlePut(w http.ResponseWriter, r *http.Request) {
	relName, fullPath, err := g.resolvePath(r.URL.Path)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if relName == "" {
		http.Error(w, "Cannot write to root", http.StatusForbidden)
		return
	}

	if g.lockBlocked(w, r, relName) {
		return
	}

	if g.config.MaxUploadBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, g.config.MaxUploadBytes)
	}

	// Create parent directories.
	dir := filepath.Dir(fullPath)
	if err := fileops.Mkdir(g.rootDir, dir, 0o755, true); err != nil {
		g.logger.Error("put mkdir failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Check if resource already exists (for status code).
	_, statErr := os.Stat(fullPath)
	isNew := os.IsNotExist(statErr)

	// Write to temp file, then rename.
	tmpFile, err := fileops.CreateTemp(dir, ".seb-tmp-*")
	if err != nil {
		g.logger.Error("put create temp failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer fileops.ReleaseTemp(tmpFile)
	tmpPath := tmpFile.Name()

	if _, err := io.Copy(tmpFile, r.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		g.logger.Error("put write failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	if err := fileops.Publish(g.rootDir, tmpPath, fullPath); err != nil {
		os.Remove(tmpPath)
		g.logger.Error("put rename failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	g.logger.Info("file written", "path", relName)
	if isNew {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleDelete removes a file or directory.
func (g *Gateway) handleDelete(w http.ResponseWriter, r *http.Request) {
	relName, fullPath, err := g.resolvePath(r.URL.Path)
	if err != nil || relName == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if g.lockBlocked(w, r, relName) {
		return
	}

	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if err != nil {
		g.logger.Error("delete stat failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if info.IsDir() {
		if err := fileops.Remove(g.rootDir, fullPath, true); err != nil {
			g.logger.Error("delete dir failed", "path", relName, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		if err := fileops.Remove(g.rootDir, fullPath, false); err != nil {
			g.logger.Error("delete file failed", "path", relName, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	g.logger.Info("deleted", "path", relName)
	w.WriteHeader(http.StatusNoContent)
}

// handleMkcol creates a directory (collection).
func (g *Gateway) handleMkcol(w http.ResponseWriter, r *http.Request) {
	relName, fullPath, err := g.resolvePath(r.URL.Path)
	if err != nil || relName == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if g.lockBlocked(w, r, relName) {
		return
	}

	// MKCOL with a request body is unsupported (RFC 4918 §9.3). Peek for any body
	// byte so chunked requests (ContentLength == -1) are rejected too.
	probe := make([]byte, 1)
	if n, _ := r.Body.Read(probe); n > 0 {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	// Parent must exist.
	parent := filepath.Dir(fullPath)
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		http.Error(w, "Conflict", http.StatusConflict)
		return
	}

	if _, err := os.Stat(fullPath); err == nil {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := fileops.Mkdir(g.rootDir, fullPath, 0o755, false); err != nil {
		g.logger.Error("mkcol failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	g.logger.Info("directory created", "path", relName)
	w.WriteHeader(http.StatusCreated)
}

// handleMove moves or renames a resource.
func (g *Gateway) handleMove(w http.ResponseWriter, r *http.Request) {
	srcRel, srcFull, err := g.resolvePath(r.URL.Path)
	if err != nil || srcRel == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	dstRel, dstFull, err := g.resolveDestination(r)
	if errors.Is(err, errMissingDestination) || errors.Is(err, errBadDestination) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err != nil || dstRel == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	overwrite, ok := parseOverwrite(r.Header.Get("Overwrite"))
	if !ok {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// MOVE mutates both source (removed) and destination (created/overwritten).
	if g.lockBlocked(w, r, srcRel) || g.lockBlocked(w, r, dstRel) {
		return
	}

	if _, err := os.Stat(srcFull); os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Reject moving a resource onto itself or into its own subtree.
	if isSameOrUnder(dstFull, srcFull) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	_, statErr := os.Stat(dstFull)
	dstExists := statErr == nil

	if dstExists && !overwrite {
		http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
		return
	}

	// Ensure parent of destination exists.
	if err := fileops.Mkdir(g.rootDir, filepath.Dir(dstFull), 0o755, true); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := fileops.Do(g.rootDir, func() error {
		exists, err := checkReplacementLocked(srcFull, dstFull, overwrite)
		if err != nil {
			return err
		}
		dstExists = exists
		if err := fileops.ReplaceLocked(g.rootDir, srcFull, dstFull); err != nil {
			return err
		}
		return errors.Join(fileops.SyncParents(filepath.Dir(srcFull), g.rootDir), fileops.SyncParents(filepath.Dir(dstFull), g.rootDir))
	}); err != nil {
		g.logger.Error("move failed", "from", srcRel, "to", dstRel, "error", err)
		status := replacementErrorStatus(err)
		http.Error(w, http.StatusText(status), status)
		return
	}

	g.logger.Info("moved", "from", srcRel, "to", dstRel)
	if dstExists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

// handleCopy copies a resource.
func (g *Gateway) handleCopy(w http.ResponseWriter, r *http.Request) {
	srcRel, srcFull, err := g.resolvePath(r.URL.Path)
	if err != nil || srcRel == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	dstRel, dstFull, err := g.resolveDestination(r)
	if errors.Is(err, errMissingDestination) || errors.Is(err, errBadDestination) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err != nil || dstRel == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	overwrite, ok := parseOverwrite(r.Header.Get("Overwrite"))
	if !ok {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// COPY mutates only the destination.
	if g.lockBlocked(w, r, dstRel) {
		return
	}

	srcInfo, err := os.Stat(srcFull)
	if os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Reject copying a resource onto itself or into its own subtree, which would
	// otherwise recurse without bound and exhaust the disk.
	if isSameOrUnder(dstFull, srcFull) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	_, statErr := os.Stat(dstFull)
	dstExists := statErr == nil

	if dstExists && !overwrite {
		http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
		return
	}

	// Ensure parent of destination exists.
	if err := fileops.Mkdir(g.rootDir, filepath.Dir(dstFull), 0o755, true); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	cp := &copier{limit: g.config.MaxUploadBytes}
	copyErr := fileops.Do(g.rootDir, func() error {
		exists, err := checkReplacementLocked(srcFull, dstFull, overwrite)
		if err != nil {
			return err
		}
		dstExists = exists
		if err := fileops.CopyReplaceLocked(g.rootDir, dstFull, func(stage string) error {
			if srcInfo.IsDir() {
				return cp.copyDir(srcFull, stage)
			}
			return cp.copyFile(srcFull, stage)
		}); err != nil {
			return err
		}
		return fileops.SyncParents(filepath.Dir(dstFull), g.rootDir)
	})
	if copyErr != nil {
		g.logger.Error("copy failed", "from", srcRel, "to", dstRel, "error", copyErr)
		status := replacementErrorStatus(copyErr)
		http.Error(w, http.StatusText(status), status)
		return
	}

	g.logger.Info("copied", "from", srcRel, "to", dstRel)
	if dstExists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

// handleLock creates (or refreshes) an exclusive write lock and is enforced by
// the mutating handlers via the If header. Locks are in-memory and single-node.
func (g *Gateway) handleLock(w http.ResponseWriter, r *http.Request) {
	relName, _, err := g.resolvePath(r.URL.Path)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	timeout := parseTimeout(r.Header.Get("Timeout"))

	// A LOCK carrying an If header and no body refreshes an existing lock rather
	// than creating a new one.
	if ifH := r.Header.Get("If"); ifH != "" {
		for token := range parseIfTokens(ifH) {
			if lk, ok := g.locks.refresh(token, timeout); ok && lk.covers(relName) {
				w.Header().Set("Lock-Token", "<"+lk.token+">")
				writeLockResponse(w, lk, http.StatusOK)
				return
			}
		}
	}

	// Drain the (optional) lock-info body so keep-alive stays healthy; the owner
	// element is not persisted.
	io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))

	depth := r.Header.Get("Depth")
	if depth != "0" {
		depth = "infinity"
	}

	lk, ok := g.locks.create(relName, depth, timeout)
	if !ok {
		http.Error(w, "Locked", http.StatusLocked)
		return
	}

	g.logger.Info("locked", "path", relName, "depth", depth)
	w.Header().Set("Lock-Token", "<"+lk.token+">")
	writeLockResponse(w, lk, http.StatusOK)
}

// handleUnlock releases the lock named by the Lock-Token header.
func (g *Gateway) handleUnlock(w http.ResponseWriter, r *http.Request) {
	token := strings.Trim(r.Header.Get("Lock-Token"), "<> ")
	if token == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !g.locks.unlock(token) {
		http.Error(w, "Conflict", http.StatusConflict)
		return
	}
	g.logger.Info("unlocked", "token", token)
	w.WriteHeader(http.StatusNoContent)
}

// writeLockResponse writes the lockdiscovery body returned by LOCK.
func writeLockResponse(w http.ResponseWriter, lk *lock, status int) {
	secs := int(time.Until(lk.expires).Seconds())
	if secs < 0 {
		secs = 0
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>`)
	fmt.Fprint(w, `<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>`)
	fmt.Fprint(w, `<D:locktype><D:write/></D:locktype>`)
	fmt.Fprint(w, `<D:lockscope><D:exclusive/></D:lockscope>`)
	fmt.Fprintf(w, `<D:depth>%s</D:depth>`, lk.depth)
	fmt.Fprint(w, `<D:owner/>`)
	fmt.Fprintf(w, `<D:timeout>Second-%d</D:timeout>`, secs)
	fmt.Fprintf(w, `<D:locktoken><D:href>%s</D:href></D:locktoken>`, xmlEscapeString(lk.token))
	fmt.Fprint(w, `</D:activelock></D:lockdiscovery></D:prop>`)
}

// --- Helpers ---

// makePropEntry creates a propEntry from a relative name and os.FileInfo.
func makePropEntry(relName string, info os.FileInfo) propEntry {
	e := propEntry{
		Href:         hrefFromPath(relName, info.IsDir()),
		DisplayName:  info.Name(),
		IsDir:        info.IsDir(),
		Size:         info.Size(),
		LastModified: info.ModTime(),
	}
	if relName == "" {
		e.DisplayName = "/"
	}
	if !info.IsDir() {
		e.ContentType = "application/octet-stream"
	}
	return e
}

// writePropResponse writes a single <D:response> element for a PROPFIND entry.
// The enclosing <D:multistatus> envelope is written by the caller so entries can
// be streamed one at a time.
func writePropResponse(w http.ResponseWriter, e propEntry) {
	fmt.Fprintf(w, `<D:response><D:href>%s</D:href>`, xmlEscapeString(e.Href))
	fmt.Fprint(w, `<D:propstat><D:prop>`)

	if e.IsDir {
		fmt.Fprint(w, `<D:resourcetype><D:collection/></D:resourcetype>`)
	} else {
		fmt.Fprint(w, `<D:resourcetype/>`)
	}

	fmt.Fprintf(w, `<D:displayname>%s</D:displayname>`, xmlEscapeString(e.DisplayName))

	if !e.IsDir {
		fmt.Fprintf(w, `<D:getcontentlength>%d</D:getcontentlength>`, e.Size)
		fmt.Fprintf(w, `<D:getcontenttype>%s</D:getcontenttype>`, xmlEscapeString(e.ContentType))
	}

	fmt.Fprintf(w, `<D:getlastmodified>%s</D:getlastmodified>`,
		e.LastModified.UTC().Format(http.TimeFormat))

	fmt.Fprint(w, `</D:prop>`)
	fmt.Fprint(w, `<D:status>HTTP/1.1 200 OK</D:status>`)
	fmt.Fprint(w, `</D:propstat></D:response>`)
}

// xmlEscapeString escapes a string for safe inclusion in XML content.
func xmlEscapeString(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// parseOverwrite interprets the WebDAV Overwrite header (RFC 4918 §10.6): absent
// or "T" means overwrite, "F" means do not, anything else is malformed.
func parseOverwrite(h string) (overwrite bool, ok bool) {
	switch h {
	case "", "T":
		return true, true
	case "F":
		return false, true
	default:
		return false, false
	}
}

// isSameOrUnder reports whether path is dir itself or lies within dir's subtree.
// It is used to reject COPY/MOVE whose destination is the source or a descendant
// of the source, which would otherwise recurse without bound.
func isSameOrUnder(path, dir string) bool {
	absPath, err1 := fileops.ResolvePath(path)
	absDir, err2 := fileops.ResolvePath(dir)
	if err1 != nil || err2 != nil {
		return true // cannot prove the operation is outside the source tree
	}
	return absPath == absDir || strings.HasPrefix(absPath, absDir+string(filepath.Separator))
}

// Recheck under the namespace lock: a concurrent request can create the
// destination or replace an alias after the early HTTP precondition checks.
func checkReplacementLocked(src, dst string, overwrite bool) (bool, error) {
	if isSameOrUnder(dst, src) {
		return false, errRecursiveReplacement
	}
	_, err := os.Lstat(dst)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !overwrite {
		return true, errDestinationExists
	}
	return true, nil
}

func replacementErrorStatus(err error) int {
	switch {
	case errors.Is(err, errDestinationExists):
		return http.StatusPreconditionFailed
	case errors.Is(err, errRecursiveReplacement):
		return http.StatusForbidden
	case errors.Is(err, errUploadTooLarge):
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}

// copier copies files/trees while enforcing an optional cumulative byte budget,
// so a COPY of a large tree cannot exceed the configured upload cap (or fill the
// disk without bound). limit == 0 means unlimited.
type copier struct {
	limit  int64
	copied int64
}

// copyFile copies a single file using a temp file + atomic rename.
func (c *copier) copyFile(src, dst string) error {
	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !si.Mode().IsRegular() {
		return fmt.Errorf("COPY source is not a regular file: %s", src)
	}
	if c.limit > 0 && c.copied+si.Size() > c.limit {
		return errUploadTooLarge
	}

	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()

	dir := filepath.Dir(dst)
	tmpFile, err := fileops.CreateTemp(dir, ".seb-tmp-*")
	if err != nil {
		return err
	}
	defer fileops.ReleaseTemp(tmpFile)
	tmpPath := tmpFile.Name()

	if _, err := io.Copy(tmpFile, sf); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chtimes(tmpPath, si.ModTime(), si.ModTime()); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := errors.Join(tmpFile.Sync(), tmpFile.Close()); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := fileops.SyncDir(filepath.Dir(dst)); err != nil {
		return err
	}
	c.copied += si.Size()
	return nil
}

// copyDir recursively copies a directory tree.
func (c *copier) copyDir(src, dst string) error {
	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, si.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		// Never follow symlinks discovered during recursion: dereferencing one
		// could copy the contents of a file outside rootDir into the destination.
		// The request/Destination paths are symlink-checked by the caller, but
		// entries found via ReadDir are not, so skip any link here.
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}

		if entry.IsDir() {
			if err := c.copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := c.copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return errors.Join(fileops.SyncDir(dst), fileops.SyncDir(filepath.Dir(dst)))
}

// stageReplace is also used by the replacement fault-injection tests.
func stageReplace(dst string, op func(string) error) error {
	return fileops.CopyReplaceLocked(filepath.Dir(dst), dst, op)
}
