package webdav

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

	var entries []propEntry

	entries = append(entries, makePropEntry(relName, info))

	if info.IsDir() && depth != "0" {
		children, err := os.ReadDir(fullPath)
		if err != nil {
			g.logger.Error("propfind readdir failed", "path", relName, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		for _, child := range children {
			childRel := child.Name()
			if relName != "" {
				childRel = relName + "/" + childRel
			}

			childInfo, err := child.Info()
			if err != nil {
				continue
			}

			entries = append(entries, makePropEntry(childRel, childInfo))
		}
	}

	g.logger.Debug("propfind", "path", relName, "depth", depth, "entries", len(entries))
	writeMultiStatus(w, entries)
}

// handleProppatch accepts property changes. This is a stub that acknowledges
// all changes without persisting them (sufficient for macOS Finder and most clients).
func (g *Gateway) handleProppatch(w http.ResponseWriter, r *http.Request) {
	relName, fullPath, err := g.resolvePath(r.URL.Path)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
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

	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		g.logger.Error("put mkdir failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_, statErr := os.Stat(fullPath)
	isNew := os.IsNotExist(statErr)

	tmpFile, err := os.CreateTemp(dir, ".seb-tmp-*")
	if err != nil {
		g.logger.Error("put create temp failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()

	if _, err := io.Copy(tmpFile, r.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		g.logger.Error("put write failed", "path", relName, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	if err := os.Rename(tmpPath, fullPath); err != nil {
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
		if err := os.RemoveAll(fullPath); err != nil {
			g.logger.Error("delete dir failed", "path", relName, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		if err := os.Remove(fullPath); err != nil {
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

	// MKCOL with a request body is unsupported (RFC 4918 §9.3).
	if r.ContentLength > 0 {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	parent := filepath.Dir(fullPath)
	if _, err := os.Stat(parent); os.IsNotExist(err) {
		http.Error(w, "Conflict", http.StatusConflict)
		return
	}

	if _, err := os.Stat(fullPath); err == nil {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := os.Mkdir(fullPath, 0o755); err != nil {
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
	if err != nil || dstRel == "" {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	if _, err := os.Stat(srcFull); os.IsNotExist(err) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	_, statErr := os.Stat(dstFull)
	overwrite := r.Header.Get("Overwrite") != "F"
	dstExists := statErr == nil

	if dstExists && !overwrite {
		http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
		return
	}

	if dstExists {
		os.RemoveAll(dstFull)
	}

	if err := os.MkdirAll(filepath.Dir(dstFull), 0o755); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := os.Rename(srcFull, dstFull); err != nil {
		g.logger.Error("move failed", "from", srcRel, "to", dstRel, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
	if err != nil || dstRel == "" {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
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

	_, statErr := os.Stat(dstFull)
	overwrite := r.Header.Get("Overwrite") != "F"
	dstExists := statErr == nil

	if dstExists && !overwrite {
		http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
		return
	}

	if dstExists {
		os.RemoveAll(dstFull)
	}

	if err := os.MkdirAll(filepath.Dir(dstFull), 0o755); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if srcInfo.IsDir() {
		if err := copyDir(srcFull, dstFull); err != nil {
			g.logger.Error("copy dir failed", "from", srcRel, "to", dstRel, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		if err := copyFile(srcFull, dstFull); err != nil {
			g.logger.Error("copy file failed", "from", srcRel, "to", dstRel, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	g.logger.Info("copied", "from", srcRel, "to", dstRel)
	if dstExists {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

// handleLock returns a fake lock token. Real locking is not implemented;
// this stub is sufficient for macOS Finder and Windows Explorer to operate.
func (g *Gateway) handleLock(w http.ResponseWriter, r *http.Request) {
	var h uint32
	for _, b := range []byte(r.URL.Path) {
		h = h*31 + uint32(b)
	}
	token := fmt.Sprintf("opaquelocktoken:sebastian-%08x", h)

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Lock-Token", "<"+token+">")
	w.WriteHeader(http.StatusOK)

	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>`)
	fmt.Fprint(w, `<D:prop xmlns:D="DAV:">`)
	fmt.Fprint(w, `<D:lockdiscovery><D:activelock>`)
	fmt.Fprint(w, `<D:locktype><D:write/></D:locktype>`)
	fmt.Fprint(w, `<D:lockscope><D:exclusive/></D:lockscope>`)
	fmt.Fprint(w, `<D:depth>infinity</D:depth>`)
	fmt.Fprint(w, `<D:owner/>`)
	fmt.Fprint(w, `<D:timeout>Second-3600</D:timeout>`)
	fmt.Fprintf(w, `<D:locktoken><D:href>%s</D:href></D:locktoken>`, xmlEscapeString(token))
	fmt.Fprint(w, `</D:activelock></D:lockdiscovery>`)
	fmt.Fprint(w, `</D:prop>`)
}

// handleUnlock acknowledges an unlock request (stub).
func (g *Gateway) handleUnlock(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
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

// writeMultiStatus writes a 207 Multi-Status PROPFIND response.
func writeMultiStatus(w http.ResponseWriter, entries []propEntry) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)

	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>`)
	fmt.Fprint(w, `<D:multistatus xmlns:D="DAV:">`)

	for _, e := range entries {
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

	fmt.Fprint(w, `</D:multistatus>`)
}

// xmlEscapeString escapes a string for safe inclusion in XML content.
func xmlEscapeString(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// copyFile copies a single file using a temp file + atomic rename.
func copyFile(src, dst string) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()

	dir := filepath.Dir(dst)
	tmpFile, err := os.CreateTemp(dir, ".seb-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	if _, err := io.Copy(tmpFile, sf); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	tmpFile.Close()

	if si, err := os.Stat(src); err == nil {
		os.Chtimes(tmpPath, si.ModTime(), si.ModTime())
	}

	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// copyDir recursively copies a directory tree.
func copyDir(src, dst string) error {
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

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}
