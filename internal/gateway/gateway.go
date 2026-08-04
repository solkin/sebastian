// Package gateway defines the interface for file access protocols and shared helpers.
package gateway

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReservedDirName is a top-level directory under rootDir that sebastian reserves
// for its own state (multipart upload staging). It is not a bucket and is hidden
// from every gateway: SafePath refuses to resolve into it and directory listings
// skip it, so clients can neither see nor corrupt in-progress uploads.
const ReservedDirName = ".sebastian"

// IsReserved reports whether name is the reserved state directory. Gateways call
// it when filtering the entries of rootDir itself.
func IsReserved(name string) bool {
	return name == ReservedDirName
}

// IsReservedPath reports whether fullPath is the reserved state directory of
// rootDir. Gateways call it while listing an arbitrary directory, where the
// reserved entry only has to be filtered when that directory is the root.
func IsReservedPath(rootDir, fullPath string) bool {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return false
	}
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return false
	}
	return absPath == filepath.Join(absRoot, ReservedDirName)
}

// Prefixes of the scratch files every gateway writes while performing an atomic
// write (create temp, fill, rename into place).
const (
	tempFilePrefix   = ".seb-tmp-"
	backupFilePrefix = ".seb-bak-"
)

// IsScratchFile reports whether name is an atomic-write scratch file. Such a file
// is an implementation detail of a write in flight — it is not an object and must
// not be presented as one.
//
// The prefixes are a reserved namespace: SafePath refuses to resolve a path that
// uses one, so a client cannot create a file the periodic sweep would later
// delete out from under it.
func IsScratchFile(name string) bool {
	return strings.HasPrefix(name, tempFilePrefix) || strings.HasPrefix(name, backupFilePrefix)
}

// SweepTempFiles removes stale atomic-write scratch files (".seb-tmp-*" and
// ".seb-bak-*") left under rootDir by a process that died between creating a temp
// file and renaming it into place.
//
// Only files last modified more than maxAge ago are removed, so the sweep can run
// periodically alongside live traffic without destroying an upload that is still
// streaming. Pass maxAge <= 0 to remove every scratch file regardless of age —
// correct at startup, when no upload can be in flight.
func SweepTempFiles(rootDir string, maxAge time.Duration, logger *slog.Logger) {
	cutoff := time.Now().Add(-maxAge)
	filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !IsScratchFile(d.Name()) {
			return nil
		}
		if maxAge > 0 {
			info, statErr := d.Info()
			if statErr != nil || info.ModTime().After(cutoff) {
				return nil
			}
		}
		if rmErr := os.Remove(path); rmErr != nil {
			logger.Warn("failed to remove stale temp file", "path", path, "error", rmErr)
		} else {
			logger.Info("removed stale temp file", "path", path)
		}
		return nil
	})
}

// Gateway is an interface that each protocol-specific file access server must implement.
type Gateway interface {
	// Start begins serving requests. Blocks until ctx is cancelled or a fatal error occurs.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the gateway.
	Stop(ctx context.Context) error

	// Name returns the protocol name (e.g. "s3", "webdav").
	Name() string
}

// SafePath validates reqPath and returns the cleaned relative path and full
// filesystem path under rootDir. Returns an error if the path escapes rootDir.
func SafePath(rootDir, reqPath string) (relPath string, fullPath string, err error) {
	cleaned := filepath.ToSlash(filepath.Clean(reqPath))
	if cleaned == "." || cleaned == "/" {
		cleaned = ""
	}
	cleaned = strings.TrimPrefix(cleaned, "/")

	if strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", "", fmt.Errorf("path traversal")
	}

	if cleaned == "" {
		return "", rootDir, nil
	}

	// The reserved state directory holds sebastian's own bookkeeping (staged
	// multipart parts); no protocol may read, write, or delete inside it.
	if cleaned == ReservedDirName || strings.HasPrefix(cleaned, ReservedDirName+"/") {
		return "", "", fmt.Errorf("reserved path")
	}

	// Likewise for the atomic-write scratch namespace. A client-created file with
	// one of those prefixes would be indistinguishable from an abandoned temp file
	// and would eventually be swept away, so the name is refused up front rather
	// than accepted and later deleted.
	for _, seg := range strings.Split(cleaned, "/") {
		if IsScratchFile(seg) {
			return "", "", fmt.Errorf("reserved path")
		}
	}

	full := filepath.Join(rootDir, filepath.FromSlash(cleaned))

	absRoot, _ := filepath.Abs(rootDir)
	absFull, _ := filepath.Abs(full)
	if !strings.HasPrefix(absFull, absRoot+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path traversal")
	}

	if err := verifyNoSymlinkEscape(rootDir, full); err != nil {
		return "", "", err
	}

	return cleaned, full, nil
}

// verifyNoSymlinkEscape ensures that, after resolving symlinks, full still lies
// within rootDir. full need not exist yet: the nearest existing ancestor is
// resolved and the remaining (not-yet-created) components are re-appended. This
// closes symlink-based escapes that the textual check above cannot detect.
func verifyNoSymlinkEscape(rootDir, full string) error {
	realRoot, err := filepath.EvalSymlinks(rootDir)
	if err != nil {
		// rootDir normally exists; if it cannot be resolved, rely on the textual
		// check already performed by the caller.
		return nil
	}

	cur := full
	rest := ""
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			if rest != "" {
				resolved = filepath.Join(resolved, rest)
			}
			if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
				return fmt.Errorf("path traversal")
			}
			return nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the filesystem root without resolving; the textual check stands.
			return nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// CheckBasicAuth validates HTTP Basic Auth credentials.
// Returns true if no auth is configured (both empty) or credentials match.
func CheckBasicAuth(r *http.Request, username, password string) bool {
	if username == "" && password == "" {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(username))
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(password))
	return userOK&passOK == 1
}

// ResponseLogger wraps http.ResponseWriter to capture status code and body size.
type ResponseLogger struct {
	http.ResponseWriter
	Status int
	Size   int
}

// WriteHeader captures the status code.
func (r *ResponseLogger) WriteHeader(status int) {
	r.Status = status
	r.ResponseWriter.WriteHeader(status)
}

// Write captures the body size.
func (r *ResponseLogger) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.Size += n
	return n, err
}

// LogMiddleware returns an HTTP handler that logs every request.
func LogMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl := &ResponseLogger{ResponseWriter: w, Status: 200}
		next.ServeHTTP(rl, r)
		logger.Info("request",
			"method", r.Method,
			"url", r.URL.String(),
			"status", rl.Status,
			"size", rl.Size,
			"user_agent", r.UserAgent(),
		)
	})
}
