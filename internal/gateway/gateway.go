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
)

// SweepTempFiles removes stale atomic-write scratch files (".seb-tmp-*" and
// ".seb-bak-*") left under rootDir by a previous process that died between
// creating a temp file and renaming it into place. It is safe to call once at
// startup, when no uploads are in flight.
func SweepTempFiles(rootDir string, logger *slog.Logger) {
	filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, ".seb-tmp-") || strings.HasPrefix(name, ".seb-bak-") {
			if rmErr := os.Remove(path); rmErr != nil {
				logger.Warn("failed to remove stale temp file", "path", path, "error", rmErr)
			} else {
				logger.Info("removed stale temp file", "path", path)
			}
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
