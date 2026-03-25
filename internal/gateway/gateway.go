// Package gateway defines the interface for file access protocols and shared helpers.
package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
)

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

	return cleaned, full, nil
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
	return user == username && pass == password
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
