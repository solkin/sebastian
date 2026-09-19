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

// Gateway is an interface that each protocol-specific file access server must implement.
type Gateway interface {
	// Start begins serving requests. Blocks until ctx is cancelled or a fatal error occurs.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the gateway.
	Stop(ctx context.Context) error

	// Name returns the protocol name (e.g. "s3", "sftp", "webdav").
	Name() string
}

// ReservedDirName is a top-level directory under rootDir that Sebastian reserves
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

// IsClientVisiblePath reports whether a directory entry may be exposed through a
// gateway listing. It validates both the entry name and any symlink-resolved
// target, so an alias cannot reveal reserved data.
func IsClientVisiblePath(rootDir, fullPath string) bool {
	rel, err := filepath.Rel(rootDir, fullPath)
	if err != nil || rel == "." || strings.HasPrefix(filepath.ToSlash(rel), "../") {
		return false
	}
	rel = filepath.ToSlash(rel)
	if err := validateClientPath(rel); err != nil {
		return false
	}
	// The directory containing this entry was already resolved by the listing
	// handler. Regular children need only the cheap lexical checks above; only a
	// symlink can redirect the entry to a different protected target.
	info, err := os.Lstat(fullPath)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return true
	}
	_, _, err = SafePath(rootDir, rel)
	return err == nil
}

// PathResolvesWithin reports whether fullPath is textually and, where possible,
// symlink-resolved inside rootDir. It is useful for narrower boundaries nested
// under the served root, such as keeping an S3 object inside its own bucket.
func PathResolvesWithin(rootDir, fullPath string) bool {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return false
	}
	absFull, err := filepath.Abs(fullPath)
	if err != nil || (absFull != absRoot && !strings.HasPrefix(absFull, absRoot+string(filepath.Separator))) {
		return false
	}
	_, _, _, err = resolveNoSymlinkEscape(absRoot, absFull)
	return err == nil
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

// SafePath validates reqPath and returns the cleaned relative path and full
// filesystem path under rootDir. Returns an error if the path escapes rootDir
// or enters a reserved namespace.
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

	if err := validateClientPath(cleaned); err != nil {
		return "", "", err
	}

	full := filepath.Join(rootDir, filepath.FromSlash(cleaned))

	absRoot, _ := filepath.Abs(rootDir)
	absFull, _ := filepath.Abs(full)
	if !strings.HasPrefix(absFull, absRoot+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path traversal")
	}

	resolved, realRoot, rootResolved, err := resolveNoSymlinkEscape(rootDir, full)
	if err != nil {
		return "", "", err
	}

	// A harmless-looking alias can resolve into .sebastian or a scratch file.
	// Validate the symlink-resolved target too, otherwise
	// every gateway could bypass its namespace protections through an in-root link.
	if rootResolved {
		resolvedRel, relErr := filepath.Rel(realRoot, resolved)
		if relErr != nil {
			return "", "", fmt.Errorf("resolve symlink target: %w", relErr)
		}
		resolvedRel = filepath.ToSlash(resolvedRel)
		if resolvedRel == "." {
			resolvedRel = ""
		}
		if err := validateClientPath(resolvedRel); err != nil {
			return "", "", err
		}
	}

	return cleaned, full, nil
}

// validateClientPath applies the non-filesystem namespace rules to a cleaned,
// root-relative path. SafePath calls it for both the requested path and its
// symlink-resolved target.
func validateClientPath(rel string) error {
	if rel == ReservedDirName || strings.HasPrefix(rel, ReservedDirName+"/") {
		return fmt.Errorf("reserved path")
	}
	for _, seg := range strings.Split(rel, "/") {
		if IsScratchFile(seg) {
			return fmt.Errorf("reserved path")
		}
	}
	return nil
}

// resolveNoSymlinkEscape resolves full through its nearest existing ancestor and
// ensures the result stays inside rootDir. full itself need not exist yet.
func resolveNoSymlinkEscape(rootDir, full string) (resolvedPath, realRoot string, rootResolved bool, err error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", "", false, err
	}
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", "", false, err
	}
	realRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		// rootDir normally exists; if it cannot be resolved, rely on the textual
		// check already performed by the caller.
		return absFull, absRoot, false, nil
	}

	cur := absFull
	rest := ""
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			if rest != "" {
				resolved = filepath.Join(resolved, rest)
			}
			if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
				return "", realRoot, true, fmt.Errorf("path traversal")
			}
			return resolved, realRoot, true, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the filesystem root without resolving; the textual check stands.
			return absFull, realRoot, true, nil
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
