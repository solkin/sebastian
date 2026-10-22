// Package gateway defines the interface for file access protocols and shared helpers.
package gateway

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/solkin/sebastian/internal/fileops"
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
//
// Every spelling is reserved: on a case-insensitive volume (APFS, NTFS)
// ".SEBASTIAN" opens the same directory, with the staged parts of uploads.
func IsReserved(name string) bool {
	return strings.EqualFold(name, ReservedDirName)
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
	return filepath.Dir(absPath) == absRoot && IsReserved(filepath.Base(absPath))
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

// SweepTempFiles removes inactive temporary files and COPY stages.
// Recovery backups are preserved, and pending journals defer all cleanup.
func SweepTempFiles(rootDir string, maxAge time.Duration, logger *slog.Logger) {
	unlock := fileops.Lock(rootDir)
	defer unlock()
	if pending, err := fileops.ReplacementPendingLocked(rootDir); err != nil || pending {
		logger.Debug("defer scratch cleanup until replacement recovery completes", "error", err)
		return
	}
	cutoff := time.Now().Add(-maxAge)
	filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// COPY staging is private and only disposable without a journal.
			// The root lock excludes an active builder for the entire sweep.
			if strings.HasPrefix(d.Name(), ".seb-tmp-replace-") {
				info, statErr := d.Info()
				if statErr == nil && (maxAge <= 0 || !info.ModTime().After(cutoff)) {
					if err := os.RemoveAll(path); err != nil {
						logger.Warn("failed to remove orphan COPY stage", "path", path, "error", err)
					}
				}
				return fs.SkipDir
			}
			if strings.HasPrefix(d.Name(), backupFilePrefix) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(d.Name(), tempFilePrefix) || fileops.ScratchActive(path) {
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
	// No filesystem stores a NUL; refusing it here answers every gateway
	// with a bad request instead of an error from deep in a syscall.
	if strings.ContainsRune(rel, 0) {
		return fmt.Errorf("invalid name")
	}
	first, _, _ := strings.Cut(rel, "/")
	if IsReserved(first) {
		return fmt.Errorf("reserved path")
	}
	for _, seg := range strings.Split(rel, "/") {
		if isScratchSpelling(seg) {
			return fmt.Errorf("reserved path")
		}
	}
	return nil
}

// ClientVisibleName applies the namespace rules of validateClientPath to one
// entry of a directory that already passed them, so only the entry's own name
// can break one. It allocates nothing: a listing calls it per entry. Symlinks
// still need IsClientVisiblePath.
func ClientVisibleName(dirRel, name string) bool {
	if dirRel == "" && IsReserved(name) {
		return false
	}
	return strings.IndexByte(name, 0) < 0 && !isScratchSpelling(name)
}

// isScratchSpelling is IsScratchFile in any letter case: a client must not
// reach a scratch file through another spelling of its name.
func isScratchSpelling(name string) bool {
	return hasPrefixFold(name, tempFilePrefix) || hasPrefixFold(name, backupFilePrefix)
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
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

	resolved := evalDeepestAncestor(absFull)
	if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
		return "", realRoot, true, fmt.Errorf("path traversal")
	}
	return resolved, realRoot, true, nil
}

// CheckBasicAuth validates HTTP Basic Auth credentials.
// Returns true if no auth is configured (both empty) or credentials match.
//
// Half a pair admits nobody: an empty password is not a secret. Configuration
// validation already refuses that; this keeps the gateway closed regardless.
func CheckBasicAuth(r *http.Request, username, password string) bool {
	if username == "" && password == "" {
		return true
	}
	if username == "" || password == "" {
		return false
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(username))
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(password))
	return userOK&passOK == 1
}

// IdleTransferTimeout bounds how long a request body or a response may make no
// progress. A total timeout would cut off a large file on a slow link; none at
// all let a client that sent one byte, or stopped reading, hold a goroutine, a
// descriptor and a scratch file forever. Progress, not duration, is bounded.
var IdleTransferTimeout = 5 * time.Minute

// idleDeadlines moves a connection's deadlines forward while a transfer
// progresses. Deadlines are refreshed at most every eighth of the timeout, so
// the per-chunk cost of a large transfer stays a clock read.
type idleDeadlines struct {
	rc        *http.ResponseController
	timeout   time.Duration
	lastRead  time.Time
	lastWrite time.Time
}

func (d *idleDeadlines) extendRead() {
	if now := time.Now(); now.Sub(d.lastRead) >= d.timeout/8 {
		d.lastRead = now
		_ = d.rc.SetReadDeadline(now.Add(d.timeout))
	}
}

func (d *idleDeadlines) extendWrite() {
	if now := time.Now(); now.Sub(d.lastWrite) >= d.timeout/8 {
		d.lastWrite = now
		_ = d.rc.SetWriteDeadline(now.Add(d.timeout))
	}
}

// idleBody moves the read deadline while the handler reads the body. When the
// body ends, net/http clears the deadline itself before it starts watching the
// connection for a disconnect, so a long publish after the upload is not cut off.
type idleBody struct {
	io.ReadCloser
	deadlines *idleDeadlines
}

func (b *idleBody) Read(p []byte) (int, error) {
	b.deadlines.extendRead()
	return b.ReadCloser.Read(p)
}

// ResponseLogger wraps http.ResponseWriter to capture status code and body size.
type ResponseLogger struct {
	http.ResponseWriter
	Status int
	Size   int

	deadlines *idleDeadlines
}

// WriteHeader captures the status code.
func (r *ResponseLogger) WriteHeader(status int) {
	r.Status = status
	r.ResponseWriter.WriteHeader(status)
}

// Write captures the body size.
func (r *ResponseLogger) Write(b []byte) (int, error) {
	if r.deadlines != nil {
		r.deadlines.extendWrite()
	}
	n, err := r.ResponseWriter.Write(b)
	r.Size += n
	return n, err
}

// Flush forwards to the underlying writer when it supports flushing.
func (r *ResponseLogger) Flush() {
	if r.deadlines != nil {
		r.deadlines.extendWrite()
	}
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the connection beneath.
func (r *ResponseLogger) Unwrap() http.ResponseWriter { return r.ResponseWriter }

var accessLog atomic.Bool

func init() { accessLog.Store(true) }

// SetAccessLog turns the per-request log line on or off.
func SetAccessLog(enabled bool) { accessLog.Store(enabled) }

// LogMiddleware returns an HTTP handler that bounds idle transfers and logs
// every request unless the access log is off.
func LogMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		deadlines := &idleDeadlines{rc: http.NewResponseController(w), timeout: IdleTransferTimeout}
		// A keep-alive connection may still carry the write deadline of the
		// previous response. This one sets its own once it starts writing, so
		// a long publish before the first byte is not cut short.
		_ = deadlines.rc.SetWriteDeadline(time.Time{})
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &idleBody{ReadCloser: r.Body, deadlines: deadlines}
		}
		rl := &ResponseLogger{ResponseWriter: w, Status: 200, deadlines: deadlines}
		next.ServeHTTP(rl, r)
		if !accessLog.Load() {
			return
		}
		attrs := []any{
			"method", r.Method,
			"url", requestLogURL(r),
			"status", rl.Status,
			"size", rl.Size,
			"duration_ms", time.Since(started).Milliseconds(),
			"remote", r.RemoteAddr,
		}
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			attrs = append(attrs, "forwarded_for", forwarded)
		}
		attrs = append(attrs, "user_agent", r.UserAgent())
		logger.Info("request", attrs...)
	})
}
