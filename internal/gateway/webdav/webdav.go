// Package webdav implements a WebDAV gateway that exposes rootDir over HTTP.
// Compatible with macOS Finder, Windows Explorer, Linux davfs2, Cyberduck,
// rclone, and other standard WebDAV clients.
package webdav

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
)

// Destination-header error sentinels, so MOVE/COPY can map a missing or malformed
// Destination to 400 and a forbidden target to 403 (rather than a blanket 502).
var (
	errMissingDestination = errors.New("missing Destination header")
	errBadDestination     = errors.New("invalid Destination header")
)

// Config holds WebDAV gateway configuration.
type Config struct {
	ListenAddr     string `yaml:"listen_addr"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	MaxUploadBytes int64  // max body size for PUT; 0 = unlimited
}

// Gateway implements the WebDAV protocol over HTTP.
type Gateway struct {
	rootDir string
	config  Config
	logger  *slog.Logger
	server  *http.Server
	locks   *lockManager
}

// New creates a new WebDAV Gateway.
func New(rootDir string, cfg Config, logger *slog.Logger) *Gateway {
	g := &Gateway{
		rootDir: rootDir,
		config:  cfg,
		logger:  logger.With("gateway", "webdav"),
		locks:   newLockManager(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", g.route)

	g.server = &http.Server{
		Handler: gateway.LogMiddleware(g.logger, mux),
		// Bound header-read and idle-connection time to blunt Slowloris-style
		// attacks. Read/Write timeouts are left unset so large file transfers are
		// not cut off mid-stream.
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return g
}

// Name returns the protocol name.
func (g *Gateway) Name() string { return "webdav" }

// Start begins serving WebDAV requests. Blocks until ctx is cancelled or error.
func (g *Gateway) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", g.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("webdav gateway listen: %w", err)
	}
	g.logger.Info("WebDAV gateway started", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		// Drain in-flight requests rather than cutting connections abruptly; Stop
		// bounds the overall drain time.
		g.server.Shutdown(context.Background())
	}()

	if err := g.server.Serve(ln); err != http.ErrServerClosed {
		return fmt.Errorf("webdav gateway serve: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the gateway.
func (g *Gateway) Stop(ctx context.Context) error {
	return g.server.Shutdown(ctx)
}

// davMethods lists all supported WebDAV methods.
const davMethods = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"

// route dispatches requests by HTTP method.
func (g *Gateway) route(w http.ResponseWriter, r *http.Request) {
	if !gateway.CheckBasicAuth(r, g.config.Username, g.config.Password) {
		w.Header().Set("WWW-Authenticate", `Basic realm="sebastian"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "OPTIONS":
		g.handleOptions(w, r)
	case "PROPFIND":
		g.handlePropfind(w, r)
	case "PROPPATCH":
		g.handleProppatch(w, r)
	case http.MethodGet:
		g.handleGet(w, r)
	case http.MethodHead:
		g.handleHead(w, r)
	case http.MethodPut:
		g.handlePut(w, r)
	case http.MethodDelete:
		g.handleDelete(w, r)
	case "MKCOL":
		g.handleMkcol(w, r)
	case "MOVE":
		g.handleMove(w, r)
	case "COPY":
		g.handleCopy(w, r)
	case "LOCK":
		g.handleLock(w, r)
	case "UNLOCK":
		g.handleUnlock(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// resolvePath validates a URL path and returns the relative name and full
// filesystem path. Delegates to gateway.SafePath for path validation.
func (g *Gateway) resolvePath(urlPath string) (relName string, fullPath string, err error) {
	return gateway.SafePath(g.rootDir, urlPath)
}

// lockBlocked reports whether a mutating request on relPath must be refused
// because a live lock covers it and the request's If header lacks the lock token.
// It writes a 423 Locked response when it returns true.
func (g *Gateway) lockBlocked(w http.ResponseWriter, r *http.Request, relPath string) bool {
	if !g.locks.canModify(relPath, r.Header.Get("If")) {
		http.Error(w, "Locked", http.StatusLocked)
		return true
	}
	return false
}

// resolveDestination extracts and validates the Destination header used by
// MOVE and COPY methods.
func (g *Gateway) resolveDestination(r *http.Request) (string, string, error) {
	dest := r.Header.Get("Destination")
	if dest == "" {
		return "", "", errMissingDestination
	}

	u, err := url.Parse(dest)
	if err != nil {
		return "", "", errBadDestination
	}

	return gateway.SafePath(g.rootDir, u.Path)
}

// hrefFromPath builds a URL-encoded href for a PROPFIND response.
func hrefFromPath(relName string, isDir bool) string {
	if relName == "" {
		return "/"
	}
	parts := strings.Split(relName, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	href := "/" + strings.Join(parts, "/")
	if isDir && !strings.HasSuffix(href, "/") {
		href += "/"
	}
	return href
}
