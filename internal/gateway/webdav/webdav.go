// Package webdav implements a WebDAV gateway that exposes rootDir over HTTP.
// Compatible with macOS Finder, Windows Explorer, Linux davfs2, Cyberduck,
// rclone, and other standard WebDAV clients.
package webdav

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/solkin/sebastian/internal/gateway"
)

// Config holds WebDAV gateway configuration.
type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
}

// Gateway implements the WebDAV protocol over HTTP.
type Gateway struct {
	rootDir string
	config  Config
	logger  *slog.Logger
	server  *http.Server
}

// New creates a new WebDAV Gateway.
func New(rootDir string, cfg Config, logger *slog.Logger) *Gateway {
	g := &Gateway{
		rootDir: rootDir,
		config:  cfg,
		logger:  logger.With("gateway", "webdav"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", g.route)

	g.server = &http.Server{
		Handler: gateway.LogMiddleware(g.logger, mux),
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
		g.server.Close()
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

// resolveDestination extracts and validates the Destination header used by
// MOVE and COPY methods.
func (g *Gateway) resolveDestination(r *http.Request) (string, string, error) {
	dest := r.Header.Get("Destination")
	if dest == "" {
		return "", "", fmt.Errorf("missing Destination header")
	}

	u, err := url.Parse(dest)
	if err != nil {
		return "", "", fmt.Errorf("invalid Destination URL: %w", err)
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
