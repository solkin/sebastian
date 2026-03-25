// Package httpui implements an HTTP file server with a web-based UI.
// It provides a Material 3 Expressive styled file browser for managing
// files in rootDir through a standard web browser.
package httpui

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/solkin/sebastian/internal/gateway"
)

//go:embed index.html
var indexHTML []byte

// Config holds HTTP file server configuration.
type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
}

// Gateway implements the HTTP file server with web UI.
type Gateway struct {
	rootDir string
	config  Config
	logger  *slog.Logger
	server  *http.Server
}

// New creates a new HTTP file server Gateway.
func New(rootDir string, cfg Config, logger *slog.Logger) *Gateway {
	g := &Gateway{
		rootDir: rootDir,
		config:  cfg,
		logger:  logger.With("gateway", "http"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", g.route)

	g.server = &http.Server{
		Handler: gateway.LogMiddleware(g.logger, mux),
	}

	return g
}

// Name returns the protocol name.
func (g *Gateway) Name() string { return "http" }

// Start begins serving HTTP requests. Blocks until ctx is cancelled or error.
func (g *Gateway) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", g.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("http file server listen: %w", err)
	}
	g.logger.Info("HTTP file server started", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		g.server.Close()
	}()

	if err := g.server.Serve(ln); err != http.ErrServerClosed {
		return fmt.Errorf("http file server serve: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the gateway.
func (g *Gateway) Stop(ctx context.Context) error {
	return g.server.Shutdown(ctx)
}

// route dispatches requests between the SPA page and API endpoints.
func (g *Gateway) route(w http.ResponseWriter, r *http.Request) {
	if !gateway.CheckBasicAuth(r, g.config.Username, g.config.Password) {
		w.Header().Set("WWW-Authenticate", `Basic realm="sebastian"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	path := r.URL.Path

	if path == "/favicon.ico" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if strings.HasPrefix(path, "/_api/") {
		g.routeAPI(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// routeAPI dispatches API requests.
func (g *Gateway) routeAPI(w http.ResponseWriter, r *http.Request) {
	apiPath := strings.TrimPrefix(r.URL.Path, "/_api")

	switch {
	case apiPath == "/list" && r.Method == http.MethodGet:
		g.handleList(w, r)
	case strings.HasPrefix(apiPath, "/dl/") && r.Method == http.MethodGet:
		g.handleDownload(w, r)
	case apiPath == "/upload" && r.Method == http.MethodPost:
		g.handleUpload(w, r)
	case apiPath == "/mkdir" && r.Method == http.MethodPost:
		g.handleMkdir(w, r)
	case apiPath == "/rename" && r.Method == http.MethodPost:
		g.handleRename(w, r)
	case apiPath == "/delete" && r.Method == http.MethodPost:
		g.handleDelete(w, r)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}
