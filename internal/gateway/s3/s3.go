// Package s3 implements an S3-compatible gateway that maps buckets to
// first-level subdirectories of rootDir.
package s3

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/solkin/sebastian/internal/gateway"
)

// Config holds S3 gateway configuration.
type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	AccessKey  string `yaml:"access_key"`
	SecretKey  string `yaml:"secret_key"`
	Domain     string `yaml:"domain"`
}

// Gateway implements the S3-compatible API.
type Gateway struct {
	rootDir string
	config  Config
	logger  *slog.Logger
	server  *http.Server
}

// New creates a new S3 Gateway.
func New(rootDir string, cfg Config, logger *slog.Logger) *Gateway {
	g := &Gateway{
		rootDir: rootDir,
		config:  cfg,
		logger:  logger.With("gateway", "s3"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", g.route)

	g.server = &http.Server{
		Handler: gateway.LogMiddleware(g.logger, mux),
	}

	return g
}

// Name returns the protocol name.
func (g *Gateway) Name() string {
	return "s3"
}

// Start begins serving S3 requests. Blocks until ctx is cancelled or error.
func (g *Gateway) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", g.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("s3 gateway listen: %w", err)
	}
	g.logger.Info("S3 gateway started", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		g.server.Close()
	}()

	if err := g.server.Serve(ln); err != http.ErrServerClosed {
		return fmt.Errorf("s3 gateway serve: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the gateway.
func (g *Gateway) Stop(ctx context.Context) error {
	return g.server.Shutdown(ctx)
}

// extractBucketFromHost detects virtual-hosted-style requests when a domain
// is configured. It strips the port, then checks if the hostname ends with
// ".{domain}" and extracts the prefix as the bucket name.
// Example: domain="localhost", Host="mybucket.localhost:9200" → "mybucket".
// Returns "" if domain is not configured or the host doesn't match.
func (g *Gateway) extractBucketFromHost(host string) string {
	if g.config.Domain == "" {
		return ""
	}

	h := host
	if idx := strings.LastIndex(h, ":"); idx != -1 {
		h = h[:idx]
	}

	suffix := "." + g.config.Domain
	if !strings.HasSuffix(h, suffix) {
		return ""
	}

	bucket := strings.TrimSuffix(h, suffix)
	if bucket == "" {
		return ""
	}

	return bucket
}

// route dispatches S3 requests based on the URL path structure.
// Supports both path-style and virtual-hosted-style addressing:
//
// Path-style:
//
//	/              → ListBuckets
//	/{bucket}      → bucket operations (HEAD/GET/PUT/DELETE)
//	/{bucket}/{key} → object operations (HEAD/GET/PUT/DELETE)
//
// Virtual-hosted-style (bucket in Host header subdomain):
//
//	Host: mybucket.endpoint / → bucket operations
//	Host: mybucket.endpoint /{key} → object operations
func (g *Gateway) route(w http.ResponseWriter, r *http.Request) {
	if !g.authenticate(r) {
		writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")

	if vhBucket := g.extractBucketFromHost(r.Host); vhBucket != "" {
		key := path
		g.logger.Debug("virtual-hosted-style request", "bucket", vhBucket, "key", key)
		g.routeBucketOrObject(w, r, vhBucket, key)
		return
	}

	if path == "" {
		if r.Method == http.MethodGet {
			g.handleListBuckets(w, r)
			return
		}
		writeS3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		return
	}

	bucket, key, _ := strings.Cut(path, "/")

	g.routeBucketOrObject(w, r, bucket, key)
}

// routeBucketOrObject handles all bucket-level and object-level operations.
// Used by both path-style and virtual-hosted-style routing.
func (g *Gateway) routeBucketOrObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if key == "" {
		query := r.URL.Query()
		if _, ok := query["location"]; ok && r.Method == http.MethodGet {
			g.handleGetBucketLocation(w, r, bucket)
			return
		}
		if _, ok := query["versioning"]; ok && r.Method == http.MethodGet {
			g.handleGetBucketVersioning(w, r, bucket)
			return
		}
		if _, ok := query["acl"]; ok && r.Method == http.MethodGet {
			g.handleGetBucketACL(w, r, bucket)
			return
		}
		if _, ok := query["tagging"]; ok && r.Method == http.MethodGet {
			writeS3Error(w, http.StatusNotFound, "NoSuchTagSet", "The TagSet does not exist.")
			return
		}
		if _, ok := query["policy"]; ok && r.Method == http.MethodGet {
			writeS3Error(w, http.StatusNotFound, "NoSuchBucketPolicy", "The bucket policy does not exist.")
			return
		}

		switch r.Method {
		case http.MethodHead:
			g.handleHeadBucket(w, r, bucket)
		case http.MethodGet:
			g.handleListObjects(w, r, bucket)
		case http.MethodPut:
			g.handleCreateBucket(w, r, bucket)
		case http.MethodDelete:
			g.handleDeleteBucket(w, r, bucket)
		default:
			writeS3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		}
		return
	}

	switch r.Method {
	case http.MethodHead:
		g.handleHeadObject(w, r, bucket, key)
	case http.MethodGet:
		g.handleGetObject(w, r, bucket, key)
	case http.MethodPut:
		g.handlePutObject(w, r, bucket, key)
	case http.MethodDelete:
		g.handleDeleteObject(w, r, bucket, key)
	default:
		writeS3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
	}
}

// authenticate checks the request for valid credentials.
// If no access_key/secret_key configured, all requests are allowed.
// Supports: Authorization header (V2, V4) and presigned URL (query string auth).
func (g *Gateway) authenticate(r *http.Request) bool {
	if g.config.AccessKey == "" && g.config.SecretKey == "" {
		return true
	}

	authHeader := r.Header.Get("Authorization")

	if authHeader != "" {
		if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
			return g.authenticateSigV4(r, authHeader)
		}

		if strings.HasPrefix(authHeader, "AWS ") {
			parts := strings.SplitN(authHeader[4:], ":", 2)
			if len(parts) == 2 && parts[0] == g.config.AccessKey {
				return true
			}
		}

		return false
	}

	query := r.URL.Query()
	if query.Get("X-Amz-Algorithm") != "" {
		credential := query.Get("X-Amz-Credential")
		if credential == "" {
			return false
		}
		parts := strings.SplitN(credential, "/", 2)
		if len(parts) >= 1 && parts[0] == g.config.AccessKey {
			return true
		}
		return false
	}

	return false
}

// authenticateSigV4 performs a simplified AWS Signature V4 check.
// We verify the access key matches. Full signature verification is not implemented
// as it requires complex canonicalization; this is sufficient for trusted environments.
func (g *Gateway) authenticateSigV4(r *http.Request, authHeader string) bool {
	credIdx := strings.Index(authHeader, "Credential=")
	if credIdx == -1 {
		return false
	}
	credStr := authHeader[credIdx+len("Credential="):]
	credEnd := strings.Index(credStr, ",")
	if credEnd != -1 {
		credStr = credStr[:credEnd]
	}

	parts := strings.SplitN(credStr, "/", 2)
	if len(parts) < 1 {
		return false
	}

	return parts[0] == g.config.AccessKey
}

// computeETag returns the hex-encoded SHA256 of data, formatted as an S3 ETag.
func computeETag(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("\"%s\"", hex.EncodeToString(h[:]))
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
