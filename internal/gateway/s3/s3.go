// Package s3 implements an S3-compatible gateway that maps buckets to
// first-level subdirectories of rootDir.
package s3

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
	"github.com/solkin/sebastian/internal/multipart"
)

// Config holds S3 gateway configuration.
type Config struct {
	ListenAddr     string `yaml:"listen_addr"`
	AccessKey      string `yaml:"access_key"`
	SecretKey      string `yaml:"secret_key"`
	Domain         string `yaml:"domain"`
	MaxUploadBytes int64  // max object size for PutObject; 0 = unlimited
	// Multipart is the staging store backing the multipart upload API. When nil,
	// multipart operations answer NotImplemented and the rest of the gateway is
	// unaffected.
	Multipart *multipart.Store
}

// Gateway implements the S3-compatible API.
type Gateway struct {
	rootDir   string
	config    Config
	logger    *slog.Logger
	server    *http.Server
	multipart *multipart.Store
}

// New creates a new S3 Gateway.
func New(rootDir string, cfg Config, logger *slog.Logger) *Gateway {
	g := &Gateway{
		rootDir:   rootDir,
		config:    cfg,
		logger:    logger.With("gateway", "s3"),
		multipart: cfg.Multipart,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", g.route)

	g.server = &http.Server{
		Handler: gateway.LogMiddleware(g.logger, mux),
		// Bound the time spent reading request headers and idle keep-alive
		// connections to blunt Slowloris-style attacks. Read/Write timeouts are
		// intentionally left unset so large object transfers are not cut off.
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
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
		// Drain in-flight requests rather than cutting connections abruptly; Stop
		// bounds the overall drain time.
		g.server.Shutdown(context.Background())
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
//	/{bucket}      → bucket operations (HEAD/GET/PUT/DELETE; POST ?delete deletes objects)
//	/{bucket}/{key} → object operations (HEAD/GET/PUT/DELETE)
//
// Virtual-hosted-style (bucket in Host header subdomain):
//
//	Host: mybucket.endpoint / → bucket operations
//	Host: mybucket.endpoint /{key} → object operations
func (g *Gateway) route(w http.ResponseWriter, r *http.Request) {
	// Objects are served with the media type of their name (see contentTypeFor);
	// a browser must not second-guess it into something it would execute.
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if !g.authenticate(r) {
		writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	// Only object PUTs decode streaming bodies. Refuse them elsewhere before
	// a handler can act on undecoded bytes.
	if streamingBody(r) && r.Method != http.MethodPut {
		writeStreamingNotImplemented(w)
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
	if failure := g.bucketFailure(bucket); failure != nil {
		writeS3Error(w, failure.status, failure.code, failure.message)
		return
	}

	if key == "" {
		if streamingBody(r) {
			writeStreamingNotImplemented(w)
			return
		}
		query := r.URL.Query()
		if _, ok := query["uploads"]; ok && r.Method == http.MethodGet {
			g.handleListMultipartUploads(w, r, bucket)
			return
		}
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
		if _, ok := query["delete"]; ok && r.Method == http.MethodPost {
			g.handleDeleteObjects(w, r, bucket)
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

	if failure := keyFailure(key); failure != nil {
		writeS3Error(w, failure.status, failure.code, failure.message)
		return
	}

	// Multipart operations are selected by query parameters on the object URL:
	// ?uploads starts one, and ?uploadId=... addresses an existing one.
	query := r.URL.Query()
	_, initiating := query["uploads"]
	uploadID := query.Get("uploadId")

	// A part upload missing its uploadId must not fall through to PutObject: that
	// would silently overwrite the whole object with the bytes of one part.
	if _, ok := query["partNumber"]; ok && uploadID == "" {
		writeS3Error(w, http.StatusBadRequest, "InvalidRequest",
			"A partNumber requires an uploadId. Start a multipart upload first.")
		return
	}

	// A PUT that names a copy source carries no data of its own: it is a
	// CopyObject, or for a part an UploadPartCopy. Neither may fall through to a
	// plain upload, which would store its empty body over the destination.
	if r.Header.Get("X-Amz-Copy-Source") != "" && r.Method == http.MethodPut {
		if uploadID != "" {
			g.handleUploadPartCopy(w, r, bucket, key, uploadID)
			return
		}
		g.handleCopyObject(w, r, bucket, key)
		return
	}

	// A key ending in "/" is a folder marker, which is the folder itself here.
	if isFolderKey(key) {
		if initiating || uploadID != "" {
			writeObjectFailure(w, errFolderHasNoData)
			return
		}
		switch r.Method {
		case http.MethodHead, http.MethodGet:
			g.handleGetFolder(w, r, bucket, key)
		case http.MethodPut:
			g.handlePutFolder(w, r, bucket, key)
		case http.MethodDelete:
			g.handleDeleteFolder(w, r, bucket, key)
		default:
			writeS3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		}
		return
	}

	switch {
	case initiating && r.Method == http.MethodPost:
		g.handleCreateMultipartUpload(w, r, bucket, key)
		return
	case uploadID != "" && r.Method == http.MethodPut:
		g.handleUploadPart(w, r, bucket, key, uploadID)
		return
	case uploadID != "" && r.Method == http.MethodPost:
		g.handleCompleteMultipartUpload(w, r, bucket, key, uploadID)
		return
	case uploadID != "" && r.Method == http.MethodDelete:
		g.handleAbortMultipartUpload(w, r, bucket, key, uploadID)
		return
	case uploadID != "" && r.Method == http.MethodGet:
		g.handleListParts(w, r, bucket, key, uploadID)
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

// bucketFailure holds a bucket name to the namespace rules: a scratch name is
// refused. The route checks the bucket of the URL; CopyObject checks its
// source's too.
func (g *Gateway) bucketFailure(bucket string) *objectFailure {
	if gateway.IsScratchFile(bucket) {
		return &objectFailure{http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name"}
	}
	return nil
}

// keyFailure holds a key to the namespace rules before any operation looks at
// it: a key no filesystem can hold is refused (see keyShapeFailure), and so is
// a scratch name. The route checks the key of the URL, and CopyObject the key
// of its source.
func keyFailure(key string) *objectFailure {
	if failure := keyShapeFailure(key); failure != nil {
		return failure
	}
	for _, segment := range strings.Split(key, "/") {
		if gateway.IsScratchFile(segment) {
			return &objectFailure{http.StatusBadRequest, "InvalidArgument", "Invalid key"}
		}
	}
	return nil
}

// authenticate checks the request for valid credentials.
// If no access_key/secret_key are configured, all requests are allowed.
// Otherwise the request must carry a valid AWS Signature V4 signature, either in
// the Authorization header or as presigned query-string parameters. Legacy SigV2
// ("AWS key:signature") is not supported and is rejected.
func (g *Gateway) authenticate(r *http.Request) bool {
	if g.config.AccessKey == "" && g.config.SecretKey == "" {
		return true
	}
	// Half a key pair admits nobody: an empty secret is a key anyone can sign
	// with. Configuration validation refuses it; this keeps the gateway closed
	// regardless.
	if g.config.AccessKey == "" || g.config.SecretKey == "" {
		return false
	}

	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, sigV4Algorithm) {
			return verifyHeaderV4(r, g.config.AccessKey, g.config.SecretKey)
		}
		return false
	}

	if r.URL.Query().Get("X-Amz-Algorithm") == sigV4Algorithm {
		return verifyPresignedV4(r, g.config.AccessKey, g.config.SecretKey)
	}

	return false
}
