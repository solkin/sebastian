package s3

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/multipart"
)

// objectGateway is a gateway with one bucket holding obj.txt ("0123456789"),
// and the object's stat.
func objectGateway(t *testing.T, cfg Config) (*Gateway, string, os.FileInfo) {
	t.Helper()
	g, root := testGateway(t, cfg)
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "bucket", "obj.txt")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A whole-second timestamp, so HTTP dates name it exactly.
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return g, root, info
}

// TestReadPreconditions evaluates GET and HEAD validators in RFC 9110 order:
// If-Match, else If-Unmodified-Since, decide 412; then If-None-Match, else
// If-Modified-Since, decide 304. HEAD used to ignore them all.
func TestReadPreconditions(t *testing.T) {
	g, _, info := objectGateway(t, Config{})
	etag := etagFor(info)
	at := func(d time.Duration) string { return info.ModTime().Add(d).UTC().Format(http.TimeFormat) }
	for _, tc := range []struct {
		name    string
		headers map[string]string
		status  int
	}{
		{"if-match", map[string]string{"If-Match": etag}, http.StatusOK},
		{"if-match unquoted", map[string]string{"If-Match": strings.Trim(etag, `"`)}, http.StatusOK},
		{"if-match list", map[string]string{"If-Match": `"other", ` + etag}, http.StatusOK},
		{"if-match star", map[string]string{"If-Match": "*"}, http.StatusOK},
		{"if-match stale", map[string]string{"If-Match": `"stale"`}, http.StatusPreconditionFailed},
		{"if-unmodified-since earlier", map[string]string{"If-Unmodified-Since": at(-time.Minute)}, http.StatusPreconditionFailed},
		{"if-unmodified-since same", map[string]string{"If-Unmodified-Since": at(0)}, http.StatusOK},
		{"if-match wins over if-unmodified-since", map[string]string{"If-Match": etag, "If-Unmodified-Since": at(-time.Minute)}, http.StatusOK},
		{"if-none-match", map[string]string{"If-None-Match": etag}, http.StatusNotModified},
		{"if-none-match weak", map[string]string{"If-None-Match": "W/" + etag}, http.StatusNotModified},
		{"if-none-match other", map[string]string{"If-None-Match": `"other"`}, http.StatusOK},
		{"if-modified-since same", map[string]string{"If-Modified-Since": at(0)}, http.StatusNotModified},
		{"if-modified-since earlier", map[string]string{"If-Modified-Since": at(-time.Minute)}, http.StatusOK},
		{"if-none-match wins over if-modified-since", map[string]string{"If-None-Match": `"other"`, "If-Modified-Since": at(time.Minute)}, http.StatusOK},
		{"412 before 304", map[string]string{"If-Match": `"stale"`, "If-None-Match": etag}, http.StatusPreconditionFailed},
		{"bad date ignored", map[string]string{"If-Unmodified-Since": "yesterday"}, http.StatusOK},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			w := serveRequest(g, method, "/bucket/obj.txt", nil, tc.headers)
			if w.Code != tc.status {
				t.Fatalf("%s %s: status %d, want %d: %s", method, tc.name, w.Code, tc.status, w.Body.String())
			}
			switch {
			case w.Code == http.StatusPreconditionFailed && method == http.MethodGet:
				if errorCode(t, w) != "PreconditionFailed" {
					t.Fatalf("%s %s: body %s", method, tc.name, w.Body.String())
				}
				fallthrough
			case w.Code == http.StatusNotModified:
				if cl := w.Header().Get("Content-Length"); cl != "" && cl != strconv.Itoa(w.Body.Len()) {
					t.Fatalf("%s %s: Content-Length %s for a %d-byte body", method, tc.name, cl, w.Body.Len())
				}
			case method == http.MethodGet && w.Body.String() != "0123456789":
				t.Fatalf("%s %s: body %q", method, tc.name, w.Body.String())
			}
			if w.Code == http.StatusNotModified && (w.Body.Len() != 0 || w.Header().Get("ETag") != etag) {
				t.Fatalf("%s %s: 304 with body %q, ETag %q", method, tc.name, w.Body.String(), w.Header().Get("ETag"))
			}
		}
	}
}

// TestGetObject_FailedPreconditionOverTheWire reads a 412 through a real
// connection. ServeContent used to answer it with an empty body under the
// object's Content-Length, which a client sees as a truncated transfer.
func TestGetObject_FailedPreconditionOverTheWire(t *testing.T) {
	g, _, _ := objectGateway(t, Config{})
	srv := httptest.NewServer(g.server.Handler)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/bucket/obj.txt", nil)
	req.Header.Set("If-Match", `"stale"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("412 body could not be read whole: %v", err)
	}
	if resp.StatusCode != http.StatusPreconditionFailed || !bytes.Contains(body, []byte("<Code>PreconditionFailed</Code>")) {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != int64(len(body)) {
		t.Fatalf("Content-Length %d for %d bytes", resp.ContentLength, len(body))
	}
}

// TestGetObject_Ranges answers an unsatisfiable range with S3's XML
// InvalidRange and the size in Content-Range, and ignores a malformed one.
func TestGetObject_Ranges(t *testing.T) {
	g, root, info := objectGateway(t, Config{})
	if err := os.WriteFile(filepath.Join(root, "bucket", "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, rng, ifRange string
		status             int
		body               string
	}{
		{"/bucket/obj.txt", "bytes=2-4", "", http.StatusPartialContent, "234"},
		{"/bucket/obj.txt", "bytes=-3", "", http.StatusPartialContent, "789"},
		{"/bucket/obj.txt", "bytes=8-100", "", http.StatusPartialContent, "89"},
		{"/bucket/obj.txt", "bytes=10-", "", http.StatusRequestedRangeNotSatisfiable, ""},
		{"/bucket/obj.txt", "bytes=100-200", "", http.StatusRequestedRangeNotSatisfiable, ""},
		{"/bucket/obj.txt", "bytes=-0", "", http.StatusRequestedRangeNotSatisfiable, ""},
		{"/bucket/obj.txt", "bytes=x-y", "", http.StatusOK, "0123456789"},
		{"/bucket/obj.txt", "lines=1-2", "", http.StatusOK, "0123456789"},
		{"/bucket/obj.txt", "bytes=100-", `"stale"`, http.StatusOK, "0123456789"},
		{"/bucket/obj.txt", "bytes=2-4", etagFor(info), http.StatusPartialContent, "234"},
		{"/bucket/empty", "bytes=0-", "", http.StatusOK, ""},
	} {
		headers := map[string]string{"Range": tc.rng}
		if tc.ifRange != "" {
			headers["If-Range"] = tc.ifRange
		}
		w := serveRequest(g, http.MethodGet, tc.path, nil, headers)
		if w.Code != tc.status {
			t.Fatalf("%s %s: status %d, want %d: %s", tc.path, tc.rng, w.Code, tc.status, w.Body.String())
		}
		if tc.status == http.StatusRequestedRangeNotSatisfiable {
			if errorCode(t, w) != "InvalidRange" || w.Header().Get("Content-Range") != "bytes */10" ||
				w.Header().Get("Content-Type") != "application/xml" {
				t.Fatalf("%s: 416 %v %s", tc.rng, w.Header(), w.Body.String())
			}
			continue
		}
		if w.Body.String() != tc.body {
			t.Fatalf("%s %s: body %q, want %q", tc.path, tc.rng, w.Body.String(), tc.body)
		}
	}
}

// TestObjectErrors_AreTheClients maps keys the filesystem cannot hold onto
// the 4xx they are, instead of a 500 a client would retry.
func TestObjectErrors_AreTheClients(t *testing.T) {
	g, root, _ := objectGateway(t, Config{})
	if err := os.MkdirAll(filepath.Join(root, "bucket", "dir", "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 256)
	for _, tc := range []struct {
		method, path string
		status       int
		code         string
	}{
		{http.MethodGet, "/bucket/obj.txt/below", http.StatusNotFound, "NoSuchKey"},
		{http.MethodHead, "/bucket/obj.txt/below", http.StatusNotFound, ""},
		{http.MethodPut, "/bucket/obj.txt/below", http.StatusConflict, "ParentIsObject"},
		{http.MethodPut, "/bucket/obj.txt/deeper/below", http.StatusConflict, "ParentIsObject"},
		{http.MethodPut, "/bucket/dir", http.StatusConflict, "ObjectExistsAsDirectory"},
		{http.MethodGet, "/bucket/" + long, http.StatusBadRequest, "KeyTooLongError"},
		{http.MethodPut, "/bucket/" + long + "/x", http.StatusBadRequest, "KeyTooLongError"},
		{http.MethodDelete, "/bucket/" + long, http.StatusBadRequest, "KeyTooLongError"},
		{http.MethodPut, "/bucket/" + strings.Repeat("a/", 512) + "b", http.StatusBadRequest, "KeyTooLongError"},
		{http.MethodGet, "/bucket/a%00b", http.StatusBadRequest, "InvalidArgument"},
		{http.MethodPut, "/bucket/a%00b", http.StatusBadRequest, "InvalidArgument"},
		{http.MethodPut, "/bucket/a%FFb", http.StatusBadRequest, "InvalidArgument"},
		{http.MethodGet, "/nobucket/obj.txt", http.StatusNotFound, "NoSuchBucket"},
		{http.MethodHead, "/nobucket/obj.txt", http.StatusNotFound, ""},
		{http.MethodDelete, "/nobucket/obj.txt", http.StatusNotFound, "NoSuchBucket"},
	} {
		w := serveRequest(g, tc.method, tc.path, strings.NewReader("data"), nil)
		if w.Code != tc.status || (tc.code != "" && errorCode(t, w) != tc.code) {
			t.Fatalf("%s %.60s: %d %s, want %d %s", tc.method, tc.path, w.Code, w.Body.String(), tc.status, tc.code)
		}
	}
	if readObject(t, root, "bucket/obj.txt") != "0123456789" {
		t.Fatal("object changed")
	}
	if entries, err := os.ReadDir(filepath.Join(root, "bucket", "dir")); err != nil || len(entries) != 1 {
		t.Fatalf("folder changed: %v %v", entries, err)
	}
}

// TestPutObject_ConditionalWrites honours If-None-Match: * and If-Match on a
// PUT; If-None-Match: * used to overwrite an existing object.
func TestPutObject_ConditionalWrites(t *testing.T) {
	g, root, info := objectGateway(t, Config{})
	for _, tc := range []struct {
		name, path string
		headers    map[string]string
		status     int
		code       string
	}{
		{"create only, exists", "/bucket/obj.txt", map[string]string{"If-None-Match": "*"}, http.StatusPreconditionFailed, "PreconditionFailed"},
		{"replace stale", "/bucket/obj.txt", map[string]string{"If-Match": `"stale"`}, http.StatusPreconditionFailed, "PreconditionFailed"},
		{"replace missing", "/bucket/missing.txt", map[string]string{"If-Match": etagFor(info)}, http.StatusNotFound, "NoSuchKey"},
		{"if-none-match etag", "/bucket/obj.txt", map[string]string{"If-None-Match": etagFor(info)}, http.StatusNotImplemented, "NotImplemented"},
	} {
		w := serveRequest(g, http.MethodPut, tc.path, strings.NewReader("new"), tc.headers)
		if w.Code != tc.status || errorCode(t, w) != tc.code {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body.String())
		}
	}
	if readObject(t, root, "bucket/obj.txt") != "0123456789" {
		t.Fatal("refused conditional write changed the object")
	}
	if _, err := os.Stat(filepath.Join(root, "bucket", "missing.txt")); !os.IsNotExist(err) {
		t.Fatalf("refused conditional write created an object: %v", err)
	}

	if w := serveRequest(g, http.MethodPut, "/bucket/new.txt", strings.NewReader("new"), map[string]string{"If-None-Match": "*"}); w.Code != http.StatusOK {
		t.Fatalf("create only, free: %d %s", w.Code, w.Body.String())
	}
	if w := serveRequest(g, http.MethodPut, "/bucket/obj.txt", strings.NewReader("replaced"), map[string]string{"If-Match": etagFor(info)}); w.Code != http.StatusOK {
		t.Fatalf("replace current: %d %s", w.Code, w.Body.String())
	}
	if readObject(t, root, "bucket/obj.txt") != "replaced" || readObject(t, root, "bucket/new.txt") != "new" {
		t.Fatal("conditional writes that hold were not stored")
	}
}

// TestPutObject_ConditionIsDecidedAtPublication creates the object while a
// create-only PUT is still streaming its body: the condition held when the
// upload began, and must still be refused when the object is published.
func TestPutObject_ConditionIsDecidedAtPublication(t *testing.T) {
	g, root, _ := objectGateway(t, Config{})
	pr, pw := io.Pipe()
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		done <- serveRequest(g, http.MethodPut, "/bucket/race.txt", pr, map[string]string{"If-None-Match": "*"})
	}()
	// Once the first bytes are taken, the handler is past its early check.
	if _, err := pw.Write([]byte("loser ")); err != nil {
		t.Fatal(err)
	}
	if w := serveRequest(g, http.MethodPut, "/bucket/race.txt", strings.NewReader("winner"), nil); w.Code != http.StatusOK {
		t.Fatalf("competing put: %d", w.Code)
	}
	pw.Write([]byte("bytes"))
	pw.Close()
	w := <-done
	if w.Code != http.StatusPreconditionFailed || errorCode(t, w) != "PreconditionFailed" {
		t.Fatalf("create-only put over a new object: %d %s", w.Code, w.Body.String())
	}
	if got := readObject(t, root, "bucket/race.txt"); got != "winner" {
		t.Fatalf("object is %q", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "bucket")); len(entries) != 2 {
		t.Fatalf("scratch left behind: %v", entries)
	}
}

// TestUploads_OversizeRefusedBeforeReading refuses a PUT or a part whose
// declared length is over the limit without reading any of it, so a client
// that asked for 100-continue never sends the body.
func TestUploads_OversizeRefusedBeforeReading(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{MaxUploadBytes: 100}, multipart.Limits{MaxPartBytes: 50})
	id := initiateUpload(t, g, "bucket", "big")
	for path, length := range map[string]int64{
		"/bucket/big": 101,
		"/bucket/big?partNumber=1&uploadId=" + id: 51, // over the part limit, under the object's
	} {
		body := &observedBody{}
		req := httptest.NewRequest(http.MethodPut, path, body)
		req.ContentLength = length
		req.Header.Set("Expect", "100-continue")
		w := httptest.NewRecorder()
		g.route(w, req)
		if w.Code != http.StatusRequestEntityTooLarge || errorCode(t, w) != "EntityTooLarge" || body.reads != 0 {
			t.Fatalf("%s: %d %s after %d reads", path, w.Code, w.Body.String(), body.reads)
		}
	}
}

// TestPutObject_RefusedBeforeReading refuses a PUT that is bound to fail
// without reading its body: a create-only write over an existing object, a
// replacement of a stale generation, and an object over a folder.
func TestPutObject_RefusedBeforeReading(t *testing.T) {
	g, root, _ := objectGateway(t, Config{})
	if err := os.MkdirAll(filepath.Join(root, "bucket", "dir", "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path    string
		headers map[string]string
		status  int
	}{
		{"/bucket/obj.txt", map[string]string{"If-None-Match": "*"}, http.StatusPreconditionFailed},
		{"/bucket/obj.txt", map[string]string{"If-Match": `"stale"`}, http.StatusPreconditionFailed},
		{"/bucket/dir", nil, http.StatusConflict},
	} {
		body := &observedBody{}
		req := httptest.NewRequest(http.MethodPut, tc.path, body)
		req.ContentLength = 10
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		g.route(w, req)
		if w.Code != tc.status || body.reads != 0 {
			t.Fatalf("%s %v: %d %s after %d reads", tc.path, tc.headers, w.Code, w.Body.String(), body.reads)
		}
	}
}

// TestObjectContentTypes serves an allowlist of inert media types by name and
// everything else, notably anything a browser would run, as a download.
func TestObjectContentTypes(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"app.apk":    "application/vnd.android.package-archive",
		"icon.png":   "image/png",
		"PHOTO.JPG":  "image/jpeg",
		"a.webp":     "image/webp",
		"meta.json":  "application/json",
		"notes.txt":  "text/plain; charset=utf-8",
		"page.html":  "application/octet-stream",
		"image.svg":  "application/octet-stream",
		"feed.xml":   "application/octet-stream",
		"script.js":  "application/octet-stream",
		"no-ext":     "application/octet-stream",
		"dir.apk/fi": "application/octet-stream",
	} {
		if w := serveRequest(g, http.MethodPut, "/bucket/"+name, strings.NewReader("<svg onload=alert(1)>"), nil); w.Code != http.StatusOK {
			t.Fatalf("put %s: %d", name, w.Code)
		}
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			w := serveRequest(g, method, "/bucket/"+name, nil, nil)
			if got := w.Header().Get("Content-Type"); w.Code != http.StatusOK || got != want {
				t.Fatalf("%s %s: %d Content-Type %q, want %q", method, name, w.Code, got, want)
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("%s %s: no nosniff", method, name)
			}
		}
	}
}

// failingBody yields some bytes, then fails as a dropped connection does.
type failingBody struct{ sent bool }

func (b *failingBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, "partial"), nil
	}
	return 0, syscall.ECONNRESET
}

// syncBuffer is a log sink safe for concurrent handlers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestUploads_ClientAbortIsNotAServerError keeps a client that drops an upload
// out of the ERROR log: it is routine for phones and flaky links, and an alert
// on it would bury the real disk failures.
func TestUploads_ClientAbortIsNotAServerError(t *testing.T) {
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	root := t.TempDir()
	store, err := multipart.New(root, multipart.Limits{MinPartBytes: 4, MaxPartBytes: 1 << 20}, logger)
	if err != nil {
		t.Fatal(err)
	}
	g := New(root, Config{Multipart: store}, logger)
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	id := initiateUpload(t, g, "bucket", "big")
	for _, path := range []string{"/bucket/obj", "/bucket/big?partNumber=1&uploadId=" + id} {
		w := serveRequest(g, http.MethodPut, path, &failingBody{}, nil)
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "IncompleteBody" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	out := logs.String()
	if strings.Contains(out, "level=ERROR") || strings.Count(out, "client aborted the upload") != 2 {
		t.Fatalf("client aborts logged as server errors:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "bucket", "obj")); !os.IsNotExist(err) {
		t.Fatalf("aborted upload published: %v", err)
	}
}

// TestListObjects_ClientGoneIsNotAServerError keeps a listing its client
// abandoned out of the ERROR log.
func TestListObjects_ClientGoneIsNotAServerError(t *testing.T) {
	logs := &syncBuffer{}
	root := t.TempDir()
	g := New(root, Config{}, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err := os.MkdirAll(filepath.Join(root, "bucket", "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bucket", "dir", "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, url := range []string{"/bucket", "/bucket?list-type=2"} {
		req := httptest.NewRequest(http.MethodGet, url, nil).WithContext(ctx)
		g.route(httptest.NewRecorder(), req)
	}
	if out := logs.String(); strings.Contains(out, "level=ERROR") || strings.Count(out, "client went away") != 2 {
		t.Fatalf("abandoned listings logged as server errors:\n%s", out)
	}
}

// TestMultipart_CompleteChecksBodyDigests holds the part list of a completion
// to its declared digests, as DeleteObjects' key list is: a captured signed
// completion cannot be replayed to assemble other parts.
func TestMultipart_CompleteChecksBodyDigests(t *testing.T) {
	g, root, _ := multipartGateway(t, Config{}, multipart.Limits{})
	id := initiateUpload(t, g, "bucket", "obj")
	parts := []CompletePartEntry{{PartNumber: 1, ETag: uploadPart(t, g, "bucket", "obj", id, 1, []byte("payload"))}}
	body := completeBody(parts)
	md5Of := func(s string) string { sum := md5.Sum([]byte(s)); return base64.StdEncoding.EncodeToString(sum[:]) }
	sha256Of := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	for _, tc := range []struct{ header, value, code string }{
		{"Content-MD5", md5Of("<CompleteMultipartUpload/>"), "BadDigest"},
		{"Content-MD5", "not base64", "BadDigest"},
		{"X-Amz-Content-Sha256", sha256Of("<CompleteMultipartUpload/>"), "XAmzContentSHA256Mismatch"},
	} {
		w := serveRequest(g, http.MethodPost, "/bucket/obj?uploadId="+id, strings.NewReader(body), map[string]string{tc.header: tc.value})
		if w.Code != http.StatusBadRequest || errorCode(t, w) != tc.code {
			t.Fatalf("%s %s: %d %s", tc.header, tc.value, w.Code, w.Body.String())
		}
		if _, err := os.Stat(filepath.Join(root, "bucket", "obj")); !os.IsNotExist(err) {
			t.Fatalf("refused completion published the object: %v", err)
		}
	}
	w := serveRequest(g, http.MethodPost, "/bucket/obj?uploadId="+id, strings.NewReader(body),
		map[string]string{"Content-MD5": md5Of(body), "X-Amz-Content-Sha256": sha256Of(body)})
	if w.Code != http.StatusOK {
		t.Fatalf("complete with matching digests: %d %s", w.Code, w.Body.String())
	}
}

// TestMultipart_CompleteConditionalWrite refuses a create-only completion over
// an existing object and keeps the upload for a retry.
func TestMultipart_CompleteConditionalWrite(t *testing.T) {
	g, root, _ := multipartGateway(t, Config{}, multipart.Limits{})
	if err := os.WriteFile(filepath.Join(root, "bucket", "obj"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := initiateUpload(t, g, "bucket", "obj")
	parts := []CompletePartEntry{{PartNumber: 1, ETag: uploadPart(t, g, "bucket", "obj", id, 1, []byte("payload"))}}
	w := serveRequest(g, http.MethodPost, "/bucket/obj?uploadId="+id, strings.NewReader(completeBody(parts)), map[string]string{"If-None-Match": "*"})
	if w.Code != http.StatusPreconditionFailed || readObject(t, root, "bucket/obj") != "existing" {
		t.Fatalf("create-only completion: %d %s", w.Code, w.Body.String())
	}
	if w := completeUpload(g, "bucket", "obj", id, parts); w.Code != http.StatusOK || readObject(t, root, "bucket/obj") != "payload" {
		t.Fatalf("upload not kept after a refused completion: %d %s", w.Code, w.Body.String())
	}
}

// TestMultipart_CompleteOverFolderIsConflict refuses to complete an upload
// whose key has become a folder, as a PUT of it is refused, and keeps the
// upload for when the key is free again.
func TestMultipart_CompleteOverFolderIsConflict(t *testing.T) {
	g, root, _ := multipartGateway(t, Config{}, multipart.Limits{})
	id := initiateUpload(t, g, "bucket", "obj")
	parts := []CompletePartEntry{{PartNumber: 1, ETag: uploadPart(t, g, "bucket", "obj", id, 1, []byte("payload"))}}
	if err := os.MkdirAll(filepath.Join(root, "bucket", "obj", "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := completeUpload(g, "bucket", "obj", id, parts)
	if w.Code != http.StatusConflict || errorCode(t, w) != "ObjectExistsAsDirectory" {
		t.Fatalf("complete over a folder: %d %s", w.Code, w.Body.String())
	}
	if err := os.RemoveAll(filepath.Join(root, "bucket", "obj")); err != nil {
		t.Fatal(err)
	}
	if w := completeUpload(g, "bucket", "obj", id, parts); w.Code != http.StatusOK || readObject(t, root, "bucket/obj") != "payload" {
		t.Fatalf("upload lost after a refused completion: %d %s", w.Code, w.Body.String())
	}
}

// TestETag_WriteResponsesMatchReads reports one ETag per object generation on
// every response: PUT, CompleteMultipartUpload and CopyObject used to report
// other ETags than HEAD, GET and LIST.
func TestETag_WriteResponsesMatchReads(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})
	written := map[string]string{}

	put := serveRequest(g, http.MethodPut, "/bucket/put", strings.NewReader("put"), nil)
	written["put"] = put.Header().Get("ETag")

	id := initiateUpload(t, g, "bucket", "multipart")
	parts := []CompletePartEntry{
		{PartNumber: 1, ETag: uploadPart(t, g, "bucket", "multipart", id, 1, bytes.Repeat([]byte("a"), 8))},
		{PartNumber: 2, ETag: uploadPart(t, g, "bucket", "multipart", id, 2, []byte("b"))},
	}
	var completed CompleteMultipartUploadResult
	xml.Unmarshal(completeUpload(g, "bucket", "multipart", id, parts).Body.Bytes(), &completed)
	written["multipart"] = completed.ETag

	var copied CopyObjectResult
	xml.Unmarshal(copyRequest(g, "/bucket/copy", "bucket/put", nil).Body.Bytes(), &copied)
	written["copy"] = copied.ETag

	var list ListBucketResultV2
	xml.Unmarshal(serveRequest(g, http.MethodGet, "/bucket?list-type=2", nil, nil).Body.Bytes(), &list)
	listed := map[string]string{}
	for _, o := range list.Contents {
		listed[o.Key] = o.ETag
	}
	for key, etag := range written {
		head := serveRequest(g, http.MethodHead, "/bucket/"+key, nil, nil).Header().Get("ETag")
		get := serveRequest(g, http.MethodGet, "/bucket/"+key, nil, nil).Header().Get("ETag")
		if etag == "" || etag != head || etag != get || etag != listed[key] {
			t.Fatalf("%s: write %q, HEAD %q, GET %q, LIST %q", key, etag, head, get, listed[key])
		}
	}
}
