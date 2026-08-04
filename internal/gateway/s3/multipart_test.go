package s3

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
	"github.com/solkin/sebastian/internal/multipart"
)

// multipartGateway creates a gateway backed by a multipart store with small part
// limits, plus a ready-made bucket. It returns the gateway, the root directory,
// and the store (for restart and cleanup scenarios).
func multipartGateway(t *testing.T, cfg Config, limits multipart.Limits) (*Gateway, string, *multipart.Store) {
	t.Helper()
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if limits.MinPartBytes == 0 {
		limits.MinPartBytes = 4
	}
	if limits.MaxPartBytes == 0 {
		limits.MaxPartBytes = 1 << 20
	}
	store, err := multipart.New(root, limits, logger)
	if err != nil {
		t.Fatalf("multipart store: %v", err)
	}

	cfg.Multipart = store
	g := New(root, cfg, logger)

	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return g, root, store
}

// initiateUpload starts an upload and returns its ID.
func initiateUpload(t *testing.T, g *Gateway, bucket, key string) string {
	t.Helper()
	w := serveRequest(g, http.MethodPost, "/"+bucket+"/"+key+"?uploads", nil, noAuth())
	if w.Code != http.StatusOK {
		t.Fatalf("initiate: status %d: %s", w.Code, w.Body.String())
	}
	var res InitiateMultipartUploadResult
	if err := xml.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("parse initiate response: %v", err)
	}
	if res.Bucket != bucket || res.Key != key || res.UploadID == "" {
		t.Fatalf("initiate response = %+v", res)
	}
	return res.UploadID
}

// uploadPart sends one part and returns the ETag from the response header.
func uploadPart(t *testing.T, g *Gateway, bucket, key, uploadID string, number int, payload []byte) string {
	t.Helper()
	url := fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", bucket, key, number, uploadID)
	w := serveRequest(g, http.MethodPut, url, bytes.NewReader(payload), noAuth())
	if w.Code != http.StatusOK {
		t.Fatalf("upload part %d: status %d: %s", number, w.Code, w.Body.String())
	}
	etag := w.Header().Get("ETag")
	if want := `"` + md5HexOf(payload) + `"`; etag != want {
		t.Fatalf("part %d etag = %s, want %s", number, etag, want)
	}
	return etag
}

// completeBody renders a CompleteMultipartUpload request document.
func completeBody(parts []CompletePartEntry) string {
	var b strings.Builder
	b.WriteString("<CompleteMultipartUpload>")
	for _, p := range parts {
		fmt.Fprintf(&b, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", p.PartNumber, p.ETag)
	}
	b.WriteString("</CompleteMultipartUpload>")
	return b.String()
}

func completeUpload(g *Gateway, bucket, key, uploadID string, parts []CompletePartEntry) *httptest.ResponseRecorder {
	url := fmt.Sprintf("/%s/%s?uploadId=%s", bucket, key, uploadID)
	return serveRequest(g, http.MethodPost, url, strings.NewReader(completeBody(parts)), noAuth())
}

func md5HexOf(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func compositeETagOf(payloads [][]byte) string {
	h := md5.New()
	for _, p := range payloads {
		sum := md5.Sum(p)
		h.Write(sum[:])
	}
	return fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(h.Sum(nil)), len(payloads))
}

// errorCode extracts the S3 error code from a response body.
func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e S3Error
	if err := xml.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("parse error response %q: %v", w.Body.String(), err)
	}
	return e.Code
}

// --- happy path ---

func TestMultipart_FullCycle(t *testing.T) {
	g, root, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "docs/report.bin")
	payloads := [][]byte{
		bytes.Repeat([]byte("a"), 16),
		bytes.Repeat([]byte("b"), 16),
		bytes.Repeat([]byte("c"), 5),
	}
	var parts []CompletePartEntry
	for i, p := range payloads {
		etag := uploadPart(t, g, "bucket", "docs/report.bin", uploadID, i+1, p)
		parts = append(parts, CompletePartEntry{PartNumber: i + 1, ETag: etag})
	}

	w := completeUpload(g, "bucket", "docs/report.bin", uploadID, parts)
	if w.Code != http.StatusOK {
		t.Fatalf("complete: status %d: %s", w.Code, w.Body.String())
	}
	var res CompleteMultipartUploadResult
	if err := xml.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("parse complete response: %v", err)
	}
	if res.ETag != compositeETagOf(payloads) {
		t.Fatalf("etag = %s, want %s", res.ETag, compositeETagOf(payloads))
	}
	if res.Bucket != "bucket" || res.Key != "docs/report.bin" {
		t.Fatalf("complete response = %+v", res)
	}

	// The object is readable through the normal object API.
	got := serveRequest(g, http.MethodGet, "/bucket/docs/report.bin", nil, noAuth())
	if got.Code != http.StatusOK {
		t.Fatalf("get object: status %d", got.Code)
	}
	if !bytes.Equal(got.Body.Bytes(), bytes.Join(payloads, nil)) {
		t.Fatal("assembled object has wrong content")
	}

	// Nothing is left staged.
	staging := filepath.Join(root, gateway.ReservedDirName, "multipart")
	entries, err := os.ReadDir(staging)
	if err != nil {
		t.Fatalf("read staging: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging not cleaned: %d entries remain", len(entries))
	}
}

func TestMultipart_ListPartsAndUploads(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	uploadPart(t, g, "bucket", "obj", uploadID, 1, bytes.Repeat([]byte("a"), 8))
	uploadPart(t, g, "bucket", "obj", uploadID, 2, bytes.Repeat([]byte("b"), 8))

	w := serveRequest(g, http.MethodGet, "/bucket/obj?uploadId="+uploadID, nil, noAuth())
	if w.Code != http.StatusOK {
		t.Fatalf("list parts: status %d: %s", w.Code, w.Body.String())
	}
	var lp ListPartsResult
	if err := xml.Unmarshal(w.Body.Bytes(), &lp); err != nil {
		t.Fatalf("parse list parts: %v", err)
	}
	if len(lp.Parts) != 2 || lp.IsTruncated {
		t.Fatalf("list parts = %+v", lp)
	}
	if lp.Parts[0].PartNumber != 1 || lp.Parts[0].Size != 8 {
		t.Fatalf("part 1 = %+v", lp.Parts[0])
	}
	if lp.Parts[0].ETag != `"`+md5HexOf(bytes.Repeat([]byte("a"), 8))+`"` {
		t.Fatalf("part 1 etag = %s", lp.Parts[0].ETag)
	}

	// A truncated page reports where to resume.
	w = serveRequest(g, http.MethodGet, "/bucket/obj?uploadId="+uploadID+"&max-parts=1", nil, noAuth())
	var page ListPartsResult
	if err := xml.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("parse list parts: %v", err)
	}
	if len(page.Parts) != 1 || !page.IsTruncated || page.NextPartNumberMarker != 1 {
		t.Fatalf("truncated list parts = %+v", page)
	}

	w = serveRequest(g, http.MethodGet, "/bucket?uploads", nil, noAuth())
	if w.Code != http.StatusOK {
		t.Fatalf("list uploads: status %d: %s", w.Code, w.Body.String())
	}
	var lu ListMultipartUploadsResult
	if err := xml.Unmarshal(w.Body.Bytes(), &lu); err != nil {
		t.Fatalf("parse list uploads: %v", err)
	}
	if len(lu.Uploads) != 1 || lu.Uploads[0].UploadID != uploadID || lu.Uploads[0].Key != "obj" {
		t.Fatalf("list uploads = %+v", lu)
	}
	if lu.Uploads[0].Initiated == "" {
		t.Fatal("Initiated timestamp is missing")
	}
}

// --- interruption, retries, and aborts ---

func TestMultipart_AbortDiscardsUpload(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	etag := uploadPart(t, g, "bucket", "obj", uploadID, 1, bytes.Repeat([]byte("a"), 8))

	w := serveRequest(g, http.MethodDelete, "/bucket/obj?uploadId="+uploadID, nil, noAuth())
	if w.Code != http.StatusNoContent {
		t.Fatalf("abort: status %d: %s", w.Code, w.Body.String())
	}

	// Everything addressed at the aborted upload now reports NoSuchUpload.
	cases := []struct {
		name   string
		method string
		url    string
		body   io.Reader
	}{
		{"upload part", http.MethodPut, "/bucket/obj?partNumber=2&uploadId=" + uploadID, strings.NewReader("more")},
		{"list parts", http.MethodGet, "/bucket/obj?uploadId=" + uploadID, nil},
		{"abort again", http.MethodDelete, "/bucket/obj?uploadId=" + uploadID, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serveRequest(g, tc.method, tc.url, tc.body, noAuth())
			if w.Code != http.StatusNotFound {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if code := errorCode(t, w); code != "NoSuchUpload" {
				t.Fatalf("error code = %s, want NoSuchUpload", code)
			}
		})
	}

	w = completeUpload(g, "bucket", "obj", uploadID, []CompletePartEntry{{PartNumber: 1, ETag: etag}})
	if w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchUpload" {
		t.Fatalf("complete after abort: status %d, body %s", w.Code, w.Body.String())
	}
}

func TestMultipart_RetriedPartReplacesPrevious(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	uploadPart(t, g, "bucket", "obj", uploadID, 1, bytes.Repeat([]byte("x"), 8))

	// The client decides the first attempt failed and re-sends the part.
	final := bytes.Repeat([]byte("y"), 8)
	etag := uploadPart(t, g, "bucket", "obj", uploadID, 1, final)

	w := completeUpload(g, "bucket", "obj", uploadID, []CompletePartEntry{{PartNumber: 1, ETag: etag}})
	if w.Code != http.StatusOK {
		t.Fatalf("complete: status %d: %s", w.Code, w.Body.String())
	}

	got := serveRequest(g, http.MethodGet, "/bucket/obj", nil, noAuth())
	if !bytes.Equal(got.Body.Bytes(), final) {
		t.Fatalf("object = %q, want %q", got.Body.String(), final)
	}
}

func TestMultipart_RepeatedCompleteIsRejected(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	payload := bytes.Repeat([]byte("a"), 8)
	etag := uploadPart(t, g, "bucket", "obj", uploadID, 1, payload)
	parts := []CompletePartEntry{{PartNumber: 1, ETag: etag}}

	if w := completeUpload(g, "bucket", "obj", uploadID, parts); w.Code != http.StatusOK {
		t.Fatalf("first complete: status %d: %s", w.Code, w.Body.String())
	}
	w := completeUpload(g, "bucket", "obj", uploadID, parts)
	if w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchUpload" {
		t.Fatalf("second complete: status %d, body %s", w.Code, w.Body.String())
	}

	// The object written by the first completion is untouched.
	got := serveRequest(g, http.MethodGet, "/bucket/obj", nil, noAuth())
	if !bytes.Equal(got.Body.Bytes(), payload) {
		t.Fatal("object was modified by the rejected retry")
	}
}

// truncatedBody stops early, standing in for a connection that drops mid-part.
type truncatedBody struct {
	data []byte
	sent int
}

func (r *truncatedBody) Read(p []byte) (int, error) {
	if r.sent >= len(r.data)/2 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.data[r.sent:])
	r.sent += n
	return n, nil
}

func TestMultipart_InterruptedPartIsNotStaged(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	url := fmt.Sprintf("/bucket/obj?partNumber=1&uploadId=%s", uploadID)
	w := serveRequest(g, http.MethodPut, url, &truncatedBody{data: bytes.Repeat([]byte("a"), 64)}, noAuth())
	if w.Code == http.StatusOK {
		t.Fatal("an interrupted part must not be accepted")
	}

	list := serveRequest(g, http.MethodGet, "/bucket/obj?uploadId="+uploadID, nil, noAuth())
	var lp ListPartsResult
	if err := xml.Unmarshal(list.Body.Bytes(), &lp); err != nil {
		t.Fatalf("parse list parts: %v", err)
	}
	if len(lp.Parts) != 0 {
		t.Fatalf("interrupted part was staged: %+v", lp.Parts)
	}

	// The upload itself survives, so the client can simply retry the part.
	etag := uploadPart(t, g, "bucket", "obj", uploadID, 1, bytes.Repeat([]byte("a"), 64))
	if w := completeUpload(g, "bucket", "obj", uploadID, []CompletePartEntry{{PartNumber: 1, ETag: etag}}); w.Code != http.StatusOK {
		t.Fatalf("complete after retry: status %d: %s", w.Code, w.Body.String())
	}
}

// --- integrity ---

func TestMultipart_ContentMD5Mismatch(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	wrong := md5.Sum([]byte("not what we send"))
	headers := map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(wrong[:])}

	url := fmt.Sprintf("/bucket/obj?partNumber=1&uploadId=%s", uploadID)
	w := serveRequest(g, http.MethodPut, url, bytes.NewReader([]byte("payload")), headers)
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "BadDigest" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
}

func TestMultipart_CompleteRejectsWrongETag(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	uploadPart(t, g, "bucket", "obj", uploadID, 1, bytes.Repeat([]byte("a"), 8))

	w := completeUpload(g, "bucket", "obj", uploadID, []CompletePartEntry{
		{PartNumber: 1, ETag: `"` + md5HexOf([]byte("different")) + `"`},
	})
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "InvalidPart" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
}

func TestMultipart_CompleteErrorCodes(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{MinPartBytes: 16})

	newUpload := func() (string, []CompletePartEntry) {
		id := initiateUpload(t, g, "bucket", "obj")
		e1 := uploadPart(t, g, "bucket", "obj", id, 1, bytes.Repeat([]byte("a"), 8))
		e2 := uploadPart(t, g, "bucket", "obj", id, 2, bytes.Repeat([]byte("b"), 8))
		return id, []CompletePartEntry{{PartNumber: 1, ETag: e1}, {PartNumber: 2, ETag: e2}}
	}

	t.Run("part below minimum size", func(t *testing.T) {
		id, parts := newUpload()
		w := completeUpload(g, "bucket", "obj", id, parts)
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "EntityTooSmall" {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
	})

	t.Run("descending part order", func(t *testing.T) {
		id, parts := newUpload()
		w := completeUpload(g, "bucket", "obj", id, []CompletePartEntry{parts[1], parts[0]})
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "InvalidPartOrder" {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
	})

	t.Run("empty part list", func(t *testing.T) {
		id, _ := newUpload()
		w := completeUpload(g, "bucket", "obj", id, nil)
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "InvalidRequest" {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
	})

	t.Run("malformed xml", func(t *testing.T) {
		id, _ := newUpload()
		url := fmt.Sprintf("/bucket/obj?uploadId=%s", id)
		w := serveRequest(g, http.MethodPost, url, strings.NewReader("<CompleteMultipartUpload"), noAuth())
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "MalformedXML" {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
	})

	t.Run("no object is published", func(t *testing.T) {
		w := serveRequest(g, http.MethodHead, "/bucket/obj", nil, noAuth())
		if w.Code != http.StatusNotFound {
			t.Fatalf("object exists after failed completions: status %d", w.Code)
		}
	})
}

// --- limits ---

func TestMultipart_PartSizeAndNumberLimits(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{MaxPartBytes: 8, MaxParts: 3})

	uploadID := initiateUpload(t, g, "bucket", "obj")

	t.Run("oversized part", func(t *testing.T) {
		url := fmt.Sprintf("/bucket/obj?partNumber=1&uploadId=%s", uploadID)
		w := serveRequest(g, http.MethodPut, url, bytes.NewReader(bytes.Repeat([]byte("a"), 9)), noAuth())
		if w.Code != http.StatusRequestEntityTooLarge || errorCode(t, w) != "EntityTooLarge" {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
	})

	t.Run("part number above the cap", func(t *testing.T) {
		url := fmt.Sprintf("/bucket/obj?partNumber=4&uploadId=%s", uploadID)
		w := serveRequest(g, http.MethodPut, url, bytes.NewReader([]byte("ok")), noAuth())
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "InvalidArgument" {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
	})

	t.Run("non-numeric part number", func(t *testing.T) {
		url := fmt.Sprintf("/bucket/obj?partNumber=abc&uploadId=%s", uploadID)
		w := serveRequest(g, http.MethodPut, url, bytes.NewReader([]byte("ok")), noAuth())
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "InvalidArgument" {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
	})
}

func TestMultipart_ObjectSizeLimit(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{MaxUploadBytes: 12}, multipart.Limits{MinPartBytes: 4, MaxObjectBytes: 12})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	e1 := uploadPart(t, g, "bucket", "obj", uploadID, 1, bytes.Repeat([]byte("a"), 8))
	e2 := uploadPart(t, g, "bucket", "obj", uploadID, 2, bytes.Repeat([]byte("b"), 8))

	w := completeUpload(g, "bucket", "obj", uploadID, []CompletePartEntry{
		{PartNumber: 1, ETag: e1}, {PartNumber: 2, ETag: e2},
	})
	if w.Code != http.StatusRequestEntityTooLarge || errorCode(t, w) != "EntityTooLarge" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
}

func TestMultipart_ConcurrentPartCapReturnsSlowDown(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{MaxConcurrentParts: 1})

	uploadID := initiateUpload(t, g, "bucket", "obj")

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		url := fmt.Sprintf("/bucket/obj?partNumber=1&uploadId=%s", uploadID)
		w := serveRequest(g, http.MethodPut, url, &gatedBody{started: started, release: release, data: []byte("hello")}, noAuth())
		done <- w.Code
	}()

	<-started
	url := fmt.Sprintf("/bucket/obj?partNumber=2&uploadId=%s", uploadID)
	w := serveRequest(g, http.MethodPut, url, bytes.NewReader([]byte("second")), noAuth())
	close(release)

	if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "SlowDown" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("SlowDown response should carry Retry-After")
	}
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first part: status %d", code)
	}
}

// gatedBody signals when it is first read and blocks until released.
type gatedBody struct {
	started  chan struct{}
	release  chan struct{}
	data     []byte
	signaled bool
}

func (r *gatedBody) Read(p []byte) (int, error) {
	if !r.signaled {
		r.signaled = true
		close(r.started)
		<-r.release
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestMultipart_ActiveUploadCapReturnsSlowDown(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{MaxActiveUploads: 1})

	initiateUpload(t, g, "bucket", "first")

	w := serveRequest(g, http.MethodPost, "/bucket/second?uploads", nil, noAuth())
	if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "SlowDown" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
}

// --- concurrency ---

func TestMultipart_ConcurrentUploadsAreIndependent(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	const uploads = 4
	const partsPerUpload = 6

	var wg sync.WaitGroup
	errs := make(chan error, uploads)
	for u := 0; u < uploads; u++ {
		wg.Add(1)
		go func(u int) {
			defer wg.Done()
			key := fmt.Sprintf("obj-%d", u)
			id := initiateUpload(t, g, "bucket", key)

			payloads := make([][]byte, partsPerUpload)
			etags := make([]string, partsPerUpload)
			var inner sync.WaitGroup
			for p := 0; p < partsPerUpload; p++ {
				payloads[p] = bytes.Repeat([]byte{byte('a' + u), byte('0' + p)}, 8)
				inner.Add(1)
				go func(p int) {
					defer inner.Done()
					url := fmt.Sprintf("/bucket/%s?partNumber=%d&uploadId=%s", key, p+1, id)
					w := serveRequest(g, http.MethodPut, url, bytes.NewReader(payloads[p]), noAuth())
					if w.Code == http.StatusOK {
						etags[p] = w.Header().Get("ETag")
					}
				}(p)
			}
			inner.Wait()

			var parts []CompletePartEntry
			for p, e := range etags {
				if e == "" {
					errs <- fmt.Errorf("upload %d part %d failed", u, p+1)
					return
				}
				parts = append(parts, CompletePartEntry{PartNumber: p + 1, ETag: e})
			}
			if w := completeUpload(g, "bucket", key, id, parts); w.Code != http.StatusOK {
				errs <- fmt.Errorf("upload %d complete: status %d: %s", u, w.Code, w.Body.String())
				return
			}

			got := serveRequest(g, http.MethodGet, "/bucket/"+key, nil, noAuth())
			if !bytes.Equal(got.Body.Bytes(), bytes.Join(payloads, nil)) {
				errs <- fmt.Errorf("upload %d assembled wrong content", u)
			}
		}(u)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// --- restart recovery ---

func TestMultipart_SurvivesGatewayRestart(t *testing.T) {
	root := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	limits := multipart.Limits{MinPartBytes: 4, MaxPartBytes: 1 << 20}

	newGateway := func() *Gateway {
		store, err := multipart.New(root, limits, logger)
		if err != nil {
			t.Fatalf("multipart store: %v", err)
		}
		return New(root, Config{Multipart: store}, logger)
	}

	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	before := newGateway()
	uploadID := initiateUpload(t, before, "bucket", "resumed.bin")
	head := bytes.Repeat([]byte("a"), 16)
	e1 := uploadPart(t, before, "bucket", "resumed.bin", uploadID, 1, head)

	// A fresh process over the same directory continues the upload.
	after := newGateway()

	list := serveRequest(after, http.MethodGet, "/bucket/resumed.bin?uploadId="+uploadID, nil, noAuth())
	if list.Code != http.StatusOK {
		t.Fatalf("list parts after restart: status %d: %s", list.Code, list.Body.String())
	}
	var lp ListPartsResult
	if err := xml.Unmarshal(list.Body.Bytes(), &lp); err != nil {
		t.Fatalf("parse list parts: %v", err)
	}
	if len(lp.Parts) != 1 || lp.Parts[0].PartNumber != 1 {
		t.Fatalf("staged part lost across restart: %+v", lp.Parts)
	}

	tail := bytes.Repeat([]byte("b"), 8)
	e2 := uploadPart(t, after, "bucket", "resumed.bin", uploadID, 2, tail)

	w := completeUpload(after, "bucket", "resumed.bin", uploadID, []CompletePartEntry{
		{PartNumber: 1, ETag: e1}, {PartNumber: 2, ETag: e2},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("complete after restart: status %d: %s", w.Code, w.Body.String())
	}

	got := serveRequest(after, http.MethodGet, "/bucket/resumed.bin", nil, noAuth())
	if !bytes.Equal(got.Body.Bytes(), append(append([]byte{}, head...), tail...)) {
		t.Fatal("object assembled after restart has wrong content")
	}
}

func TestMultipart_JanitorRemovesExpiredUploads(t *testing.T) {
	g, root, store := multipartGateway(t, Config{}, multipart.Limits{UploadTTL: time.Hour})

	stale := initiateUpload(t, g, "bucket", "stale")
	uploadPart(t, g, "bucket", "stale", stale, 1, bytes.Repeat([]byte("a"), 8))
	fresh := initiateUpload(t, g, "bucket", "fresh")

	staleDir := filepath.Join(root, gateway.ReservedDirName, "multipart", stale)
	past := time.Now().Add(-3 * time.Hour)
	entries, err := os.ReadDir(staleDir)
	if err != nil {
		t.Fatalf("read staging: %v", err)
	}
	for _, e := range entries {
		if err := os.Chtimes(filepath.Join(staleDir, e.Name()), past, past); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	if err := os.Chtimes(staleDir, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	store.Cleanup(time.Now())

	w := serveRequest(g, http.MethodGet, "/bucket/stale?uploadId="+stale, nil, noAuth())
	if w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchUpload" {
		t.Fatalf("expired upload still addressable: status %d", w.Code)
	}
	w = serveRequest(g, http.MethodGet, "/bucket/fresh?uploadId="+fresh, nil, noAuth())
	if w.Code != http.StatusOK {
		t.Fatalf("fresh upload was collected: status %d: %s", w.Code, w.Body.String())
	}
}

// --- isolation of the staging area ---

func TestMultipart_StagingIsHiddenFromObjectAPI(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	uploadPart(t, g, "bucket", "obj", uploadID, 1, bytes.Repeat([]byte("a"), 8))

	// Buckets never include the reserved state directory.
	w := serveRequest(g, http.MethodGet, "/", nil, noAuth())
	if strings.Contains(w.Body.String(), gateway.ReservedDirName) {
		t.Fatalf("ListBuckets exposed the reserved directory: %s", w.Body.String())
	}

	// Nor can it be addressed as a bucket, in any operation.
	for _, tc := range []struct{ method, url string }{
		{http.MethodGet, "/" + gateway.ReservedDirName},
		{http.MethodPut, "/" + gateway.ReservedDirName},
		{http.MethodDelete, "/" + gateway.ReservedDirName},
		{http.MethodHead, "/" + gateway.ReservedDirName},
		{http.MethodGet, "/" + gateway.ReservedDirName + "/multipart/" + uploadID + "/upload.json"},
	} {
		w := serveRequest(g, tc.method, tc.url, nil, noAuth())
		if w.Code == http.StatusOK {
			t.Fatalf("%s %s was allowed", tc.method, tc.url)
		}
	}

	// Staged parts are not visible as objects in the bucket either.
	w = serveRequest(g, http.MethodGet, "/bucket?list-type=2", nil, noAuth())
	var lr ListBucketResultV2
	if err := xml.Unmarshal(w.Body.Bytes(), &lr); err != nil {
		t.Fatalf("parse listing: %v", err)
	}
	if len(lr.Contents) != 0 {
		t.Fatalf("staged parts leaked into the bucket listing: %+v", lr.Contents)
	}
}

func TestMultipart_BucketWithUploadsCannotBeDeleted(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")

	w := serveRequest(g, http.MethodDelete, "/bucket", nil, noAuth())
	if w.Code != http.StatusConflict || errorCode(t, w) != "BucketNotEmpty" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	// Once the upload is gone the empty bucket can be deleted again.
	if w := serveRequest(g, http.MethodDelete, "/bucket/obj?uploadId="+uploadID, nil, noAuth()); w.Code != http.StatusNoContent {
		t.Fatalf("abort: status %d", w.Code)
	}
	if w := serveRequest(g, http.MethodDelete, "/bucket", nil, noAuth()); w.Code != http.StatusNoContent {
		t.Fatalf("delete bucket: status %d: %s", w.Code, w.Body.String())
	}
}

// --- request validation ---

func TestMultipart_UploadIDIsBoundToBucketAndKey(t *testing.T) {
	g, root, _ := multipartGateway(t, Config{}, multipart.Limits{})
	if err := os.Mkdir(filepath.Join(root, "other"), 0o755); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	uploadID := initiateUpload(t, g, "bucket", "obj")

	// The same ID under a different key or bucket must not be usable.
	for _, url := range []string{
		"/bucket/different?partNumber=1&uploadId=" + uploadID,
		"/other/obj?partNumber=1&uploadId=" + uploadID,
	} {
		w := serveRequest(g, http.MethodPut, url, bytes.NewReader([]byte("data")), noAuth())
		if w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchUpload" {
			t.Fatalf("PUT %s: status %d, body %s", url, w.Code, w.Body.String())
		}
	}
}

func TestMultipart_MalformedUploadID(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	for _, id := range []string{"nope", "../../../etc", strings.Repeat("z", 32)} {
		url := fmt.Sprintf("/bucket/obj?partNumber=1&uploadId=%s", id)
		w := serveRequest(g, http.MethodPut, url, bytes.NewReader([]byte("data")), noAuth())
		if w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchUpload" {
			t.Fatalf("uploadId=%q: status %d, body %s", id, w.Code, w.Body.String())
		}
	}
}

func TestMultipart_UnknownBucket(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	w := serveRequest(g, http.MethodPost, "/missing/obj?uploads", nil, noAuth())
	if w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchBucket" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	w = serveRequest(g, http.MethodGet, "/missing?uploads", nil, noAuth())
	if w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchBucket" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
}

func TestMultipart_DisabledWhenStoreIsAbsent(t *testing.T) {
	g, syncDir := testGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(syncDir, "bucket"), 0o755); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	w := serveRequest(g, http.MethodPost, "/bucket/obj?uploads", nil, noAuth())
	if w.Code != http.StatusNotImplemented || errorCode(t, w) != "NotImplemented" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	// A plain PUT still works when multipart is unavailable.
	w = serveRequest(g, http.MethodPut, "/bucket/obj", strings.NewReader("data"), noAuth())
	if w.Code != http.StatusOK {
		t.Fatalf("plain put: status %d: %s", w.Code, w.Body.String())
	}
}

func TestMultipart_ListUploadsDelimiterAndPaging(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	for _, key := range []string{"a.txt", "photos/1.jpg", "photos/2.jpg", "videos/clip.mp4"} {
		initiateUpload(t, g, "bucket", key)
	}

	// A delimiter rolls the nested keys up into common prefixes, leaving only the
	// top-level key as an upload.
	w := serveRequest(g, http.MethodGet, "/bucket?uploads&delimiter=/", nil, noAuth())
	var res ListMultipartUploadsResult
	if err := xml.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(res.Uploads) != 1 || res.Uploads[0].Key != "a.txt" {
		t.Fatalf("uploads = %+v, want only a.txt", res.Uploads)
	}
	if len(res.CommonPrefixes) != 2 ||
		res.CommonPrefixes[0].Prefix != "photos/" || res.CommonPrefixes[1].Prefix != "videos/" {
		t.Fatalf("common prefixes = %+v", res.CommonPrefixes)
	}

	// A prefix narrows the set, and the delimiter still applies within it.
	w = serveRequest(g, http.MethodGet, "/bucket?uploads&prefix=photos/&delimiter=/", nil, noAuth())
	var scoped ListMultipartUploadsResult
	if err := xml.Unmarshal(w.Body.Bytes(), &scoped); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(scoped.Uploads) != 2 || len(scoped.CommonPrefixes) != 0 {
		t.Fatalf("scoped listing = %+v", scoped)
	}

	// Paging walks the whole set without repeating or dropping an upload.
	seen := map[string]bool{}
	keyMarker, idMarker := "", ""
	for page := 0; page < 10; page++ {
		url := fmt.Sprintf("/bucket?uploads&max-uploads=1&key-marker=%s&upload-id-marker=%s", keyMarker, idMarker)
		w := serveRequest(g, http.MethodGet, url, nil, noAuth())
		var p ListMultipartUploadsResult
		if err := xml.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatalf("parse page: %v", err)
		}
		for _, u := range p.Uploads {
			if seen[u.UploadID] {
				t.Fatalf("upload %s returned twice", u.UploadID)
			}
			seen[u.UploadID] = true
		}
		if !p.IsTruncated {
			break
		}
		keyMarker, idMarker = p.NextKeyMarker, p.NextUploadIDMarker
	}
	if len(seen) != 4 {
		t.Fatalf("paged over %d uploads, want 4", len(seen))
	}
}

func TestMultipart_ContentSHA256Mismatch(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	uploadID := initiateUpload(t, g, "bucket", "obj")
	other := sha256.Sum256([]byte("a body we are not sending"))
	headers := map[string]string{"X-Amz-Content-Sha256": hex.EncodeToString(other[:])}

	url := fmt.Sprintf("/bucket/obj?partNumber=1&uploadId=%s", uploadID)
	w := serveRequest(g, http.MethodPut, url, bytes.NewReader([]byte("payload")), headers)
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "XAmzContentSHA256Mismatch" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	// A matching digest is accepted, and UNSIGNED-PAYLOAD is not checked at all.
	payload := []byte("payload")
	sum := sha256.Sum256(payload)
	w = serveRequest(g, http.MethodPut, url, bytes.NewReader(payload),
		map[string]string{"X-Amz-Content-Sha256": hex.EncodeToString(sum[:])})
	if w.Code != http.StatusOK {
		t.Fatalf("matching digest: status %d: %s", w.Code, w.Body.String())
	}
	w = serveRequest(g, http.MethodPut, url, bytes.NewReader(payload),
		map[string]string{"X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD"})
	if w.Code != http.StatusOK {
		t.Fatalf("unsigned payload: status %d: %s", w.Code, w.Body.String())
	}
}

func TestListObjects_SkipsScratchFiles(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(root, "b"), 0o755); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	// A write in flight (or a crashed one) leaves scratch files behind. They are
	// not objects and must never be advertised as keys — a client would otherwise
	// see a key that vanishes the instant the write is renamed into place.
	for _, name := range []string{".seb-tmp-inflight", ".seb-bak-rollback"} {
		if err := os.WriteFile(filepath.Join(root, "b", name), []byte("partial"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "b", "real.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write object: %v", err)
	}

	for _, url := range []string{"/b?list-type=2", "/b"} {
		w := serveRequest(g, http.MethodGet, url, nil, noAuth())
		if w.Code != http.StatusOK {
			t.Fatalf("list %s: status %d", url, w.Code)
		}
		if strings.Contains(w.Body.String(), ".seb-tmp-") || strings.Contains(w.Body.String(), ".seb-bak-") {
			t.Fatalf("scratch file listed as an object by %s: %s", url, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "real.txt") {
			t.Fatalf("real object missing from %s listing", url)
		}
	}
}

func TestMultipart_PartNumberWithoutUploadIDIsRejected(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{}, multipart.Limits{})

	original := []byte("the object as it should stay")
	if w := serveRequest(g, http.MethodPut, "/bucket/obj", bytes.NewReader(original), noAuth()); w.Code != http.StatusOK {
		t.Fatalf("seed object: status %d", w.Code)
	}

	// Without this guard the request would fall through to PutObject and replace
	// the whole object with one part's bytes.
	w := serveRequest(g, http.MethodPut, "/bucket/obj?partNumber=1", bytes.NewReader([]byte("just a part")), noAuth())
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "InvalidRequest" {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	got := serveRequest(g, http.MethodGet, "/bucket/obj", nil, noAuth())
	if !bytes.Equal(got.Body.Bytes(), original) {
		t.Fatalf("object was overwritten: %q", got.Body.String())
	}
}

func TestMultipart_LeavesNoScratchFilesInBucket(t *testing.T) {
	g, root, _ := multipartGateway(t, Config{}, multipart.Limits{MinPartBytes: 16})

	// A completion that fails validation must not leave a partial assembly behind.
	bad := initiateUpload(t, g, "bucket", "nested/dir/failed.bin")
	e1 := uploadPart(t, g, "bucket", "nested/dir/failed.bin", bad, 1, bytes.Repeat([]byte("a"), 4))
	e2 := uploadPart(t, g, "bucket", "nested/dir/failed.bin", bad, 2, bytes.Repeat([]byte("b"), 4))
	if w := completeUpload(g, "bucket", "nested/dir/failed.bin", bad,
		[]CompletePartEntry{{PartNumber: 1, ETag: e1}, {PartNumber: 2, ETag: e2}}); w.Code == http.StatusOK {
		t.Fatal("undersized part should have failed the completion")
	}

	// And neither must a successful one, including into a directory that did not
	// exist before.
	ok := initiateUpload(t, g, "bucket", "nested/dir/done.bin")
	payloads := [][]byte{bytes.Repeat([]byte("a"), 32), bytes.Repeat([]byte("b"), 8)}
	var parts []CompletePartEntry
	for i, p := range payloads {
		parts = append(parts, CompletePartEntry{
			PartNumber: i + 1,
			ETag:       uploadPart(t, g, "bucket", "nested/dir/done.bin", ok, i+1, p),
		})
	}
	if w := completeUpload(g, "bucket", "nested/dir/done.bin", ok, parts); w.Code != http.StatusOK {
		t.Fatalf("complete: status %d: %s", w.Code, w.Body.String())
	}

	var leftovers []string
	filepath.WalkDir(filepath.Join(root, "bucket"), func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && gateway.IsScratchFile(d.Name()) {
			leftovers = append(leftovers, path)
		}
		return nil
	})
	if len(leftovers) != 0 {
		t.Fatalf("scratch files left in the bucket: %v", leftovers)
	}

	got := serveRequest(g, http.MethodGet, "/bucket/nested/dir/done.bin", nil, noAuth())
	if !bytes.Equal(got.Body.Bytes(), bytes.Join(payloads, nil)) {
		t.Fatal("assembled object has wrong content")
	}
}

func TestMultipart_CompleteLocation(t *testing.T) {
	g, _, _ := multipartGateway(t, Config{Domain: "s3.example.com"}, multipart.Limits{})

	complete := func(t *testing.T, headers map[string]string, urlPrefix string) string {
		t.Helper()
		w := serveRequest(g, http.MethodPost, urlPrefix+"?uploads", nil, headers)
		var init InitiateMultipartUploadResult
		if err := xml.Unmarshal(w.Body.Bytes(), &init); err != nil {
			t.Fatalf("parse initiate: %v", err)
		}
		partURL := fmt.Sprintf("%s?partNumber=1&uploadId=%s", urlPrefix, init.UploadID)
		pw := serveRequest(g, http.MethodPut, partURL, bytes.NewReader([]byte("data")), headers)
		etag := pw.Header().Get("ETag")

		body := completeBody([]CompletePartEntry{{PartNumber: 1, ETag: etag}})
		cw := serveRequest(g, http.MethodPost, fmt.Sprintf("%s?uploadId=%s", urlPrefix, init.UploadID),
			strings.NewReader(body), headers)
		if cw.Code != http.StatusOK {
			t.Fatalf("complete: status %d: %s", cw.Code, cw.Body.String())
		}
		var res CompleteMultipartUploadResult
		if err := xml.Unmarshal(cw.Body.Bytes(), &res); err != nil {
			t.Fatalf("parse complete: %v", err)
		}
		return res.Location
	}

	// Path-style keeps the bucket in the path.
	loc := complete(t, map[string]string{"Host": "s3.example.com"}, "/bucket/a%20b.bin")
	if want := "http://s3.example.com/bucket/a%20b.bin"; loc != want {
		t.Fatalf("path-style location = %q, want %q", loc, want)
	}

	// Virtual-hosted requests already carry the bucket in the host.
	loc = complete(t, map[string]string{"Host": "bucket.s3.example.com"}, "/vh.bin")
	if want := "http://bucket.s3.example.com/vh.bin"; loc != want {
		t.Fatalf("virtual-hosted location = %q, want %q", loc, want)
	}

	// A TLS-terminating proxy is reflected in the scheme.
	loc = complete(t, map[string]string{"Host": "s3.example.com", "X-Forwarded-Proto": "https"}, "/bucket/tls.bin")
	if want := "https://s3.example.com/bucket/tls.bin"; loc != want {
		t.Fatalf("forwarded-proto location = %q, want %q", loc, want)
	}
}
