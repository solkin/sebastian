package s3

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// copyRequest sends a CopyObject of source to the object at path.
func copyRequest(g *Gateway, path, source string, headers map[string]string) *httptest.ResponseRecorder {
	all := map[string]string{"X-Amz-Copy-Source": source}
	for k, v := range headers {
		all[k] = v
	}
	return serveRequest(g, http.MethodPut, path, nil, all)
}

// copyGateway is a gateway with two buckets, "bucket" holding src.txt and
// dst.txt, and an empty "other".
func copyGateway(t *testing.T, cfg Config) (*Gateway, string) {
	t.Helper()
	g, root := testGateway(t, cfg)
	for _, dir := range []string{"bucket", "other"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{"src.txt": "source bytes", "dst.txt": "destination bytes"} {
		if err := os.WriteFile(filepath.Join(root, "bucket", name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return g, root
}

func readObject(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// TestCopyObject_CopiesBytes is the AWS CLI's `s3 cp`/`s3 mv` between keys:
// the destination gets the source's bytes, and the result reports the ETag a
// HEAD of the destination returns. Without CopyObject support the request was a
// PutObject with an empty body and truncated the destination to zero bytes.
func TestCopyObject_CopiesBytes(t *testing.T) {
	for _, tc := range []struct{ name, path, source string }{
		{"overwrite in bucket", "/bucket/dst.txt", "bucket/src.txt"},
		{"new key, leading slash", "/bucket/new/deep/key.txt", "/bucket/src.txt"},
		{"across buckets", "/other/copy.txt", "/bucket/src.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, root := copyGateway(t, Config{})
			w := copyRequest(g, tc.path, tc.source, map[string]string{"X-Amz-Metadata-Directive": "REPLACE"})
			if w.Code != http.StatusOK {
				t.Fatalf("copy: %d %s", w.Code, w.Body.String())
			}
			var result CopyObjectResult
			if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("copy result: %v: %s", err, w.Body.String())
			}
			if got := readObject(t, root, tc.path); got != "source bytes" {
				t.Fatalf("destination holds %q", got)
			}
			if got := readObject(t, root, "bucket/src.txt"); got != "source bytes" {
				t.Fatalf("source changed to %q", got)
			}
			head := serveRequest(g, http.MethodHead, tc.path, nil, nil)
			if head.Code != http.StatusOK || result.ETag != head.Header().Get("ETag") {
				t.Fatalf("copy ETag %s, HEAD %d ETag %s", result.ETag, head.Code, head.Header().Get("ETag"))
			}
			if _, err := time.Parse(s3TimeFormat, result.LastModified); err != nil {
				t.Fatalf("LastModified %q: %v", result.LastModified, err)
			}
		})
	}
}

// TestCopyObject_EncodedSource decodes the source key as SDKs encode it.
func TestCopyObject_EncodedSource(t *testing.T) {
	g, root := copyGateway(t, Config{})
	if w := serveRequest(g, http.MethodPut, "/bucket/a%20b+c%3F.txt", strings.NewReader("odd name"), nil); w.Code != http.StatusOK {
		t.Fatalf("put: %d", w.Code)
	}
	if w := copyRequest(g, "/bucket/plain.txt", "bucket/a%20b%2Bc%3F.txt", nil); w.Code != http.StatusOK {
		t.Fatalf("copy: %d %s", w.Code, w.Body.String())
	}
	if got := readObject(t, root, "bucket/plain.txt"); got != "odd name" {
		t.Fatalf("copied %q", got)
	}
}

// TestCopyObject_OntoItselfKeepsObject copies an object onto itself, which is
// how clients replace metadata (aws s3 cp --metadata-directive REPLACE). There
// is no metadata to replace, so the object must stay exactly as it was.
func TestCopyObject_OntoItselfKeepsObject(t *testing.T) {
	g, root := copyGateway(t, Config{})
	path := filepath.Join(root, "bucket", "src.txt")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{"", "COPY", "REPLACE"} {
		w := copyRequest(g, "/bucket/src.txt", "bucket/src.txt", map[string]string{"X-Amz-Metadata-Directive": directive})
		if w.Code != http.StatusOK {
			t.Fatalf("%q: %d %s", directive, w.Code, w.Body.String())
		}
		var result CopyObjectResult
		if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil || result.ETag != etagFor(before) {
			t.Fatalf("%q: result %+v (%v), want ETag %s", directive, result, err, etagFor(before))
		}
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) || readObject(t, root, "bucket/src.txt") != "source bytes" {
		t.Fatalf("self-copy rewrote the object: %v", err)
	}
}

// TestCopyObject_RefusalsLeaveDestination checks every refused copy leaves the
// destination as it was.
func TestCopyObject_RefusalsLeaveDestination(t *testing.T) {
	g, root := copyGateway(t, Config{MaxUploadBytes: 5})
	src, err := os.Stat(filepath.Join(root, "bucket", "src.txt"))
	if err != nil {
		t.Fatal(err)
	}
	stamp := src.ModTime().UTC().Format(http.TimeFormat)
	past := src.ModTime().Add(-time.Hour).UTC().Format(http.TimeFormat)
	future := src.ModTime().Add(time.Hour).UTC().Format(http.TimeFormat)
	for _, tc := range []struct {
		name, source string
		headers      map[string]string
		body         string
		status       int
		code         string
	}{
		{"missing source", "bucket/missing.txt", nil, "", http.StatusNotFound, "NoSuchKey"},
		{"missing source bucket", "nobucket/src.txt", nil, "", http.StatusNotFound, "NoSuchBucket"},
		{"source below an object", "bucket/src.txt/below", nil, "", http.StatusNotFound, "NoSuchKey"},
		{"no key", "bucket", nil, "", http.StatusBadRequest, "InvalidArgument"},
		{"version", "bucket/src.txt?versionId=3", nil, "", http.StatusNotImplemented, "NotImplemented"},
		{"body", "bucket/src.txt", nil, "data", http.StatusBadRequest, "InvalidRequest"},
		{"scratch source", "bucket/.seb-tmp-x", nil, "", http.StatusBadRequest, "InvalidArgument"},
		{"directive", "bucket/src.txt", map[string]string{"X-Amz-Metadata-Directive": "MERGE"}, "", http.StatusBadRequest, "InvalidArgument"},
		{"if-match", "bucket/src.txt", map[string]string{"X-Amz-Copy-Source-If-Match": `"stale"`}, "", http.StatusPreconditionFailed, "PreconditionFailed"},
		{"if-none-match", "bucket/src.txt", map[string]string{"X-Amz-Copy-Source-If-None-Match": etagFor(src)}, "", http.StatusPreconditionFailed, "PreconditionFailed"},
		{"if-unmodified-since", "bucket/src.txt", map[string]string{"X-Amz-Copy-Source-If-Unmodified-Since": past}, "", http.StatusPreconditionFailed, "PreconditionFailed"},
		{"if-modified-since", "bucket/src.txt", map[string]string{"X-Amz-Copy-Source-If-Modified-Since": future}, "", http.StatusPreconditionFailed, "PreconditionFailed"},
		{"too large", "bucket/src.txt", map[string]string{"X-Amz-Copy-Source-If-Unmodified-Since": stamp}, "", http.StatusRequestEntityTooLarge, "EntityTooLarge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"X-Amz-Copy-Source": tc.source}
			for k, v := range tc.headers {
				headers[k] = v
			}
			w := serveRequest(g, http.MethodPut, "/bucket/dst.txt", strings.NewReader(tc.body), headers)
			if w.Code != tc.status || errorCode(t, w) != tc.code {
				t.Fatalf("status %d, body %s; want %d %s", w.Code, w.Body.String(), tc.status, tc.code)
			}
			if got := readObject(t, root, "bucket/dst.txt"); got != "destination bytes" {
				t.Fatalf("destination changed to %q", got)
			}
		})
	}
}

// TestCopyObject_PreconditionsThatHold copies when the source validators match.
func TestCopyObject_PreconditionsThatHold(t *testing.T) {
	g, root := copyGateway(t, Config{})
	src, err := os.Stat(filepath.Join(root, "bucket", "src.txt"))
	if err != nil {
		t.Fatal(err)
	}
	w := copyRequest(g, "/bucket/dst.txt", "bucket/src.txt", map[string]string{
		"X-Amz-Copy-Source-If-Match": etagFor(src),
		// If-Match holds, so If-Unmodified-Since is not consulted (RFC 9110).
		"X-Amz-Copy-Source-If-Unmodified-Since": src.ModTime().Add(-time.Hour).UTC().Format(http.TimeFormat),
		"X-Amz-Copy-Source-If-None-Match":       `"other"`,
	})
	if w.Code != http.StatusOK || readObject(t, root, "bucket/dst.txt") != "source bytes" {
		t.Fatalf("copy: %d %s", w.Code, w.Body.String())
	}
}

// TestCopyObject_DestinationConflicts refuses a destination the filesystem
// cannot hold as an object.
func TestCopyObject_DestinationConflicts(t *testing.T) {
	g, root := copyGateway(t, Config{})
	if err := os.MkdirAll(filepath.Join(root, "bucket", "folder", "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, code := range map[string]string{
		"/bucket/folder":           "ObjectExistsAsDirectory",
		"/bucket/dst.txt/below":    "ParentIsObject",
		"/bucket/dst.txt/":         "InvalidRequest", // an object cannot become a folder
		"/missing-bucket/copy.txt": "NoSuchBucket",
	} {
		w := copyRequest(g, path, "bucket/src.txt", nil)
		if errorCode(t, w) != code {
			t.Fatalf("%s: %d %s, want %s", path, w.Code, w.Body.String(), code)
		}
	}
	if readObject(t, root, "bucket/dst.txt") != "destination bytes" {
		t.Fatal("destination changed")
	}
}

// TestCopyObject_Folders copies a folder marker to another, which makes that
// folder, as the AWS console does when it moves a folder.
func TestCopyObject_Folders(t *testing.T) {
	g, root := copyGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(root, "bucket", "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := copyRequest(g, "/other/moved/", "bucket/dir/", nil)
	var result CopyObjectResult
	if w.Code != http.StatusOK || xml.Unmarshal(w.Body.Bytes(), &result) != nil || result.ETag != emptyETag {
		t.Fatalf("folder copy: %d %s", w.Code, w.Body.String())
	}
	if info, err := os.Stat(filepath.Join(root, "other", "moved")); err != nil || !info.IsDir() {
		t.Fatalf("folder not made: %v", err)
	}
	if w := copyRequest(g, "/other/x/", "bucket/missing/", nil); errorCode(t, w) != "NoSuchKey" {
		t.Fatalf("missing folder: %d %s", w.Code, w.Body.String())
	}
	if w := copyRequest(g, "/other/file", "bucket/dir/", nil); errorCode(t, w) != "InvalidRequest" {
		t.Fatalf("folder to object: %d %s", w.Code, w.Body.String())
	}
}
