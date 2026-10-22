package s3

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFolderMarker_CreatesFolder puts a folder marker the way the AWS console's
// "Create folder", Cyberduck and rclone do, then uses the folder. The marker
// used to become a zero-byte file named like the folder, after which every
// object put into the folder failed.
func TestFolderMarker_CreatesFolder(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := serveRequest(g, http.MethodPut, "/bucket/apps/2026/", nil, nil)
	if w.Code != http.StatusOK || w.Header().Get("ETag") != emptyETag {
		t.Fatalf("put marker: %d %s etag %s", w.Code, w.Body.String(), w.Header().Get("ETag"))
	}
	if info, err := os.Stat(filepath.Join(root, "bucket", "apps", "2026")); err != nil || !info.IsDir() {
		t.Fatalf("marker did not make a folder: %v", err)
	}
	// Rewriting the marker is harmless.
	if w := serveRequest(g, http.MethodPut, "/bucket/apps/2026/", strings.NewReader(""), nil); w.Code != http.StatusOK {
		t.Fatalf("repeat marker: %d %s", w.Code, w.Body.String())
	}
	if w := serveRequest(g, http.MethodPut, "/bucket/apps/2026/app.apk", strings.NewReader("apk"), nil); w.Code != http.StatusOK {
		t.Fatalf("put into folder: %d %s", w.Code, w.Body.String())
	}
	// A marker over a folder that has objects is just as harmless.
	if w := serveRequest(g, http.MethodPut, "/bucket/apps/", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("marker over populated folder: %d %s", w.Code, w.Body.String())
	}
	if readObject(t, root, "bucket/apps/2026/app.apk") != "apk" {
		t.Fatal("object lost")
	}
}

// TestFolderMarker_StreamingEmptyBody accepts the aws-chunked empty body that
// current SDKs send for a folder marker.
func TestFolderMarker_StreamingEmptyBody(t *testing.T) {
	f := newStreamingFixture(t, Config{AccessKey: streamAccess, SecretKey: streamSecret})
	req, body := streamingPut("/bucket/folder/", nil, streamOptions{mode: streamingUnsignedPayloadTrailer, trailer: "x-amz-checksum-crc32"})
	if w := serveBody(f.g, req, body); w.Code != http.StatusOK {
		t.Fatalf("streaming marker: %d %s", w.Code, w.Body.String())
	}
	req, body = streamingPut("/bucket/full/", []byte("data"), streamOptions{mode: streamingSignedPayload})
	if w := serveBody(f.g, req, body); w.Code != http.StatusBadRequest || errorCode(t, w) != "InvalidRequest" {
		t.Fatalf("streaming marker with data: %d %s", w.Code, w.Body.String())
	}
}

// TestFolderMarker_Refusals refuses what a folder cannot be.
func TestFolderMarker_Refusals(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bucket", "report"), []byte("object"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		code                     string
	}{
		{"data", http.MethodPut, "/bucket/folder/", "data", http.StatusBadRequest, "InvalidRequest"},
		{"object of that name", http.MethodPut, "/bucket/report/", "", http.StatusConflict, "ParentIsObject"},
		{"below an object", http.MethodPut, "/bucket/report/sub/", "", http.StatusConflict, "ParentIsObject"},
		{"missing bucket", http.MethodPut, "/nobucket/folder/", "", http.StatusNotFound, "NoSuchBucket"},
		{"multipart", http.MethodPost, "/bucket/folder/?uploads", "", http.StatusBadRequest, "InvalidRequest"},
		{"bucket itself", http.MethodPut, "/bucket/./", "", http.StatusBadRequest, "InvalidArgument"},
	} {
		w := serveRequest(g, tc.method, tc.path, strings.NewReader(tc.body), nil)
		if w.Code != tc.status || errorCode(t, w) != tc.code {
			t.Fatalf("%s: %d %s, want %d %s", tc.name, w.Code, w.Body.String(), tc.status, tc.code)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "bucket", "folder")); !os.IsNotExist(err) {
		t.Fatalf("refused marker made a folder: %v", err)
	}
	if readObject(t, root, "bucket/report") != "object" {
		t.Fatal("object changed")
	}
}

// TestFolderMarker_HeadGet reads a marker as the empty object it stands for.
func TestFolderMarker_HeadGet(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.MkdirAll(filepath.Join(root, "bucket", "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		w := serveRequest(g, method, "/bucket/folder/", nil, nil)
		if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "0" || w.Header().Get("ETag") != emptyETag {
			t.Fatalf("%s existing folder: %d %q %v", method, w.Code, w.Body.String(), w.Header())
		}
		for path, code := range map[string]string{"/bucket/missing/": "NoSuchKey", "/nobucket/folder/": "NoSuchBucket"} {
			w := serveRequest(g, method, path, nil, nil)
			if w.Code != http.StatusNotFound || (method == http.MethodGet && errorCode(t, w) != code) {
				t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
			}
		}
	}
}

// TestFolderMarker_Delete removes an empty folder and never what is in one.
func TestFolderMarker_Delete(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.MkdirAll(filepath.Join(root, "bucket", "full", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bucket", "full", "sub", "keep.apk"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "bucket", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/bucket/full/", "/bucket/full/sub/", "/bucket/empty/", "/bucket/missing/"} {
		if w := serveRequest(g, http.MethodDelete, path, nil, nil); w.Code != http.StatusNoContent {
			t.Fatalf("delete %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	if readObject(t, root, "bucket/full/sub/keep.apk") != "keep" {
		t.Fatal("deleting a marker deleted an object")
	}
	if _, err := os.Stat(filepath.Join(root, "bucket", "empty")); !os.IsNotExist(err) {
		t.Fatalf("empty folder kept: %v", err)
	}
	if w := serveRequest(g, http.MethodDelete, "/nobucket/folder/", nil, nil); w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchBucket" {
		t.Fatalf("delete in missing bucket: %d %s", w.Code, w.Body.String())
	}
}

// TestFolderMarker_ListUnchanged keeps listings made of objects only: a marker
// adds no entry, with or without a delimiter.
func TestFolderMarker_ListUnchanged(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	if w := serveRequest(g, http.MethodPut, "/bucket/apps/a.apk", strings.NewReader("a"), nil); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	urls := []string{"/bucket", "/bucket?list-type=2", "/bucket?list-type=2&delimiter=/", "/bucket?list-type=2&prefix=apps/&delimiter=/"}
	before := make([]string, len(urls))
	for i, url := range urls {
		before[i] = serveRequest(g, http.MethodGet, url, nil, nil).Body.String()
	}
	for _, marker := range []string{"/bucket/apps/", "/bucket/apps/empty/", "/bucket/other/"} {
		if w := serveRequest(g, http.MethodPut, marker, nil, nil); w.Code != http.StatusOK {
			t.Fatalf("marker %s: %d", marker, w.Code)
		}
	}
	for i, url := range urls {
		if after := serveRequest(g, http.MethodGet, url, nil, nil).Body.String(); after != before[i] {
			t.Fatalf("%s changed:\n%s\n---\n%s", url, before[i], after)
		}
	}
}
