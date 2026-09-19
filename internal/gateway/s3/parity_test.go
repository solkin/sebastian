package s3

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"github.com/solkin/sebastian/internal/gateway"
	"github.com/solkin/sebastian/internal/multipart"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParity_CrossBucketSymlinkRead(t *testing.T) {
	g, root := testGateway(t, Config{})
	for _, bucket := range []string{"first", "second"} {
		if err := os.Mkdir(filepath.Join(root, bucket), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "second", "secret"), []byte("other bucket data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "second", "secret"), filepath.Join(root, "first", "alias")); err != nil {
		t.Fatal(err)
	}
	w := serveRequest(g, http.MethodGet, "/first/alias", nil, nil)
	if w.Code == 200 {
		t.Fatalf("cross-bucket alias read succeeded: %s", w.Body.String())
	}
}
func TestParity_DeleteBucketUnavailableStaging(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0755); err != nil {
		t.Fatal(err)
	}
	store, err := multipart.New(root, multipart.Limits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	g.multipart = store
	if _, err := store.Create("bucket", "object"); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, gateway.ReservedDirName, "multipart")
	if err := os.Rename(staging, staging+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	w := serveRequest(g, http.MethodDelete, "/bucket", nil, nil)
	if w.Code != 500 {
		t.Fatalf("delete with unavailable staging: HTTP %d (want 500)", w.Code)
	}
}
func TestParity_PutObject_ContentMD5(t *testing.T) {
	g, syncDir := testGateway(t, Config{})
	bp := filepath.Join(syncDir, "mybucket")
	if err := os.Mkdir(bp, 0o755); err != nil {
		t.Fatal(err)
	}

	body := []byte("verified payload")
	sum := md5.Sum(body)
	w := serveRequest(g, http.MethodPut, "/mybucket/good.txt", bytes.NewReader(body),
		map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(sum[:])})
	if w.Code != http.StatusOK {
		t.Fatalf("matching Content-MD5: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	original := []byte("keep this object")
	objectPath := filepath.Join(bp, "existing.txt")
	if err := os.WriteFile(objectPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	wrong := md5.Sum([]byte("different payload"))
	w = serveRequest(g, http.MethodPut, "/mybucket/existing.txt", bytes.NewReader(body),
		map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(wrong[:])})
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "BadDigest" {
		t.Fatalf("mismatched Content-MD5: status %d, body %s", w.Code, w.Body.String())
	}
	got, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("mismatched digest overwrote existing object: %q", got)
	}

	w = serveRequest(g, http.MethodPut, "/mybucket/malformed.txt", bytes.NewReader(body),
		map[string]string{"Content-MD5": "not-base64"})
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "BadDigest" {
		t.Fatalf("malformed Content-MD5: status %d, body %s", w.Code, w.Body.String())
	}
}
func TestParity_ListObjects_SafeSymlinkMatchesHeadAndEscapeIsHidden(t *testing.T) {
	g, syncDir := testGateway(t, Config{})
	bp := filepath.Join(syncDir, "mybucket")
	if err := os.Mkdir(bp, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(bp, "target.txt")
	if err := os.WriteFile(target, []byte("target contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(bp, "alias.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(bp, "escape.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	otherBucket := filepath.Join(syncDir, "otherbucket")
	if err := os.Mkdir(otherBucket, 0o755); err != nil {
		t.Fatal(err)
	}
	otherObject := filepath.Join(otherBucket, "other.txt")
	if err := os.WriteFile(otherObject, []byte("other bucket"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(otherObject, filepath.Join(bp, "cross-bucket.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	w := serveRequest(g, http.MethodGet, "/mybucket?list-type=2", nil, noAuth())
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result ListBucketResultV2
	if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	objects := make(map[string]ObjectInfo, len(result.Contents))
	for _, obj := range result.Contents {
		objects[obj.Key] = obj
	}
	alias, ok := objects["alias.txt"]
	if !ok {
		t.Fatal("safe in-root symlink missing from listing")
	}
	if _, ok := objects["escape.txt"]; ok {
		t.Fatal("symlink escaping syncDir must not appear in listing")
	}
	if _, ok := objects["cross-bucket.txt"]; ok {
		t.Fatal("symlink escaping its bucket must not appear in listing")
	}

	head := serveRequest(g, http.MethodHead, "/mybucket/alias.txt", nil, noAuth())
	if head.Code != http.StatusOK {
		t.Fatalf("head alias: expected 200, got %d", head.Code)
	}
	if alias.ETag != head.Header().Get("ETag") {
		t.Fatalf("alias ETag mismatch: LIST=%q HEAD=%q", alias.ETag, head.Header().Get("ETag"))
	}
	if alias.Size != int64(len("target contents")) {
		t.Fatalf("alias size = %d, want target size %d", alias.Size, len("target contents"))
	}
	if cross := serveRequest(g, http.MethodGet, "/mybucket/cross-bucket.txt", nil, noAuth()); cross.Code == http.StatusOK {
		t.Fatalf("cross-bucket symlink was readable: %q", cross.Body.String())
	}
}

func TestMultipart_RootPaths(t *testing.T) {
	for _, kind := range []string{"absolute", "relative", "relative-symlink"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			root := "files"
			if err := os.MkdirAll(filepath.Join(root, "bucket"), 0755); err != nil {
				t.Fatal(err)
			}
			if kind == "absolute" {
				var err error
				root, err = filepath.Abs(root)
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind == "relative-symlink" {
				if err := os.Symlink("files", "alias"); err != nil {
					t.Fatal(err)
				}
				root = "alias"
			}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			store, err := multipart.New(root, multipart.Limits{}, logger)
			if err != nil {
				t.Fatal(err)
			}
			g := New(root, Config{Multipart: store}, logger)
			id := initiateUpload(t, g, "bucket", "object")
			etag := uploadPart(t, g, "bucket", "object", id, 1, []byte("payload"))
			w := completeUpload(g, "bucket", "object", id, []CompletePartEntry{{PartNumber: 1, ETag: etag}})
			if w.Code != http.StatusOK {
				t.Fatalf("complete: %d: %s", w.Code, w.Body.String())
			}
			got, err := os.ReadFile(filepath.Join(root, "bucket", "object"))
			if err != nil || string(got) != "payload" {
				t.Fatalf("published object: %q %v", got, err)
			}
			if strings.Contains(w.Body.String(), root+"/bucket") {
				t.Fatal("response leaked filesystem root")
			}
		})
	}
}
