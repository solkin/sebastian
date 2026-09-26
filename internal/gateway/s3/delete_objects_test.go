package s3

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deleteObjectsBody builds a DeleteObjects request naming keys.
func deleteObjectsBody(quiet bool, keys ...string) string {
	var b strings.Builder
	b.WriteString(`<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	if quiet {
		b.WriteString(`<Quiet>true</Quiet>`)
	}
	for _, key := range keys {
		b.WriteString("<Object><Key>")
		xml.EscapeText(&b, []byte(key))
		b.WriteString("</Key></Object>")
	}
	b.WriteString(`</Delete>`)
	return b.String()
}

// deleteResult is a DeleteObjects response as an S3 client reads it, spelled
// out here rather than taken from the server's own types, so that the element
// names and namespace clients depend on are what the tests check.
type deleteResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
	Deleted []struct {
		Key string `xml:"Key"`
	} `xml:"Deleted"`
	Errors []struct {
		Key     string `xml:"Key"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// deleteObjects posts a DeleteObjects request and decodes a successful result.
func deleteObjects(t *testing.T, g *Gateway, path, body string, headers map[string]string) (*http.Response, deleteResult) {
	t.Helper()
	w := serveRequest(g, http.MethodPost, path, strings.NewReader(body), headers)
	var result deleteResult
	if w.Code == http.StatusOK {
		if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode result: %v\n%s", err, w.Body.String())
		}
	}
	return w.Result(), result
}

// bucketWithFiles makes a bucket holding the named files.
func bucketWithFiles(t *testing.T, root, bucket string, names ...string) string {
	t.Helper()
	bp := filepath.Join(root, bucket)
	for _, name := range names {
		path := filepath.Join(bp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(bp, 0o755); err != nil {
		t.Fatal(err)
	}
	return bp
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func keysOf(result deleteResult) []string {
	keys := make([]string, 0, len(result.Deleted))
	for _, d := range result.Deleted {
		keys = append(keys, d.Key)
	}
	return keys
}

// Every key is deleted as DeleteObject would delete it: a missing one counts as
// deleted, and emptied directories stay.
func TestDeleteObjects(t *testing.T) {
	g, root := testGateway(t, Config{})
	bp := bucketWithFiles(t, root, "mybucket", "a.txt", "dir/b.txt", "dir/c.txt")

	resp, result := deleteObjects(t, g, "/mybucket?delete",
		deleteObjectsBody(false, "a.txt", "dir/b.txt", "missing.txt"), noAuth())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := strings.Join(keysOf(result), ","); got != "a.txt,dir/b.txt,missing.txt" || len(result.Errors) != 0 {
		t.Fatalf("deleted %s, errors %+v", got, result.Errors)
	}
	if exists(filepath.Join(bp, "a.txt")) || exists(filepath.Join(bp, "dir", "b.txt")) {
		t.Fatal("named objects should have been deleted")
	}
	if !exists(filepath.Join(bp, "dir", "c.txt")) {
		t.Fatal("an object not named should stay")
	}
}

// A quiet request is answered with its failures alone.
func TestDeleteObjects_Quiet(t *testing.T) {
	g, root := testGateway(t, Config{})
	bp := bucketWithFiles(t, root, "mybucket", "a.txt")

	resp, result := deleteObjects(t, g, "/mybucket?delete", deleteObjectsBody(true, "a.txt", "../outside.txt"), noAuth())
	if resp.StatusCode != http.StatusOK || len(result.Deleted) != 0 || len(result.Errors) != 1 {
		t.Fatalf("quiet result: %d %+v", resp.StatusCode, result)
	}
	if exists(filepath.Join(bp, "a.txt")) {
		t.Fatal("a.txt should have been deleted")
	}
}

// A key no single request could address is reported on its own, and the others
// are still deleted.
func TestDeleteObjects_ReportsKeysItCannotDelete(t *testing.T) {
	g, root := testGateway(t, Config{})
	bp := bucketWithFiles(t, root, "mybucket", "ok.txt")
	bucketWithFiles(t, root, "other", "secret.txt")

	bad := []string{"../other/secret.txt", ".seb-tmp-x", "nested/.seb-bak-y/z", ""}
	resp, result := deleteObjects(t, g, "/mybucket?delete", deleteObjectsBody(false, append(bad, "ok.txt")...), noAuth())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if len(result.Errors) != len(bad) {
		t.Fatalf("errors %+v, want one for each of %q", result.Errors, bad)
	}
	for i, e := range result.Errors {
		if e.Key != bad[i] || e.Code != "InvalidArgument" {
			t.Fatalf("error %d = %+v", i, e)
		}
	}
	if got := keysOf(result); len(got) != 1 || got[0] != "ok.txt" || exists(filepath.Join(bp, "ok.txt")) {
		t.Fatalf("deleted %v", got)
	}
	if !exists(filepath.Join(root, "other", "secret.txt")) {
		t.Fatal("an object of another bucket was deleted")
	}
}

// A key longer than S3 allows is refused on its own, before any work is spent
// resolving it.
func TestDeleteObjects_KeyTooLong(t *testing.T) {
	g, root := testGateway(t, Config{})
	bp := bucketWithFiles(t, root, "mybucket", "a.txt")
	long := strings.Repeat("a/", maxKeyLength/2) + "b"

	resp, result := deleteObjects(t, g, "/mybucket?delete", deleteObjectsBody(false, long, "a.txt"), noAuth())
	if resp.StatusCode != http.StatusOK || len(result.Errors) != 1 || result.Errors[0].Code != "KeyTooLongError" {
		t.Fatalf("result: %d %+v", resp.StatusCode, result.Errors)
	}
	if got := keysOf(result); len(got) != 1 || got[0] != "a.txt" || exists(filepath.Join(bp, "a.txt")) {
		t.Fatalf("deleted %v", got)
	}
}

// An object that cannot be looked at may still be there, so it is reported as
// not deleted rather than as gone.
func TestDeleteObjects_ReportsWhatCannotBeLookedAt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not bind root")
	}
	g, root := testGateway(t, Config{})
	bp := bucketWithFiles(t, root, "mybucket", "locked/a.txt")
	locked := filepath.Join(bp, "locked")
	if err := os.Chmod(locked, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	resp, result := deleteObjects(t, g, "/mybucket?delete", deleteObjectsBody(false, "locked/a.txt"), noAuth())
	if resp.StatusCode != http.StatusOK || len(result.Deleted) != 0 || len(result.Errors) != 1 || result.Errors[0].Code != "InternalError" {
		t.Fatalf("result: %d %+v", resp.StatusCode, result)
	}
	os.Chmod(locked, 0o755)
	if !exists(filepath.Join(locked, "a.txt")) {
		t.Fatal("the object should still be there")
	}
}

// A key naming a directory is no object: nothing is removed, as with
// DeleteObject.
func TestDeleteObjects_DirectoryIsNotAnObject(t *testing.T) {
	g, root := testGateway(t, Config{})
	bp := bucketWithFiles(t, root, "mybucket", "dir/keep.txt")

	resp, result := deleteObjects(t, g, "/mybucket?delete", deleteObjectsBody(false, "dir"), noAuth())
	if resp.StatusCode != http.StatusOK || len(result.Errors) != 0 {
		t.Fatalf("result: %d %+v", resp.StatusCode, result)
	}
	if !exists(filepath.Join(bp, "dir", "keep.txt")) {
		t.Fatal("the directory's contents should stay")
	}
}

func TestDeleteObjects_NoBucket(t *testing.T) {
	g, _ := testGateway(t, Config{})

	w := serveRequest(g, http.MethodPost, "/missing?delete", strings.NewReader(deleteObjectsBody(false, "a.txt")), noAuth())
	if w.Code != http.StatusNotFound || errorCode(t, w) != "NoSuchBucket" {
		t.Fatalf("expected NoSuchBucket, got %d %s", w.Code, w.Body.String())
	}
}

func TestDeleteObjects_MalformedRequests(t *testing.T) {
	g, root := testGateway(t, Config{})
	bp := bucketWithFiles(t, root, "mybucket", "a.txt")

	tooMany := make([]string, maxDeleteObjectsKeys+1)
	for i := range tooMany {
		tooMany[i] = "a.txt"
	}
	for name, body := range map[string]string{
		"not XML":       "not xml",
		"wrong element": `<Remove><Object><Key>a.txt</Key></Object></Remove>`,
		"no objects":    deleteObjectsBody(false),
		"too many keys": deleteObjectsBody(false, tooMany...),
		"too large":     deleteObjectsBody(false, strings.Repeat("k", maxDeleteObjectsBody)),
	} {
		w := serveRequest(g, http.MethodPost, "/mybucket?delete", strings.NewReader(body), noAuth())
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "MalformedXML" {
			t.Fatalf("%s: expected MalformedXML, got %d %s", name, w.Code, w.Body.String())
		}
	}
	if !exists(filepath.Join(bp, "a.txt")) {
		t.Fatal("a malformed request deleted an object")
	}
}

// The body is held to its declared digests, so that a captured signed request
// cannot be replayed naming other keys.
func TestDeleteObjects_Digests(t *testing.T) {
	g, root := testGateway(t, Config{})
	bp := bucketWithFiles(t, root, "mybucket", "a.txt", "b.txt", "c.txt")
	body := deleteObjectsBody(false, "a.txt")
	other := deleteObjectsBody(false, "b.txt")
	md5Of := func(s string) string { sum := md5.Sum([]byte(s)); return base64.StdEncoding.EncodeToString(sum[:]) }
	sha256Of := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

	for _, tc := range []struct {
		name, body, header, value, code string
	}{
		{"Content-MD5 of other keys", other, "Content-MD5", md5Of(body), "BadDigest"},
		{"Content-MD5 not base64", other, "Content-MD5", "not-base64!", "BadDigest"},
		{"payload hash of other keys", other, "X-Amz-Content-Sha256", sha256Of(body), "XAmzContentSHA256Mismatch"},
	} {
		w := serveRequest(g, http.MethodPost, "/mybucket?delete", strings.NewReader(tc.body), map[string]string{tc.header: tc.value})
		if w.Code != http.StatusBadRequest || errorCode(t, w) != tc.code {
			t.Fatalf("%s: expected %s, got %d %s", tc.name, tc.code, w.Code, w.Body.String())
		}
	}
	if !exists(filepath.Join(bp, "b.txt")) {
		t.Fatal("a request failing its digest deleted an object")
	}

	for _, tc := range []struct{ key, header, value string }{
		{"a.txt", "Content-MD5", md5Of(deleteObjectsBody(false, "a.txt"))},
		{"b.txt", "X-Amz-Content-Sha256", sha256Of(deleteObjectsBody(false, "b.txt"))},
		{"c.txt", "X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD"},
	} {
		resp, result := deleteObjects(t, g, "/mybucket?delete", deleteObjectsBody(false, tc.key), map[string]string{tc.header: tc.value})
		if resp.StatusCode != http.StatusOK || len(result.Deleted) != 1 || exists(filepath.Join(bp, tc.key)) {
			t.Fatalf("%s with %s: %d %+v", tc.key, tc.header, resp.StatusCode, result)
		}
	}
}

// Without valid credentials nothing is deleted.
func TestDeleteObjects_RequiresAuth(t *testing.T) {
	g, root := testGateway(t, Config{AccessKey: "key", SecretKey: "secret"})
	bp := bucketWithFiles(t, root, "mybucket", "a.txt")

	w := serveRequest(g, http.MethodPost, "/mybucket?delete", strings.NewReader(deleteObjectsBody(false, "a.txt")), sigV4Headers("key"))
	if w.Code != http.StatusForbidden || !exists(filepath.Join(bp, "a.txt")) {
		t.Fatalf("expected 403 and the object kept, got %d", w.Code)
	}
}

// A virtual-hosted request names its bucket in the host, as every other bucket
// operation does.
func TestDeleteObjects_VirtualHostedStyle(t *testing.T) {
	g, root := testGateway(t, Config{Domain: "files.example"})
	bp := bucketWithFiles(t, root, "mybucket", "a.txt")

	resp, result := deleteObjects(t, g, "/?delete", deleteObjectsBody(false, "a.txt"), map[string]string{"Host": "mybucket.files.example"})
	if resp.StatusCode != http.StatusOK || len(result.Deleted) != 1 || exists(filepath.Join(bp, "a.txt")) {
		t.Fatalf("hosted result: %d %+v", resp.StatusCode, result)
	}
}
