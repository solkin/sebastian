package webdav

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestGateway creates a Gateway with a temporary rootDir and httptest server.
func newTestGateway(t *testing.T, username, password string) (*Gateway, *httptest.Server) {
	t.Helper()
	rootDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := New(rootDir, Config{
		ListenAddr: ":0",
		Username:   username,
		Password:   password,
	}, logger)
	ts := httptest.NewServer(g.server.Handler)
	t.Cleanup(ts.Close)
	return g, ts
}

// doReq is a helper to make a request and return the response.
func doReq(t *testing.T, method, url string, body string, headers map[string]string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, url, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// --- Tests ---

func TestOptions(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "OPTIONS", ts.URL+"/", "", nil)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if dav := resp.Header.Get("DAV"); !strings.Contains(dav, "1") {
		t.Fatalf("expected DAV header with class 1, got %q", dav)
	}
	allow := resp.Header.Get("Allow")
	for _, m := range []string{"PROPFIND", "GET", "PUT", "DELETE", "MKCOL", "MOVE", "COPY", "LOCK"} {
		if !strings.Contains(allow, m) {
			t.Errorf("Allow header missing %s: %q", m, allow)
		}
	}
}

func TestPropfind_Root(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "hello.txt"), []byte("hello"), 0o644)
	os.Mkdir(filepath.Join(g.rootDir, "subdir"), 0o755)

	resp := doReq(t, "PROPFIND", ts.URL+"/", "", map[string]string{"Depth": "1"})
	body := readBody(t, resp)

	if resp.StatusCode != 207 {
		t.Fatalf("expected 207, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "<D:multistatus") {
		t.Fatalf("expected multistatus XML, got %s", body)
	}
	if !strings.Contains(body, "hello.txt") {
		t.Errorf("expected hello.txt in listing, body: %s", body)
	}
	if !strings.Contains(body, "subdir") {
		t.Errorf("expected subdir in listing, body: %s", body)
	}
	if !strings.Contains(body, "<D:collection/>") {
		t.Errorf("expected collection in root, body: %s", body)
	}
}

func TestPropfind_Depth0(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "file.txt"), []byte("data"), 0o644)

	resp := doReq(t, "PROPFIND", ts.URL+"/", "", map[string]string{"Depth": "0"})
	body := readBody(t, resp)

	if resp.StatusCode != 207 {
		t.Fatalf("expected 207, got %d", resp.StatusCode)
	}
	if strings.Contains(body, "file.txt") {
		t.Errorf("depth 0 should not list children, body: %s", body)
	}
}

func TestPropfind_File(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "doc.txt"), []byte("content"), 0o644)

	resp := doReq(t, "PROPFIND", ts.URL+"/doc.txt", "", map[string]string{"Depth": "0"})
	body := readBody(t, resp)

	if resp.StatusCode != 207 {
		t.Fatalf("expected 207, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "doc.txt") {
		t.Errorf("expected doc.txt in response, body: %s", body)
	}
	if !strings.Contains(body, "<D:getcontentlength>7</D:getcontentlength>") {
		t.Errorf("expected content length 7, body: %s", body)
	}
	if strings.Contains(body, "<D:collection/>") {
		t.Errorf("file should not be a collection, body: %s", body)
	}
}

func TestPropfind_NotFound(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "PROPFIND", ts.URL+"/nonexistent", "", map[string]string{"Depth": "0"})
	resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetFile(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "test.txt"), []byte("hello world"), 0o644)

	resp := doReq(t, "GET", ts.URL+"/test.txt", "", nil)
	body := readBody(t, resp)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if body != "hello world" {
		t.Fatalf("expected 'hello world', got %q", body)
	}
}

func TestGetFile_NotFound(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "GET", ts.URL+"/nope.txt", "", nil)
	resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetFile_Directory(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.Mkdir(filepath.Join(g.rootDir, "dir"), 0o755)

	resp := doReq(t, "GET", ts.URL+"/dir", "", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestHead(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "info.txt"), []byte("12345"), 0o644)

	resp := doReq(t, "HEAD", ts.URL+"/info.txt", "", nil)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "5" {
		t.Fatalf("expected Content-Length 5, got %q", cl)
	}
}

func TestPut_NewFile(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	resp := doReq(t, "PUT", ts.URL+"/new.txt", "new content", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	data, err := os.ReadFile(filepath.Join(g.rootDir, "new.txt"))
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(data) != "new content" {
		t.Fatalf("expected 'new content', got %q", string(data))
	}
}

func TestPut_OverwriteFile(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "exist.txt"), []byte("old"), 0o644)

	resp := doReq(t, "PUT", ts.URL+"/exist.txt", "updated", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}

	data, _ := os.ReadFile(filepath.Join(g.rootDir, "exist.txt"))
	if string(data) != "updated" {
		t.Fatalf("expected 'updated', got %q", string(data))
	}
}

func TestPut_CreatesParentDirs(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	resp := doReq(t, "PUT", ts.URL+"/a/b/c/deep.txt", "deep", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	data, _ := os.ReadFile(filepath.Join(g.rootDir, "a", "b", "c", "deep.txt"))
	if string(data) != "deep" {
		t.Fatalf("expected 'deep', got %q", string(data))
	}
}

func TestDelete_File(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "remove.txt"), []byte("bye"), 0o644)

	resp := doReq(t, "DELETE", ts.URL+"/remove.txt", "", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}

	if _, err := os.Stat(filepath.Join(g.rootDir, "remove.txt")); !os.IsNotExist(err) {
		t.Fatal("file should be deleted")
	}
}

func TestDelete_Directory(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	dir := filepath.Join(g.rootDir, "rmdir")
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "file.txt"), []byte("x"), 0o644)

	resp := doReq(t, "DELETE", ts.URL+"/rmdir", "", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("directory should be deleted")
	}
}

func TestDelete_NotFound(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "DELETE", ts.URL+"/ghost.txt", "", nil)
	resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDelete_Root(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "DELETE", ts.URL+"/", "", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for root deletion, got %d", resp.StatusCode)
	}
}

func TestMkcol(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	resp := doReq(t, "MKCOL", ts.URL+"/newdir", "", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	info, err := os.Stat(filepath.Join(g.rootDir, "newdir"))
	if err != nil {
		t.Fatalf("stat new dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected directory")
	}
}

func TestMkcol_AlreadyExists(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.Mkdir(filepath.Join(g.rootDir, "existing"), 0o755)

	resp := doReq(t, "MKCOL", ts.URL+"/existing", "", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for existing dir, got %d", resp.StatusCode)
	}
}

func TestMkcol_ParentMissing(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "MKCOL", ts.URL+"/no/parent", "", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestMove(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "src.txt"), []byte("moveme"), 0o644)

	resp := doReq(t, "MOVE", ts.URL+"/src.txt", "", map[string]string{
		"Destination": ts.URL + "/dst.txt",
	})
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	if _, err := os.Stat(filepath.Join(g.rootDir, "src.txt")); !os.IsNotExist(err) {
		t.Fatal("source should be gone")
	}

	data, _ := os.ReadFile(filepath.Join(g.rootDir, "dst.txt"))
	if string(data) != "moveme" {
		t.Fatalf("expected 'moveme', got %q", string(data))
	}
}

func TestMove_Overwrite(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "a.txt"), []byte("aaa"), 0o644)
	os.WriteFile(filepath.Join(g.rootDir, "b.txt"), []byte("bbb"), 0o644)

	resp := doReq(t, "MOVE", ts.URL+"/a.txt", "", map[string]string{
		"Destination": ts.URL + "/b.txt",
		"Overwrite":   "T",
	})
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}

	data, _ := os.ReadFile(filepath.Join(g.rootDir, "b.txt"))
	if string(data) != "aaa" {
		t.Fatalf("expected 'aaa', got %q", string(data))
	}
}

func TestMove_NoOverwrite(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "x.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(g.rootDir, "y.txt"), []byte("y"), 0o644)

	resp := doReq(t, "MOVE", ts.URL+"/x.txt", "", map[string]string{
		"Destination": ts.URL + "/y.txt",
		"Overwrite":   "F",
	})
	resp.Body.Close()

	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", resp.StatusCode)
	}
}

func TestCopy(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "orig.txt"), []byte("copy me"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/orig.txt", "", map[string]string{
		"Destination": ts.URL + "/clone.txt",
	})
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	data, _ := os.ReadFile(filepath.Join(g.rootDir, "orig.txt"))
	if string(data) != "copy me" {
		t.Fatal("original should be unchanged")
	}

	data, _ = os.ReadFile(filepath.Join(g.rootDir, "clone.txt"))
	if string(data) != "copy me" {
		t.Fatalf("clone content mismatch: %q", string(data))
	}
}

func TestCopy_Directory(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	src := filepath.Join(g.rootDir, "srcdir")
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	os.WriteFile(filepath.Join(src, "sub", "file.txt"), []byte("deep"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/srcdir", "", map[string]string{
		"Destination": ts.URL + "/dstdir",
	})
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	data, err := os.ReadFile(filepath.Join(g.rootDir, "dstdir", "sub", "file.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(data) != "deep" {
		t.Fatalf("expected 'deep', got %q", string(data))
	}
}

func TestLock(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "LOCK", ts.URL+"/file.txt", "", nil)
	body := readBody(t, resp)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	lockToken := resp.Header.Get("Lock-Token")
	if lockToken == "" {
		t.Fatal("expected Lock-Token header")
	}
	if !strings.Contains(body, "opaquelocktoken:") {
		t.Errorf("expected opaquelocktoken in body, got %s", body)
	}
}

func TestUnlock(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "UNLOCK", ts.URL+"/file.txt", "", map[string]string{
		"Lock-Token": "<opaquelocktoken:test>",
	})
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

func TestProppatch(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "pp.txt"), []byte("x"), 0o644)

	resp := doReq(t, "PROPPATCH", ts.URL+"/pp.txt",
		`<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop/></D:set></D:propertyupdate>`,
		nil)
	body := readBody(t, resp)

	if resp.StatusCode != 207 {
		t.Fatalf("expected 207, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "200 OK") {
		t.Errorf("expected 200 OK status in body, got %s", body)
	}
}

func TestAuthentication_NoAuth(t *testing.T) {
	_, ts := newTestGateway(t, "user", "pass")

	resp := doReq(t, "OPTIONS", ts.URL+"/", "", nil)
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if www := resp.Header.Get("WWW-Authenticate"); !strings.Contains(www, "Basic") {
		t.Fatalf("expected Basic auth challenge, got %q", www)
	}
}

func TestAuthentication_Valid(t *testing.T) {
	_, ts := newTestGateway(t, "user", "pass")

	req, _ := http.NewRequest("OPTIONS", ts.URL+"/", nil)
	req.SetBasicAuth("user", "pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAuthentication_Invalid(t *testing.T) {
	_, ts := newTestGateway(t, "user", "pass")

	req, _ := http.NewRequest("OPTIONS", ts.URL+"/", nil)
	req.SetBasicAuth("user", "wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthentication_Disabled(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "OPTIONS", ts.URL+"/", "", nil)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 when no auth configured, got %d", resp.StatusCode)
	}
}

func TestPathTraversal(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	paths := []string{"/../etc/passwd", "/%2e%2e/etc/passwd", "/..%2f..%2fetc/passwd"}
	for _, p := range paths {
		resp := doReq(t, "PROPFIND", ts.URL+p, "", map[string]string{"Depth": "0"})
		resp.Body.Close()
		if resp.StatusCode != 207 && resp.StatusCode != 404 {
			t.Errorf("path %q: expected safe response, got %d", p, resp.StatusCode)
		}
	}
}

func TestPropfind_XMLValid(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	os.WriteFile(filepath.Join(g.rootDir, "file.txt"), []byte("hello"), 0o644)

	resp := doReq(t, "PROPFIND", ts.URL+"/", "", map[string]string{"Depth": "1"})
	body := readBody(t, resp)

	type multistatus struct {
		XMLName xml.Name `xml:"multistatus"`
	}
	var ms multistatus
	if err := xml.Unmarshal([]byte(body), &ms); err != nil {
		t.Fatalf("XML is not well-formed: %v\n%s", err, body)
	}
}

func TestGetFile_IndexHTML(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	dir := filepath.Join(g.rootDir, "site")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>test</html>"), 0o644)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("unexpected redirect to %s", req.URL)
		},
	}
	req, _ := http.NewRequest("GET", ts.URL+"/site/index.html", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed (possible unwanted redirect): %v", err)
	}
	body := readBody(t, resp)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if body != "<html>test</html>" {
		t.Fatalf("expected HTML content, got %q", body)
	}
}

func TestGateway_StartStop(t *testing.T) {
	rootDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := New(rootDir, Config{ListenAddr: "127.0.0.1:0"}, logger)

	if name := g.Name(); name != "webdav" {
		t.Fatalf("expected name 'webdav', got %q", name)
	}
}

func TestHrefEncoding(t *testing.T) {
	tests := []struct {
		name  string
		isDir bool
		want  string
	}{
		{"", false, "/"},
		{"file.txt", false, "/file.txt"},
		{"dir", true, "/dir/"},
		{"path with spaces/file name.txt", false, "/path%20with%20spaces/file%20name.txt"},
		{"a/b/c", true, "/a/b/c/"},
	}
	for _, tt := range tests {
		got := hrefFromPath(tt.name, tt.isDir)
		if got != tt.want {
			t.Errorf("hrefFromPath(%q, %v) = %q, want %q", tt.name, tt.isDir, got, tt.want)
		}
	}
}

// --- HEAD on directory ---

func TestHead_Directory(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.Mkdir(filepath.Join(g.rootDir, "subdir"), 0o755)

	resp := doReq(t, http.MethodHead, ts.URL+"/subdir", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for HEAD on dir, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "httpd/unix-directory" {
		t.Fatalf("expected httpd/unix-directory, got %q", ct)
	}
}

func TestHead_NotFound(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, http.MethodHead, ts.URL+"/nonexistent", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// --- COPY with Overwrite ---

func TestCopy_OverwriteTrue(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.WriteFile(filepath.Join(g.rootDir, "src.txt"), []byte("source"), 0o644)
	os.WriteFile(filepath.Join(g.rootDir, "dst.txt"), []byte("old"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/src.txt", "", map[string]string{
		"Destination": ts.URL + "/dst.txt",
		"Overwrite":   "T",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for overwrite, got %d", resp.StatusCode)
	}
	data, _ := os.ReadFile(filepath.Join(g.rootDir, "dst.txt"))
	if string(data) != "source" {
		t.Fatalf("expected source, got %q", data)
	}
}

func TestCopy_OverwriteFalse(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.WriteFile(filepath.Join(g.rootDir, "src.txt"), []byte("source"), 0o644)
	os.WriteFile(filepath.Join(g.rootDir, "dst.txt"), []byte("existing"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/src.txt", "", map[string]string{
		"Destination": ts.URL + "/dst.txt",
		"Overwrite":   "F",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", resp.StatusCode)
	}
	data, _ := os.ReadFile(filepath.Join(g.rootDir, "dst.txt"))
	if string(data) != "existing" {
		t.Fatalf("destination should not be modified")
	}
}

func TestCopy_SourceNotFound(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "COPY", ts.URL+"/nonexistent", "", map[string]string{
		"Destination": ts.URL + "/dst.txt",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestCopy_MissingDestination(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.WriteFile(filepath.Join(g.rootDir, "src.txt"), []byte("data"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/src.txt", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for missing Destination, got %d", resp.StatusCode)
	}
}

func TestCopy_IntoSubdir(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.WriteFile(filepath.Join(g.rootDir, "src.txt"), []byte("data"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/src.txt", "", map[string]string{
		"Destination": ts.URL + "/sub/copy.txt",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	data, _ := os.ReadFile(filepath.Join(g.rootDir, "sub", "copy.txt"))
	if string(data) != "data" {
		t.Fatalf("expected data, got %q", data)
	}
}

// --- MKCOL edge cases ---

func TestMkcol_Root(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "MKCOL", ts.URL+"/", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for MKCOL on root, got %d", resp.StatusCode)
	}
}

func TestMkcol_WithBody(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	req, _ := http.NewRequest("MKCOL", ts.URL+"/newdir", strings.NewReader("some body"))
	req.Header.Set("Content-Length", "9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 for MKCOL with body, got %d", resp.StatusCode)
	}
}

func TestMkcol_Traversal(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "MKCOL", ts.URL+"/../../etc/evil", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("should reject traversal in MKCOL")
	}
}

// --- PROPFIND default depth ---

func TestPropfind_DefaultDepthImplicit(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.WriteFile(filepath.Join(g.rootDir, "a.txt"), []byte("a"), 0o644)

	resp := doReq(t, "PROPFIND", ts.URL+"/", "", nil)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("expected 207, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "a.txt") {
		t.Fatal("default depth should list children (depth=1)")
	}
}

// --- PUT edge cases ---

func TestPut_Root(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, http.MethodPut, ts.URL+"/", "data", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for PUT on root, got %d", resp.StatusCode)
	}
}

func TestPut_DeepPath(t *testing.T) {
	g, ts := newTestGateway(t, "", "")

	resp := doReq(t, http.MethodPut, ts.URL+"/deep/nested/file.txt", "data", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	data, _ := os.ReadFile(filepath.Join(g.rootDir, "deep", "nested", "file.txt"))
	if string(data) != "data" {
		t.Fatalf("expected data, got %q", data)
	}
}

func TestPut_OverwriteExisting(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.WriteFile(filepath.Join(g.rootDir, "f.txt"), []byte("old"), 0o644)

	resp := doReq(t, http.MethodPut, ts.URL+"/f.txt", "new", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 or 204, got %d", resp.StatusCode)
	}
	data, _ := os.ReadFile(filepath.Join(g.rootDir, "f.txt"))
	if string(data) != "new" {
		t.Fatalf("expected new, got %q", data)
	}
}

// --- DELETE edge cases ---

func TestDelete_Traversal(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, http.MethodDelete, ts.URL+"/../../etc/passwd", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("should reject traversal in DELETE")
	}
}

func TestDelete_NonExistent(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, http.MethodDelete, ts.URL+"/nonexistent", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDelete_DirectoryRecursive(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.MkdirAll(filepath.Join(g.rootDir, "dir", "sub"), 0o755)
	os.WriteFile(filepath.Join(g.rootDir, "dir", "sub", "f.txt"), []byte("x"), 0o644)

	resp := doReq(t, http.MethodDelete, ts.URL+"/dir", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for recursive delete, got %d", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(g.rootDir, "dir")); !os.IsNotExist(err) {
		t.Fatal("directory should be removed")
	}
}

// --- MOVE edge cases ---

func TestMove_SourceNotFound(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "MOVE", ts.URL+"/nonexistent", "", map[string]string{
		"Destination": ts.URL + "/dst.txt",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestMove_MissingDestination(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.WriteFile(filepath.Join(g.rootDir, "src.txt"), []byte("data"), 0o644)

	resp := doReq(t, "MOVE", ts.URL+"/src.txt", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for missing Destination, got %d", resp.StatusCode)
	}
}

func TestMove_OverwriteExisting(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.WriteFile(filepath.Join(g.rootDir, "old.txt"), []byte("old"), 0o644)
	os.WriteFile(filepath.Join(g.rootDir, "new.txt"), []byte("new"), 0o644)

	resp := doReq(t, "MOVE", ts.URL+"/new.txt", "", map[string]string{
		"Destination": ts.URL + "/old.txt",
		"Overwrite":   "T",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	data, _ := os.ReadFile(filepath.Join(g.rootDir, "old.txt"))
	if string(data) != "new" {
		t.Fatalf("expected new, got %q", data)
	}
	if _, err := os.Stat(filepath.Join(g.rootDir, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("source should be removed after MOVE")
	}
}

func TestMove_Directory(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.MkdirAll(filepath.Join(g.rootDir, "srcdir"), 0o755)
	os.WriteFile(filepath.Join(g.rootDir, "srcdir", "f.txt"), []byte("x"), 0o644)

	resp := doReq(t, "MOVE", ts.URL+"/srcdir", "", map[string]string{
		"Destination": ts.URL + "/dstdir",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	data, err := os.ReadFile(filepath.Join(g.rootDir, "dstdir", "f.txt"))
	if err != nil {
		t.Fatal("file should exist in moved dir")
	}
	if string(data) != "x" {
		t.Fatalf("expected x, got %q", data)
	}
}

// --- GET edge cases ---

func TestGet_Traversal(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, http.MethodGet, ts.URL+"/../../etc/passwd", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("should reject traversal in GET")
	}
}

func TestGet_NotFound(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, http.MethodGet, ts.URL+"/nonexistent", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// --- PROPFIND edge cases ---

func TestPropfind_NonExistent(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "PROPFIND", ts.URL+"/nonexistent", "", map[string]string{
		"Depth": "0",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestPropfind_Traversal(t *testing.T) {
	_, ts := newTestGateway(t, "", "")

	resp := doReq(t, "PROPFIND", ts.URL+"/../../etc", "", map[string]string{
		"Depth": "0",
	})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMultiStatus {
		t.Fatal("should reject traversal in PROPFIND")
	}
}

// --- Copy directory ---

func TestCopy_DirectoryRecursive(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	os.MkdirAll(filepath.Join(g.rootDir, "srcdir", "sub"), 0o755)
	os.WriteFile(filepath.Join(g.rootDir, "srcdir", "a.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(g.rootDir, "srcdir", "sub", "b.txt"), []byte("b"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/srcdir", "", map[string]string{
		"Destination": ts.URL + "/dstdir",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	data, err := os.ReadFile(filepath.Join(g.rootDir, "dstdir", "sub", "b.txt"))
	if err != nil {
		t.Fatal("nested file should exist in copied dir")
	}
	if string(data) != "b" {
		t.Fatalf("expected b, got %q", data)
	}

	if _, err := os.Stat(filepath.Join(g.rootDir, "srcdir", "a.txt")); err != nil {
		t.Fatal("source should still exist after COPY")
	}
}

// --- Auth ---

func TestAuth_Unauthorized(t *testing.T) {
	_, ts := newTestGateway(t, "admin", "secret")

	resp := doReq(t, "PROPFIND", ts.URL+"/", "", map[string]string{
		"Depth": "0",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}
