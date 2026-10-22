package httpui

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/fileops"
)

// scratchFiles lists the atomic-write scratch files anywhere under dir.
func scratchFiles(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), ".seb-tmp-") {
			found = append(found, p)
		}
		return nil
	})
	return found
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// An upload goes from the connection straight into a scratch file next to its
// destination. It used to be spooled whole to os.TempDir first — written twice,
// and onto a filesystem that may be far smaller than the volume.
func TestUpload_StreamsIntoVolumeNotTempDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.TempDir does not follow TMPDIR on Windows")
	}
	g, dir := newTestGateway(t, "", "")
	if err := os.Mkdir(filepath.Join(dir, "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	req := httptest.NewRequest(http.MethodPost, "/_api/upload", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.server.Handler.ServeHTTP(w, req)
	}()

	chunk := bytes.Repeat([]byte("apk!"), 1<<19) // 2 MiB, beyond any in-memory part
	mw.WriteField("path", "apps")
	part, _ := mw.CreateFormFile("files", "big.apk")
	if _, err := part.Write(chunk); err != nil {
		t.Fatal(err)
	}
	// The server has consumed 2 MiB of the file and is still waiting for more.
	if spooled := dirEntries(t, tmp); len(spooled) != 0 {
		t.Fatalf("upload was spooled to TMPDIR: %v", spooled)
	}
	staged := scratchFiles(t, dir)
	if len(staged) != 1 || filepath.Dir(staged[0]) != filepath.Join(dir, "apps") {
		t.Fatalf("expected one scratch file next to the destination, got %v", staged)
	}
	part.Write(chunk)
	mw.WriteField("relpaths", "big.apk")
	mw.Close()
	pw.Close()
	<-done

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, "apps", "big.apk"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, append(chunk, chunk...)) {
		t.Fatalf("uploaded %d bytes, content differs", len(data))
	}
	if left := scratchFiles(t, dir); len(left) != 0 {
		t.Fatalf("scratch files left: %v", left)
	}
	if spooled := dirEntries(t, tmp); len(spooled) != 0 {
		t.Fatalf("upload left files in TMPDIR: %v", spooled)
	}
}

// A client that disconnects mid-upload leaves neither a scratch file nor a
// partial file behind, and that is not logged as a server error.
func TestUpload_ClientDisconnectLeavesNothing(t *testing.T) {
	g, dir, logs := newLoggedGateway(t, Config{})
	srv := httptest.NewServer(g.server.Handler)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var head bytes.Buffer
	mw := multipart.NewWriter(&head)
	mw.WriteField("path", "")
	part, _ := mw.CreateFormFile("files", "app.apk")
	part.Write(bytes.Repeat([]byte("x"), 64<<10))
	fmt.Fprintf(conn, "POST /_api/upload HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
		srv.Listener.Addr(), mw.FormDataContentType(), 100<<20)
	if _, err := conn.Write(head.Bytes()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(scratchFiles(t, dir)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("upload never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	conn.Close()

	logs.waitFor(t, "upload aborted")
	for len(g.uploadSem) != 0 { // released after the cleanup ran
		if time.Now().After(deadline) {
			t.Fatal("upload handler did not return")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if left := scratchFiles(t, dir); len(left) != 0 {
		t.Fatalf("scratch files left after disconnect: %v", left)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.apk")); !os.IsNotExist(err) {
		t.Fatalf("partial upload was published: %v", err)
	}
	if errs := logs.errors(); len(errs) != 0 {
		t.Fatalf("client disconnect logged as an error: %v", errs)
	}
}

// A failure on the server's side of an upload is still an error.
func TestUpload_ServerFailureIsLoggedAsError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs directory permissions that the current user cannot bypass")
	}
	g, dir, logs := newLoggedGateway(t, Config{})
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	body, ct := createMultipartUpload("locked", "a.txt", "data")
	req := httptest.NewRequest(http.MethodPost, "/_api/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	g.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	assertNoPaths(t, w, dir)
	if errs := logs.errors(); len(errs) != 1 || errs[0] != "upload failed" {
		t.Fatalf("server failure not logged as an error: %v", logs.messages())
	}
}

func TestUpload_OverLimitLeavesNothing(t *testing.T) {
	g, dir, logs := newLoggedGateway(t, Config{MaxUploadBytes: 64 << 10})

	body, ct := createMultipartUpload("", "large.apk", strings.Repeat("x", 1<<20))
	req := httptest.NewRequest(http.MethodPost, "/_api/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	g.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "upload exceeds the size limit") {
		t.Fatalf("expected 413 size limit, got %d: %s", w.Code, w.Body.String())
	}
	if left := scratchFiles(t, dir); len(left) != 0 {
		t.Fatalf("scratch files left: %v", left)
	}
	if _, err := os.Stat(filepath.Join(dir, "large.apk")); !os.IsNotExist(err) {
		t.Fatal("over-limit upload must not create the file")
	}
	if errs := logs.errors(); len(errs) != 0 {
		t.Fatalf("over-limit upload logged as an error: %v", errs)
	}
}

// formPart is one part of a hand-built upload form.
type formPart struct {
	name, filename, value string
}

func uploadForm(t *testing.T, g *Gateway, url string, parts ...formPart) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		if p.filename == "" {
			mw.WriteField(p.name, p.value)
			continue
		}
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, p.name, p.filename))
		h.Set("Content-Type", "application/octet-stream")
		pw, _ := mw.CreatePart(h)
		pw.Write([]byte(p.value))
	}
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	g.server.Handler.ServeHTTP(w, req)
	return w
}

// Streaming must not make the form's field order matter: the target and the
// relative paths may come before or after the files they apply to, as they
// could when the whole form was parsed first.
func TestUpload_FieldOrderDoesNotMatter(t *testing.T) {
	cases := []struct {
		name  string
		url   string
		parts []formPart
		want  map[string]string
	}{
		{
			name: "frontend folder upload",
			url:  "/_api/upload",
			parts: []formPart{
				{name: "path", value: "apps"},
				{name: "files", filename: "release/a.apk", value: "A"},
				{name: "relpaths", value: "release/a.apk"},
				{name: "files", filename: "release/icons/a.png", value: "I"},
				{name: "relpaths", value: "release/icons/a.png"},
			},
			want: map[string]string{"apps/release/a.apk": "A", "apps/release/icons/a.png": "I"},
		},
		{
			name: "flat files without relpaths",
			url:  "/_api/upload",
			parts: []formPart{
				{name: "path", value: "apps"},
				{name: "files", filename: "a.apk", value: "A"},
				{name: "files", filename: "b.apk", value: "B"},
			},
			want: map[string]string{"apps/a.apk": "A", "apps/b.apk": "B"},
		},
		{
			name: "path after the files",
			url:  "/_api/upload",
			parts: []formPart{
				{name: "files", filename: "a.apk", value: "A"},
				{name: "relpaths", value: "sub/a.apk"},
				{name: "path", value: "new/dir"},
			},
			want: map[string]string{"new/dir/sub/a.apk": "A"},
		},
		{
			name: "relpaths before the files",
			url:  "/_api/upload",
			parts: []formPart{
				{name: "relpaths", value: "x/a.apk"},
				{name: "relpaths", value: "y/b.apk"},
				{name: "files", filename: "a.apk", value: "A"},
				{name: "files", filename: "b.apk", value: "B"},
			},
			want: map[string]string{"x/a.apk": "A", "y/b.apk": "B"},
		},
		{
			name: "query path wins over the field",
			url:  "/_api/upload?path=q",
			parts: []formPart{
				{name: "path", value: "field"},
				{name: "files", filename: "a.apk", value: "A"},
			},
			want: map[string]string{"q/a.apk": "A"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, dir := newTestGateway(t, "", "")
			if err := os.Mkdir(filepath.Join(dir, "apps"), 0o755); err != nil {
				t.Fatal(err)
			}
			w := uploadForm(t, g, tc.url, tc.parts...)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			for name, content := range tc.want {
				data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
				if err != nil || string(data) != content {
					t.Fatalf("%s = %q, %v; want %q", name, data, err, content)
				}
			}
			if left := scratchFiles(t, dir); len(left) != 0 {
				t.Fatalf("scratch files left: %v", left)
			}
			if _, err := os.Stat(filepath.Join(dir, "field")); !os.IsNotExist(err) {
				t.Fatal("the form's path field overrode the query")
			}
		})
	}
}

// Nothing is published until every name in the form has been checked.
func TestUpload_InvalidNamePublishesNothing(t *testing.T) {
	for _, bad := range []string{"../evil.apk", "..", "x/..", "bad\x00name.apk", ".seb-tmp-x", "sub/.seb-bak-y"} {
		g, dir := newTestGateway(t, "", "")
		if err := os.Mkdir(filepath.Join(dir, "apps"), 0o755); err != nil {
			t.Fatal(err)
		}
		w := uploadForm(t, g, "/_api/upload",
			formPart{name: "path", value: "apps"},
			formPart{name: "files", filename: "good.apk", value: "G"},
			formPart{name: "relpaths", value: "good.apk"},
			formPart{name: "files", filename: "bad.apk", value: "B"},
			formPart{name: "relpaths", value: bad},
		)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%q: expected 400, got %d: %s", bad, w.Code, w.Body.String())
		}
		if _, err := os.Stat(filepath.Join(dir, "apps", "good.apk")); !os.IsNotExist(err) {
			t.Fatalf("%q: a valid file of a rejected form was published", bad)
		}
		if left := scratchFiles(t, dir); len(left) != 0 {
			t.Fatalf("%q: scratch files left: %v", bad, left)
		}
	}
}

// An upload into a directory that does not exist yet stages at the root and
// creates the directory only once the form is complete, so a refused form
// leaves no empty directories behind.
func TestUpload_RefusedFormCreatesNoDirectories(t *testing.T) {
	g, dir := newTestGateway(t, "", "")
	w := uploadForm(t, g, "/_api/upload",
		formPart{name: "path", value: "new/deep"},
		formPart{name: "files", filename: "a.apk", value: "A"},
		formPart{name: "relpaths", value: "sub/a.apk"},
		formPart{name: "files", filename: "b.apk", value: "B"},
		formPart{name: "relpaths", value: "../../../b.apk"},
	)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if names := dirEntries(t, dir); len(names) != 0 {
		t.Fatalf("refused upload left %v", names)
	}
}

// A form of more parts than an upload may have is refused before anything is
// published, as ParseMultipartForm refused it.
func TestUpload_TooManyPartsIsRefused(t *testing.T) {
	g, dir := newTestGateway(t, "", "")
	parts := []formPart{{name: "files", filename: "a.apk", value: "A"}}
	for i := 0; i < maxUploadParts; i++ {
		parts = append(parts, formPart{name: "other", value: "x"})
	}
	w := uploadForm(t, g, "/_api/upload", parts...)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if names := dirEntries(t, dir); len(names) != 0 {
		t.Fatalf("refused upload left %v", names)
	}
}

// A bucket may be a separate mount. A scratch file staged outside it cannot
// be renamed in, so the upload is copied next to its destination instead of
// failing.
func TestUpload_PublishesAcrossFilesystems(t *testing.T) {
	g, dir := newTestGateway(t, "", "")
	crossed := 0
	publishUpload = func(root, scratch, dest string) error {
		if filepath.Dir(scratch) != filepath.Dir(dest) {
			crossed++
			return &os.LinkError{Op: "rename", Old: scratch, New: dest, Err: syscall.EXDEV}
		}
		return fileops.Publish(root, scratch, dest)
	}
	t.Cleanup(func() { publishUpload = fileops.Publish })

	w := uploadForm(t, g, "/_api/upload",
		formPart{name: "files", filename: "a.apk", value: "A"},
		formPart{name: "relpaths", value: "mounted/bucket/a.apk"},
	)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if crossed == 0 {
		t.Fatal("the test did not stage outside the destination directory")
	}
	if data, err := os.ReadFile(filepath.Join(dir, "mounted", "bucket", "a.apk")); err != nil || string(data) != "A" {
		t.Fatalf("upload across filesystems = %q, %v", data, err)
	}
	if left := scratchFiles(t, dir); len(left) != 0 {
		t.Fatalf("scratch files left: %v", left)
	}
}
