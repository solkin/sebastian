package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSafePath_Root(t *testing.T) {
	rel, full, err := SafePath("/data", "/")
	if err != nil {
		t.Fatal(err)
	}
	if rel != "" || full != "/data" {
		t.Fatalf("got rel=%q full=%q", rel, full)
	}
}

func TestSafePath_Dot(t *testing.T) {
	rel, full, err := SafePath("/data", ".")
	if err != nil {
		t.Fatal(err)
	}
	if rel != "" || full != "/data" {
		t.Fatalf("got rel=%q full=%q", rel, full)
	}
}

func TestSafePath_Empty(t *testing.T) {
	rel, full, err := SafePath("/data", "")
	if err != nil {
		t.Fatal(err)
	}
	if rel != "" || full != "/data" {
		t.Fatalf("got rel=%q full=%q", rel, full)
	}
}

func TestSafePath_Normal(t *testing.T) {
	rel, full, err := SafePath("/data", "/foo/bar.txt")
	if err != nil {
		t.Fatal(err)
	}
	if rel != "foo/bar.txt" {
		t.Fatalf("expected rel=foo/bar.txt, got %q", rel)
	}
	if full != "/data/foo/bar.txt" {
		t.Fatalf("expected full=/data/foo/bar.txt, got %q", full)
	}
}

func TestSafePath_TraversalVariants(t *testing.T) {
	cases := []string{
		"..",
		"../",
		"../..",
		"../../etc/passwd",
		"foo/../../../etc",
	}
	for _, p := range cases {
		_, _, err := SafePath("/data", p)
		if err == nil {
			t.Errorf("expected error for path %q", p)
		}
	}
}

func TestSafePath_AbsolutePathsCleaned(t *testing.T) {
	// Absolute paths with /../.. get cleaned by filepath.Clean to stay within root.
	// /../../etc/passwd → /etc/passwd → rootDir/etc/passwd (inside rootDir).
	rel, full, err := SafePath("/data", "/../../../etc/passwd")
	if err != nil {
		t.Fatalf("should not error (cleans to etc/passwd under root): %v", err)
	}
	if rel != "etc/passwd" || full != "/data/etc/passwd" {
		t.Fatalf("got rel=%q full=%q", rel, full)
	}
}

func TestSafePath_DotDotInName(t *testing.T) {
	rel, _, err := SafePath("/data", "/foo..bar")
	if err != nil {
		t.Fatalf("dotdot in filename should be allowed: %v", err)
	}
	if rel != "foo..bar" {
		t.Fatalf("expected foo..bar, got %q", rel)
	}
}

func TestSafePath_LeadingSlash(t *testing.T) {
	rel, full, err := SafePath("/data", "subdir/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if rel != "subdir/file.txt" {
		t.Fatalf("expected subdir/file.txt, got %q", rel)
	}
	if full != "/data/subdir/file.txt" {
		t.Fatalf("got %q", full)
	}
}

func TestSafePath_SymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A symlink inside root pointing outside must not allow escaping root.
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, _, err := SafePath(root, "/escape/secret.txt"); err == nil {
		t.Fatal("expected traversal error through an escaping symlink")
	}
	// Even a not-yet-existing target under the escaping symlink must be rejected.
	if _, _, err := SafePath(root, "/escape/new.txt"); err == nil {
		t.Fatal("expected traversal error for new file under escaping symlink")
	}

	// A symlink that stays within root is allowed.
	sub := filepath.Join(root, "real")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f.txt"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, filepath.Join(root, "inlink")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, _, err := SafePath(root, "/inlink/f.txt"); err != nil {
		t.Fatalf("symlink within root should be allowed: %v", err)
	}
}

func TestCheckBasicAuth_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if !CheckBasicAuth(req, "", "") {
		t.Error("should pass when no auth configured")
	}
}

func TestCheckBasicAuth_ValidCredentials(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	if !CheckBasicAuth(req, "admin", "secret") {
		t.Error("should pass with valid credentials")
	}
}

func TestCheckBasicAuth_InvalidCredentials(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "wrong")
	if CheckBasicAuth(req, "admin", "secret") {
		t.Error("should fail with wrong password")
	}
}

func TestCheckBasicAuth_NoHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if CheckBasicAuth(req, "admin", "secret") {
		t.Error("should fail without auth header")
	}
}

func TestCheckBasicAuth_WrongUser(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("other", "secret")
	if CheckBasicAuth(req, "admin", "secret") {
		t.Error("should fail with wrong username")
	}
}

func TestLogMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("hello"))
	})

	wrapped := LogMiddleware(logger, handler)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	if w.Body.String() != "hello" {
		t.Fatalf("expected hello, got %q", w.Body.String())
	}
}

func TestResponseLogger_DefaultStatus(t *testing.T) {
	w := httptest.NewRecorder()
	rl := &ResponseLogger{ResponseWriter: w, Status: 200}

	rl.Write([]byte("data"))
	if rl.Status != 200 {
		t.Fatalf("expected default 200, got %d", rl.Status)
	}
	if rl.Size != 4 {
		t.Fatalf("expected size 4, got %d", rl.Size)
	}
}
