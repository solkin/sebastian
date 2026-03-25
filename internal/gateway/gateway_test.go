package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
