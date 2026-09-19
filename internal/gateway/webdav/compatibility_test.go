package webdav

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCopy_MaxUploadBytesTree(t *testing.T) {
	syncDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := New(syncDir, Config{ListenAddr: ":0", MaxUploadBytes: 4}, logger)
	ts := httptest.NewServer(g.server.Handler)
	t.Cleanup(ts.Close)

	src := filepath.Join(g.rootDir, "srcdir")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("aaa"), 0o644)
	os.WriteFile(filepath.Join(src, "b.txt"), []byte("bbb"), 0o644)

	// Cumulative size (6 bytes) exceeds the 4-byte budget, so the copy is refused.
	resp := doReq(t, "COPY", ts.URL+"/srcdir", "", map[string]string{
		"Destination": ts.URL + "/dstdir",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for over-budget COPY, got %d", resp.StatusCode)
	}
}

func TestCopy_OverwritePreservesOnConflict(t *testing.T) {
	// Non-destructive overwrite: copying a directory over an existing file
	// succeeds and replaces it (exercises stageReplace's happy path).
	g, ts := newTestGateway(t, "", "")
	src := filepath.Join(g.rootDir, "srcdir")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "inner.txt"), []byte("deep"), 0o644)
	os.WriteFile(filepath.Join(g.rootDir, "dst"), []byte("existing"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/srcdir", "", map[string]string{
		"Destination": ts.URL + "/dst",
		"Overwrite":   "T",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for overwrite copy, got %d", resp.StatusCode)
	}
	data, err := os.ReadFile(filepath.Join(g.rootDir, "dst", "inner.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(data) != "deep" {
		t.Fatalf("expected 'deep', got %q", data)
	}
}
