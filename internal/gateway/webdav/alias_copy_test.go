package webdav

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCopyMoveRejectsSubtreeThroughAlias(t *testing.T) {
	for _, method := range []string{"COPY", "MOVE"} {
		for _, dest := range []string{"alias", "alias/child", "alias/missing/deep/child"} {
			t.Run(method+"/"+dest, func(t *testing.T) {
				root := t.TempDir()
				logger := slog.New(slog.NewTextHandler(io.Discard, nil))
				source := filepath.Join(root, "src")
				if err := os.Mkdir(source, 0o700); err != nil {
					t.Fatal(err)
				}
				reviewWrite(t, root, "src/file", "keep", time.Now())
				if err := os.Symlink(source, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				// Check the guard before issuing COPY: a broken guard would recurse
				// into the directory being created, unnecessarily consuming disk.
				if !isSameOrUnder(filepath.Join(root, dest), source) {
					t.Fatal("directory alias bypasses recursive-copy guard")
				}
				g := New(root, Config{}, logger)
				req := httptest.NewRequest(method, "http://node/src", nil)
				req.Header.Set("Destination", "http://node/"+dest)
				out := httptest.NewRecorder()
				g.server.Handler.ServeHTTP(out, req)
				if out.Code != http.StatusForbidden {
					t.Fatalf("subtree mutation accepted: %d %s", out.Code, out.Body)
				}
				entries, err := os.ReadDir(source)
				if err != nil || len(entries) != 1 || entries[0].Name() != "file" {
					t.Fatalf("source mutated: %v %v", entries, err)
				}
			})
		}
	}
}
