package webdav

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/fileops"
	"github.com/solkin/sebastian/internal/gateway"
)

func TestDeleteAndMoveRespectDescendantLocks(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	if err := os.MkdirAll(filepath.Join(g.rootDir, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g.rootDir, "dir", "child.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	lockResp := doReq(t, "LOCK", ts.URL+"/dir/child.txt", "", nil)
	token := lockResp.Header.Get("Lock-Token")
	lockResp.Body.Close()
	if lockResp.StatusCode != http.StatusOK || token == "" {
		t.Fatalf("LOCK failed: status=%d token=%q", lockResp.StatusCode, token)
	}

	delResp := doReq(t, http.MethodDelete, ts.URL+"/dir", "", nil)
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusLocked {
		t.Fatalf("DELETE parent with locked child = %d, want 423", delResp.StatusCode)
	}

	mvResp := doReq(t, "MOVE", ts.URL+"/dir", "", map[string]string{"Destination": ts.URL + "/dir2"})
	mvResp.Body.Close()
	if mvResp.StatusCode != http.StatusLocked {
		t.Fatalf("MOVE parent with locked child = %d, want 423", mvResp.StatusCode)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := doReq(t, "LOCK", ts.URL+"/dir/child.txt", "", map[string]string{"If": "(" + token + ")"})
			r.Body.Close()
		}()
	}
	wg.Wait()

	delOK := doReq(t, http.MethodDelete, ts.URL+"/dir", "", map[string]string{"If": "(" + token + ")"})
	delOK.Body.Close()
	if delOK.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE parent with token = %d, want 204", delOK.StatusCode)
	}
}

func TestCopyDirSkipsScratchAndGetSetsNoSniff(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	if err := os.MkdirAll(filepath.Join(g.rootDir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(g.rootDir, "src", "good.txt"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(g.rootDir, "src", ".seb-tmp-leftover"), []byte("secret"), 0o644)

	resp := doReq(t, "COPY", ts.URL+"/src", "", map[string]string{"Destination": ts.URL + "/dst"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("COPY status = %d", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(g.rootDir, "dst", "good.txt")); err != nil {
		t.Fatalf("good.txt not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(g.rootDir, "dst", ".seb-tmp-leftover")); !os.IsNotExist(err) {
		t.Fatal("scratch file was copied")
	}

	getResp := doReq(t, http.MethodGet, ts.URL+"/dst/good.txt", "", nil)
	getResp.Body.Close()
	if got := getResp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestCopyCleansStageOnFailureAndSweepRespectsActiveStage(t *testing.T) {
	g, ts := newTestGateway(t, "", "")
	g.config.MaxUploadBytes = 8
	if err := os.WriteFile(filepath.Join(g.rootDir, "big.bin"), make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}

	resp := doReq(t, "COPY", ts.URL+"/big.bin", "", map[string]string{"Destination": ts.URL + "/dst.bin"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("COPY over limit = %d, want 413", resp.StatusCode)
	}

	entries, err := os.ReadDir(g.rootDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".seb-tmp-replace-") {
			t.Fatalf("leftover replace stage dir after failed COPY: %s", e.Name())
		}
	}

	activeStage, err := os.MkdirTemp(g.rootDir, ".seb-tmp-replace-*")
	if err != nil {
		t.Fatal(err)
	}
	staleStage, err := os.MkdirTemp(g.rootDir, ".seb-tmp-replace-*")
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{activeStage, staleStage} {
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	fileops.RetainTemp(activeStage)
	defer fileops.ReleaseTempPath(activeStage)

	gateway.SweepTempFiles(g.rootDir, time.Hour, g.logger)
	if _, err := os.Stat(activeStage); err != nil {
		t.Fatalf("retained replace stage was swept: %v", err)
	}
	if _, err := os.Stat(staleStage); !os.IsNotExist(err) {
		t.Fatalf("stale replace stage was not swept: %v", err)
	}
}
