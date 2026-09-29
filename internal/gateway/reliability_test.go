package gateway

import (
	"github.com/solkin/sebastian/internal/fileops"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSweepPreservesActiveUploadAndRecoveryBackup(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "file")
	f, err := fileops.CreateTemp(root, tempFilePrefix+"*")
	if err != nil {
		t.Fatal(err)
	}
	defer fileops.ReleaseTemp(f)
	defer f.Close()
	if _, err := f.WriteString("upload"); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(f.Name(), past, past); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, backupFilePrefix+"old")
	if err := os.WriteFile(backup, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	SweepTempFiles(root, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := fileops.Publish(root, f.Name(), dest); err != nil {
		t.Fatalf("active upload removed: %v", err)
	}
	if body, err := os.ReadFile(backup); err != nil || string(body) != "original" {
		t.Fatalf("recovery backup removed: %q %v", body, err)
	}
	if err := fileops.CheckOrphanedBackups(root, nil); err == nil {
		t.Fatal("unmapped backup did not stop recovery")
	}
}

func TestSweepPreservesJournalOwnedCopyStage(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, ".seb-tmp-replace-test")
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(stage, "payload")
	if err := os.WriteFile(payload, []byte("pending recovery"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".sebastian", "transactions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "replace-test.json")
	// Even a malformed/blocked journal must fence the janitor.
	if err := os.WriteFile(journal, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	SweepTempFiles(root, 0, slog.Default())
	if b, err := os.ReadFile(payload); err != nil || string(b) != "pending recovery" {
		t.Fatalf("deleted journal-owned stage: %q %v", b, err)
	}
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	SweepTempFiles(root, 0, slog.Default())
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("orphan COPY stage remains: %v", err)
	}
}
