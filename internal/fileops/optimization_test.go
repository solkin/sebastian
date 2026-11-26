package fileops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSyncParentsRejectsOutsideRoot(t *testing.T) {
	rootDir := t.TempDir()
	outside := t.TempDir()
	if err := SyncParents(outside, rootDir); err == nil {
		t.Fatalf("SyncParents(%q, %q) succeeded, want boundary error", outside, rootDir)
	}
}

func TestRecoverIfNeededLockedTracksDirtyState(t *testing.T) {
	dir := t.TempDir()
	unlock := Lock(dir)
	defer unlock()

	if err := RecoverIfNeededLocked(dir); err != nil {
		t.Fatalf("first RecoverIfNeededLocked: %v", err)
	}
	if !root(dir).recoveryClean.Load() {
		t.Fatal("expected recoveryClean=true after clean recovery")
	}

	stage, err := os.MkdirTemp(dir, ".seb-tmp-replace-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "payload"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceStagedLocked(dir, stage, dst); err != nil {
		t.Fatalf("ReplaceStagedLocked: %v", err)
	}
	body, err := os.ReadFile(dst)
	if err != nil || string(body) != "new" {
		t.Fatalf("dst after ReplaceStagedLocked = %q, %v", body, err)
	}
	if err := RecoverIfNeededLocked(dir); err != nil {
		t.Fatalf("post-replace RecoverIfNeededLocked: %v", err)
	}
	if !root(dir).recoveryClean.Load() {
		t.Fatal("expected recoveryClean=true after post-replace recovery")
	}
}
