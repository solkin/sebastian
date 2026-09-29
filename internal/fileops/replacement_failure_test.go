package fileops

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReplacementFailedMoveRestoresDestination(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged permissions")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "readable-source")
	src, dst := filepath.Join(parent, "file"), filepath.Join(root, "dst")
	mustWrite(t, src, "source bytes")
	mustWrite(t, dst, "destination bytes")
	// Reading the source is allowed, but the real rename syscall must fail.
	if err := os.Chmod(parent, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	err := ReplaceLocked(root, src, dst)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected rename permission failure, got %v", err)
	}
	wantBody(t, src, "source bytes")
	wantBody(t, dst, "destination bytes")
	if pending, err := ReplacementPendingLocked(root); err != nil || pending {
		t.Fatalf("failed rename stranded a journal: %v %v", pending, err)
	}
	if err := RecoverLocked(root); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementFailedCopyLeavesDestinationUntouched(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, "dst")
	mustWrite(t, dst, "destination bytes")
	before, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	err = CopyReplaceLocked(root, dst, func(stage string) error {
		mustWrite(t, filepath.Join(stage, "partial-file"), "partial copy")
		// Inject a write failure after real partial filesystem work. The existing
		// destination must never leave its name/inode, even temporarily.
		wantBody(t, dst, "destination bytes")
		return &os.PathError{Op: "write", Path: stage, Err: syscall.ENOSPC}
	})
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("write error lost: %v", err)
	}
	after, err := os.Stat(dst)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("failed COPY replaced destination: %v", err)
	}
	wantBody(t, dst, "destination bytes")
	paths, err := filepath.Glob(filepath.Join(root, ".seb-tmp-replace-*"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("partial copy leaked: %v %v", paths, err)
	}
	if pending, err := ReplacementPendingLocked(root); err != nil || pending {
		t.Fatalf("failed build created a journal: %v %v", pending, err)
	}
}
