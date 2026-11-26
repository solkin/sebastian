//go:build unix

package fileops

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenRegularRejectsFIFOAndDir(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := OpenRegular(fifo)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("OpenRegular succeeded on FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenRegular blocked on FIFO")
	}

	if f, err := OpenRegular(dir); !errors.Is(err, syscall.EISDIR) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("OpenRegular(dir) = %v, want EISDIR", err)
	}
}

func TestCheckOrphanedBackupsSkipsUnreadableSubdir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses chmod 000")
	}
	root := t.TempDir()
	sub := filepath.Join(root, "locked")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sub, 0o700) })

	if err := CheckOrphanedBackups(root, nil); err != nil {
		t.Fatalf("CheckOrphanedBackups failed on unreadable subdir: %v", err)
	}
}

func TestLockStableAcrossSymlinkAlias(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Fatal(err)
	}
	unlock := Lock(alias)
	defer unlock()
	if u, ok := TryLock(realDir); ok {
		u()
		t.Fatal("TryLock on canonical path succeeded while symlink alias held lock")
	}
}
