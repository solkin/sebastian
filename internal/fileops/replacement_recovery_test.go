//go:build unix

package fileops

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReplacementRecoveryChild(t *testing.T) {
	root := os.Getenv("SEBASTIAN_RECOVERY_REVIEW_ROOT")
	if root == "" {
		t.Skip("subprocess only")
	}
	src := ""
	if os.Getenv("SEBASTIAN_RECOVERY_REVIEW_MOVE") == "1" {
		src = filepath.Join(root, "source")
	}
	dst := filepath.Join(root, "dir", "destination")
	var build func(string) error
	if src == "" {
		build = func(stage string) error { return os.WriteFile(stage, []byte("published copy"), 0600) }
	}
	err := replaceLocked(root, src, dst, build, func(step string) {
		if step == "published" {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	})
	t.Fatalf("child missed checkpoint: %v", err)
}

func interruptedReplacement(t *testing.T, move bool) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sync")
	mustWrite(t, filepath.Join(root, "source"), "original source")
	mustWrite(t, filepath.Join(root, "dir", "destination"), "original destination")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestReplacementRecoveryChild$")
	moveFlag := "0"
	if move {
		moveFlag = "1"
	}
	cmd.Env = append(os.Environ(), "SEBASTIAN_RECOVERY_REVIEW_ROOT="+root, "SEBASTIAN_RECOVERY_REVIEW_MOVE="+moveFlag)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("child: %v %s", err, out)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("wrong exit: %v %s", err, out)
	}
	return root
}

func atomicRecoveryEdit(t *testing.T, path, content string) {
	t.Helper()
	stage := path + "-new-generation"
	mustWrite(t, stage, content)
	if err := os.Rename(stage, path); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementRecoveryPreservesOfflineEdit(t *testing.T) {
	for _, move := range []bool{false, true} {
		name := "COPY"
		if move {
			name = "MOVE"
		}
		t.Run(name, func(t *testing.T) {
			root := interruptedReplacement(t, move)
			dst := filepath.Join(root, "dir", "destination")
			edited := dst
			expectedDst := "new offline user data"
			if move {
				// The old source still exists at the published MOVE destination.
				// A new file is created at its now-vacant original name while stopped.
				edited = filepath.Join(root, "source")
				expectedDst = "original source"
			}
			atomicRecoveryEdit(t, edited, "new offline user data")
			err := RecoverLocked(root)
			if err == nil {
				t.Fatal("recovery accepted an offline namespace change")
			}
			body, readErr := os.ReadFile(dst)
			if readErr != nil || string(body) != expectedDst {
				t.Errorf("recovery discarded existing data: got %q (%v), want %q", body, readErr, expectedDst)
			}
			if move {
				wantBody(t, edited, "new offline user data")
			}
		})
	}
}

func TestReplacementRecoveryRejectsOutsideParent(t *testing.T) {
	root := interruptedReplacement(t, false)
	original := filepath.Join(root, "dir")
	outside := filepath.Join(t.TempDir(), "relocated-dir")
	if err := os.Rename(original, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, original); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(outside, "destination")
	before, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	err = RecoverLocked(root)
	if err == nil {
		t.Errorf("recovery accepted a symlink parent outside sync root")
	}
	after, readErr := os.ReadFile(dst)
	if readErr != nil || string(after) != string(before) {
		t.Errorf("recovery mutated outside file: before=%q after=%q err=%v", before, after, readErr)
	}
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(outside, original); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := RecoverLocked(root); err != nil {
			t.Fatal(err)
		}
	}
	wantBody(t, filepath.Join(original, "destination"), "original destination")
}

func TestReplacementRecoveryAfterRootRelocation(t *testing.T) {
	root := interruptedReplacement(t, false)
	relocated := filepath.Join(filepath.Dir(root), "new-mount")
	if err := os.Rename(root, relocated); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(relocated); err != nil {
		t.Fatalf("relocated root cannot recover: %v", err)
	}
	wantBody(t, filepath.Join(relocated, "dir", "destination"), "original destination")
}
