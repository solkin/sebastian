package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNamespace_ReservedSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ReservedDirName, "multipart"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, ReservedDirName), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SafePath(root, "alias/multipart/state"); err == nil {
		t.Fatal("symlink bypassed reserved namespace")
	}
}
