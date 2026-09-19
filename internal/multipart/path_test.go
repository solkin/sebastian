package multipart

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCompleteOutsideViaSymlink(t *testing.T) {
	s, root := testStore(t, Limits{})
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	up, err := s.Create("bucket", "object")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.WritePart(up.ID, 1, bytes.NewReader([]byte("payload")), Checksums{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Complete(up.ID, []CompletePart{{Number: 1, ETag: p.ETag}}, filepath.Join(root, "alias", "object"))
	if err == nil {
		t.Fatal("multipart store published through a symlink outside root")
	}
}
