package multipart

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestCreateReportsDirectoryFlushFailures(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(fmt.Sprint("parent=", parent), func(t *testing.T) {
			s, _ := testStore(t, Limits{})
			failure := errors.New("injected directory I/O error")
			realSync := s.syncDirectory
			s.syncDirectory = func(dir string) error {
				if (dir == s.stagingDir) == parent {
					return failure
				}
				return realSync(dir)
			}
			if _, err := s.Create("bucket", "object"); !errors.Is(err, failure) {
				t.Fatalf("acknowledged unflushed upload: %v", err)
			}
		})
	}
}

func TestPartFlushFailurePreservesAcknowledgedPredecessor(t *testing.T) {
	s, _ := testStore(t, Limits{})
	up, err := s.Create("bucket", "object")
	if err != nil {
		t.Fatal(err)
	}
	previous, err := s.WritePart(up.ID, 1, bytes.NewBufferString("previous"), Checksums{})
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("injected directory I/O error")
	s.syncDirectory = func(string) error { return failure }
	if _, err = s.WritePart(up.ID, 1, bytes.NewBufferString("replacement"), Checksums{}); !errors.Is(err, failure) {
		t.Fatalf("acknowledged unflushed part: %v", err)
	}
	parts, _, _, err := s.ListParts(up.ID, 0, 1000)
	if err != nil || len(parts) != 1 || parts[0].ETag != previous.ETag {
		t.Fatalf("lost acknowledged predecessor: %v %v", parts, err)
	}
}

func TestStoreCreatesAndPersistsMissingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing", "root")
	store, err := New(root, Limits{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("bucket", "object"); err != nil {
		t.Fatal(err)
	}
}
