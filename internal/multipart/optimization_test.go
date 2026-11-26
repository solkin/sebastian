package multipart

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/fileops"
)

func TestWritePartSupersedeCacheAcrossRestart(t *testing.T) {
	s, root := testStore(t, Limits{})
	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatal(err)
	}

	p1, err := s.WritePart(up.ID, 1, bytes.NewBufferString("v1"), Checksums{})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s.WritePart(up.ID, 1, bytes.NewBufferString("v2"), Checksums{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.uploadDir(up.ID), partFileName(1, p1.ETag))); !os.IsNotExist(err) {
		t.Fatalf("superseded part v1 still on disk: %v", err)
	}

	restarted, err := New(root, Limits{}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	p3, err := restarted.WritePart(up.ID, 1, bytes.NewBufferString("v3"), Checksums{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(restarted.uploadDir(up.ID), partFileName(1, p2.ETag))); !os.IsNotExist(err) {
		t.Fatalf("superseded part v2 still on disk after restart: %v", err)
	}
	if _, err := os.Stat(filepath.Join(restarted.uploadDir(up.ID), partFileName(1, p3.ETag))); err != nil {
		t.Fatalf("latest part v3 missing: %v", err)
	}
}

func TestRemoveStagingEntryLeavesNoTrashAndRespectsRetention(t *testing.T) {
	s, _ := testStore(t, Limits{UploadTTL: time.Hour, TempFileMaxAge: time.Minute})
	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WritePart(up.ID, 1, bytes.NewBufferString("part-data"), Checksums{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Abort(up.ID); err != nil {
		t.Fatalf("Abort: %v", err)
	}

	entries, err := os.ReadDir(s.stagingDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix+"trash-") || e.Name() == up.ID {
			t.Fatalf("leftover entry after Abort: %s", e.Name())
		}
	}

	activeTrash := filepath.Join(s.stagingDir, tempPrefix+"trash-active")
	staleTrash := filepath.Join(s.stagingDir, tempPrefix+"trash-stale")
	for _, p := range []string{activeTrash, staleTrash} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		past := time.Now().Add(-5 * time.Minute)
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	fileops.RetainTemp(activeTrash)
	defer fileops.ReleaseTempPath(activeTrash)

	s.Cleanup(time.Now())
	if _, err := os.Stat(activeTrash); err != nil {
		t.Fatalf("retained active trash dir was swept: %v", err)
	}
	if _, err := os.Stat(staleTrash); !os.IsNotExist(err) {
		t.Fatalf("stale trash dir was not swept: %v", err)
	}
}
