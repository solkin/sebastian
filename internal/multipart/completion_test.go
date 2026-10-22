package multipart

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// completedUpload completes a one-part upload of bucket/obj and returns its
// part list, destination and result.
func completedUpload(t *testing.T, s *Store, root string) ([]CompletePart, string, CompleteResult) {
	t.Helper()
	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatal(err)
	}
	list := writeParts(t, s, up.ID, [][]byte{[]byte("payload")})
	dest := filepath.Join(root, "bucket", "obj")
	res, err := s.Complete(up.ID, list, dest)
	if err != nil {
		t.Fatal(err)
	}
	return list, dest, res
}

// TestCompletionRecordExpires drops the record of a completion past the upload
// TTL, after which a retry is NoSuchUpload, and leaves the object alone.
func TestCompletionRecordExpires(t *testing.T) {
	s, root := testStore(t, Limits{UploadTTL: time.Hour})
	list, dest, first := completedUpload(t, s, root)
	id := firstRecord(t, s)

	s.Cleanup(time.Now())
	if again, err := s.Complete(id, list, dest); err != nil || !again.Repeated || again.ETag != first.ETag {
		t.Fatalf("fresh record not honoured: %+v %v", again, err)
	}

	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(s.completionPath(id), old, old); err != nil {
		t.Fatal(err)
	}
	s.Cleanup(time.Now())
	if _, err := os.Stat(s.completionPath(id)); !os.IsNotExist(err) {
		t.Fatalf("expired record kept: %v", err)
	}
	if _, err := s.Complete(id, list, dest); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("complete after expiry: %v", err)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "payload" {
		t.Fatalf("object touched by cleanup: %q %v", got, err)
	}
}

// TestCompletionRecordIsNotAnUpload keeps records out of everything that
// counts or lists uploads.
func TestCompletionRecordIsNotAnUpload(t *testing.T) {
	s, root := testStore(t, Limits{MaxActiveUploads: 1})
	completedUpload(t, s, root)
	if ups, _, err := s.List("bucket", "", "", "", 0); err != nil || len(ups) != 0 {
		t.Fatalf("listed: %v %v", ups, err)
	}
	if has, err := s.HasUploads("bucket"); err != nil || has {
		t.Fatalf("HasUploads = %v %v", has, err)
	}
	if _, err := s.Create("bucket", "next"); err != nil {
		t.Fatalf("record counted against the active-upload cap: %v", err)
	}
}

// TestCompleteIfRefusalKeepsUpload refuses a completion whose precondition
// fails at publication, and keeps the upload so the client can retry.
func TestCompleteIfRefusalKeepsUpload(t *testing.T) {
	s, root := testStore(t, Limits{})
	dest := filepath.Join(root, "bucket", "obj")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatal(err)
	}
	list := writeParts(t, s, up.ID, [][]byte{[]byte("payload")})
	refused := errors.New("refused")
	var seen os.FileInfo
	_, err = s.CompleteIf(up.ID, list, dest, func(current os.FileInfo, err error) error {
		seen = current
		return refused
	})
	if !errors.Is(err, refused) || seen == nil || seen.Size() != int64(len("existing")) {
		t.Fatalf("CompleteIf = %v, saw %v", err, seen)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, []byte("existing")) {
		t.Fatalf("refused completion replaced the object: %q", got)
	}
	if _, err := s.Get(up.ID); err != nil {
		t.Fatalf("refused completion dropped the upload: %v", err)
	}
	res, err := s.Complete(up.ID, list, dest)
	if err != nil || res.Info == nil || res.Info.Size() != int64(len("payload")) {
		t.Fatalf("retry: %+v %v", res, err)
	}
	if info, err := os.Stat(dest); err != nil || !info.ModTime().Equal(res.Info.ModTime()) {
		t.Fatalf("result does not describe the published object: %v", err)
	}
}

func firstRecord(t *testing.T, s *Store) string {
	t.Helper()
	entries, err := os.ReadDir(s.completedDir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("completion records: %v %v", entries, err)
	}
	id := entries[0].Name()
	return id[:len(id)-len(".json")]
}
