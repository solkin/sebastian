package fileops

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestPublishIf decides a write against the destination as it is at
// publication: a refusal leaves both the destination and the scratch file, and
// a publication reports the stat of exactly what it published.
func TestPublishIf(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "object")
	scratch := filepath.Join(root, ".seb-tmp-scratch")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scratch, []byte("new bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	refused := errors.New("refused")
	var seen os.FileInfo
	if _, err := PublishIf(root, scratch, dest, func(current os.FileInfo, err error) error {
		seen = current
		return refused
	}); !errors.Is(err, refused) {
		t.Fatalf("refusal = %v", err)
	}
	if seen == nil || seen.Size() != 3 {
		t.Fatalf("precondition saw %v", seen)
	}
	if got, _ := os.ReadFile(dest); string(got) != "old" {
		t.Fatalf("refused write replaced the destination: %q", got)
	}
	if _, err := os.Stat(scratch); err != nil {
		t.Fatalf("refused write consumed the scratch file: %v", err)
	}

	info, err := PublishIf(root, scratch, dest, func(os.FileInfo, error) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(dest)
	if err != nil || !SameGeneration(info, current) {
		t.Fatalf("returned stat does not name the published file: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "new bytes" {
		t.Fatalf("published %q", got)
	}

	// A missing destination is reported to the precondition as such.
	if err := os.WriteFile(scratch, []byte("fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	var missing error
	if _, err := PublishIf(root, scratch, filepath.Join(root, "fresh"), func(_ os.FileInfo, err error) error {
		missing = err
		return nil
	}); err != nil || !os.IsNotExist(missing) {
		t.Fatalf("publish to a new name: %v, precondition saw %v", err, missing)
	}
}
