package s3

import (
	"os"
	"path/filepath"
	"testing"
)

// Buckets named at startup are made when missing; one that exists keeps what
// it holds.
func TestCreateBuckets(t *testing.T) {
	g, root := testGateway(t, Config{})
	bucketWithFiles(t, root, "existing", "keep.txt")

	if err := g.CreateBuckets([]string{"existing", "backups", "backups"}); err != nil {
		t.Fatalf("create buckets: %v", err)
	}
	if info, err := os.Stat(filepath.Join(root, "backups")); err != nil || !info.IsDir() {
		t.Fatalf("backups bucket not created: %v", err)
	}
	if !exists(filepath.Join(root, "existing", "keep.txt")) {
		t.Fatal("an existing bucket lost its contents")
	}
}

// A name that could not be a bucket, or is taken by a file, stops startup
// rather than being skipped.
func TestCreateBuckets_RefusesWhatCannotBeABucket(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.WriteFile(filepath.Join(root, "taken"), []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"", "..", "a/b", ".sebastian", ".seb-tmp-bucket", "taken"} {
		if err := g.CreateBuckets([]string{name}); err == nil {
			t.Fatalf("bucket %q was accepted", name)
		}
	}
	if exists(filepath.Join(root, ".seb-tmp-bucket")) {
		t.Fatal("a scratch name became a directory")
	}
}
