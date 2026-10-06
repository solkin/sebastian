package s3

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestDeleteBucketPreservesIgnoredUserData(t *testing.T) {
	g, root := testGateway(t, Config{})

	if err := os.Mkdir(filepath.Join(root, "bucket"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "bucket", ".DS_Store")
	if err := os.WriteFile(path, []byte("irreplaceable"), 0600); err != nil {
		t.Fatal(err)
	}
	out := serveRequest(g, http.MethodDelete, "/bucket", nil, noAuth())
	if out.Code != http.StatusConflict {
		t.Fatalf("DeleteBucket: %d %s", out.Code, out.Body.String())
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "irreplaceable" {
		t.Fatalf("ignored data lost: %q %v", body, err)
	}
}
