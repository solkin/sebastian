package s3

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractBucketFromHost_IPv6AndCaseInsensitive(t *testing.T) {
	g, _ := testGateway(t, Config{Domain: "Example.COM"})

	cases := []struct {
		host string
		want string
	}{
		{"[::1]:9200", ""},
		{"[::1]", ""},
		{"127.0.0.1:9200", ""},
		{"example.com:9200", ""},
		{"mybucket.example.com", "mybucket"},
		{"mybucket.EXAMPLE.COM:9200", "mybucket"},
		{"nested.bucket.Example.Com:443", "nested.bucket"},
	}
	for _, tc := range cases {
		if got := g.extractBucketFromHost(tc.host); got != tc.want {
			t.Errorf("extractBucketFromHost(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestDeleteBucketEmptinessCheck(t *testing.T) {
	g, rootDir := testGateway(t, Config{})
	bp := filepath.Join(rootDir, "bkt")
	if err := os.Mkdir(bp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bp, "obj"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := serveRequest(g, http.MethodDelete, "/bkt", nil, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("DELETE non-empty bucket = %d, want 409", w.Code)
	}
	if err := os.Remove(filepath.Join(bp, "obj")); err != nil {
		t.Fatal(err)
	}
	w = serveRequest(g, http.MethodDelete, "/bkt", nil, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE empty bucket = %d, want 204", w.Code)
	}
}
