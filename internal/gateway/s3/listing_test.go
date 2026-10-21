package s3

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemListingBeyond100000Objects(t *testing.T) {
	g, root := testGateway(t, Config{})
	bucket := filepath.Join(root, "bucket")
	if err := os.Mkdir(bucket, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100001; i++ {
		f, err := os.OpenFile(filepath.Join(bucket, fmt.Sprintf("%06d.txt", i)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	first := serveRequest(g, http.MethodGet, "/bucket?list-type=2&start-after=099998.txt&max-keys=1", nil, nil)
	var v2 ListBucketResultV2
	if err := xml.Unmarshal(first.Body.Bytes(), &v2); err != nil {
		t.Fatal(err)
	}
	if first.Code != 200 || len(v2.Contents) != 1 || v2.Contents[0].Key != "099999.txt" || !v2.IsTruncated || v2.NextContinuationToken != "099999.txt" {
		t.Fatalf("first V2 page: %d %+v", first.Code, v2)
	}
	last := serveRequest(g, http.MethodGet, "/bucket?list-type=2&continuation-token=099999.txt&start-after=zzzz&max-keys=1", nil, nil)
	v2 = ListBucketResultV2{}
	if err := xml.Unmarshal(last.Body.Bytes(), &v2); err != nil {
		t.Fatal(err)
	}
	if last.Code != 200 || len(v2.Contents) != 1 || v2.Contents[0].Key != "100000.txt" || v2.IsTruncated {
		t.Fatalf("last V2 page: %d %+v", last.Code, v2)
	}
	v1Response := serveRequest(g, http.MethodGet, "/bucket?marker=099999.txt&max-keys=2", nil, nil)
	var v1 ListBucketResultV1
	if err := xml.Unmarshal(v1Response.Body.Bytes(), &v1); err != nil {
		t.Fatal(err)
	}
	if v1Response.Code != 200 || len(v1.Contents) != 1 || v1.Contents[0].Key != "100000.txt" || v1.IsTruncated {
		t.Fatalf("last V1 page: %d %+v", v1Response.Code, v1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, err := g.filesystemPage(ctx, bucket, "", "", "", 1); err == nil {
		t.Fatal("cancelled listing continued")
	}
}

func TestFilesystemPagesOrderObjectsAndDeduplicatePrefixes(t *testing.T) {
	g, root := testGateway(t, Config{})
	for _, key := range []string{"a/file", "a/other", "a.txt", "b/file", "b/other", "z.txt"} {
		path := filepath.Join(root, "bucket", filepath.FromSlash(key))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(key), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bucket := filepath.Join(root, "bucket")
	objects, prefixes, truncated, next, err := g.filesystemPage(context.Background(), bucket, "", "/", "", 2)
	if err != nil || len(objects) != 1 || objects[0].Key != "a.txt" || len(prefixes) != 1 || prefixes[0].Prefix != "a/" || !truncated || next != "a/" {
		t.Fatalf("first mixed page: %v %v %v %q %v", objects, prefixes, truncated, next, err)
	}
	objects, prefixes, truncated, _, err = g.filesystemPage(context.Background(), bucket, "", "/", next, 2)
	if err != nil || len(objects) != 1 || objects[0].Key != "z.txt" || len(prefixes) != 1 || prefixes[0].Prefix != "b/" || truncated {
		t.Fatalf("last mixed page: %v %v %v %v", objects, prefixes, truncated, err)
	}
}
