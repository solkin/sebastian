package s3

import (
	"encoding/xml"
	"github.com/solkin/sebastian/internal/gateway"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListHidesScratchDirectories(t *testing.T) {
	g, root := testGateway(t, Config{})
	for _, dir := range []string{"bucket", ".seb-tmp-stage", "bucket/.seb-bak-tree", "bucket/nested/.seb-tmp-stage"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"bucket/visible.txt", "bucket/.seb-bak-tree/secret.txt", "bucket/nested/.seb-tmp-stage/secret.txt"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, url := range []string{"/", "/bucket", "/bucket?list-type=2", "/bucket?list-type=2&delimiter=/"} {
		w := serveRequest(g, http.MethodGet, url, nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", url, w.Code, w.Body.String())
		}
		for _, hidden := range []string{".seb-tmp-stage", ".seb-bak-tree", "secret.txt", "nested/"} {
			if strings.Contains(w.Body.String(), hidden) {
				t.Fatalf("%s exposed %s: %s", url, hidden, w.Body.String())
			}
		}
	}
}

func TestNestedStateDirectoryIsAnOrdinaryObjectPrefix(t *testing.T) {
	g, root := testGateway(t, Config{})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0755); err != nil {
		t.Fatal(err)
	}
	key := gateway.ReservedDirName + "/ordinary.txt"
	w := serveRequest(g, http.MethodPut, "/bucket/"+key, strings.NewReader("ordinary"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("nested state name is not reserved: %d %s", w.Code, w.Body.String())
	}
	w = serveRequest(g, http.MethodGet, "/bucket?list-type=2", nil, nil)
	var list ListBucketResultV2
	if err := xml.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Contents) != 1 || list.Contents[0].Key != key {
		t.Fatalf("ordinary nested directory not listed: %s", w.Body.String())
	}
	w = serveRequest(g, http.MethodGet, "/bucket/"+key, nil, nil)
	if w.Code != http.StatusOK || w.Body.String() != "ordinary" {
		t.Fatalf("ordinary nested read: %d %s", w.Code, w.Body.String())
	}
}

func TestScratchRoutingMatchesAddressStyles(t *testing.T) {
	g, root := testGateway(t, Config{Domain: "files.example"})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, hosted := range []bool{false, true} {
		for _, tc := range []struct{ bucket, key, code string }{{".seb-tmp-bucket", "", "InvalidBucketName"}, {"bucket", ".seb-tmp-object", "InvalidArgument"}, {"bucket", "nested/.seb-bak-tree/object", "InvalidArgument"}} {
			path := "/" + tc.bucket + "/" + tc.key
			headers := map[string]string{}
			if hosted {
				path = "/" + tc.key
				headers["Host"] = tc.bucket + ".files.example"
			}
			w := serveRequest(g, http.MethodGet, path, nil, headers)
			if w.Code != http.StatusBadRequest || errorCode(t, w) != tc.code {
				t.Fatalf("hosted=%v %s: %d %s", hosted, path, w.Code, w.Body.String())
			}
		}
	}
}
