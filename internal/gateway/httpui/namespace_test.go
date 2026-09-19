package httpui

import (
	"github.com/solkin/sebastian/internal/gateway"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNamespace_HTTPReservedSymlinkRead(t *testing.T) {
	g, root := newTestGateway(t, "", "")
	reserved := filepath.Join(root, gateway.ReservedDirName)
	if err := os.MkdirAll(reserved, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reserved, "state"), []byte("internal state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(reserved, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	w := serve(g, http.MethodGet, "/_api/dl/alias/state", nil, nil)
	if w.Code == 200 {
		t.Fatalf("reserved state is downloadable: %s", w.Body.String())
	}
}
func TestNamespace_HTTPScratchListing(t *testing.T) {
	g, root := newTestGateway(t, "", "")
	name := ".seb-tmp-upload"
	if err := os.WriteFile(filepath.Join(root, name), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	w := serve(g, http.MethodGet, "/_api/list", nil, nil)
	if w.Code != 200 {
		t.Fatalf("listing returned %d", w.Code)
	}
	if strings.Contains(w.Body.String(), name) {
		t.Fatalf("listing exposes scratch file: %s", w.Body.String())
	}
}
