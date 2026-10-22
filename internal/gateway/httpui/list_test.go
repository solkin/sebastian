package httpui

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
)

// logRecords captures what a gateway logs, at every level.
type logRecords struct {
	mu      sync.Mutex
	records []slog.Record
}

func (l *logRecords) Enabled(context.Context, slog.Level) bool { return true }
func (l *logRecords) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, r.Clone())
	return nil
}
func (l *logRecords) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logRecords) WithGroup(string) slog.Handler      { return l }

// find returns the first record with this message, if any.
func (l *logRecords) find(msg string) (slog.Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.records {
		if r.Message == msg {
			return r, true
		}
	}
	return slog.Record{}, false
}

// waitFor waits for a record with this message.
func (l *logRecords) waitFor(t *testing.T, msg string) slog.Record {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := l.find(msg); ok {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q record logged; got %v", msg, l.messages())
	return slog.Record{}
}

func (l *logRecords) errors() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, r := range l.records {
		if r.Level >= slog.LevelError {
			out = append(out, r.Message)
		}
	}
	return out
}

func (l *logRecords) messages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, r := range l.records {
		out = append(out, r.Level.String()+" "+r.Message)
	}
	return out
}

// newLoggedGateway is newTestGatewayWithConfig with every log record captured.
func newLoggedGateway(t *testing.T, cfg Config) (*Gateway, string, *logRecords) {
	t.Helper()
	dir := t.TempDir()
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":0"
	}
	logs := &logRecords{}
	return New(dir, cfg, slog.New(logs)), dir, logs
}

func listPage(t *testing.T, g *Gateway, query string) listResponse {
	t.Helper()
	w := serve(g, http.MethodGet, "/_api/list?"+query, nil, noAuth())
	if w.Code != http.StatusOK {
		t.Fatalf("list %s: status %d: %s", query, w.Code, w.Body.String())
	}
	var resp listResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse listing: %v", err)
	}
	return resp
}

// The page is cut from directories first, then everything else, each in byte
// order of the name — the order os.ReadDir gave the listing before.
func TestList_PageAcrossDirsAndFiles(t *testing.T) {
	g, dir := newTestGateway(t, "", "")
	for _, d := range []string{"b-dir", "a-dir"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"a.txt", "B.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a.txt", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	resp := listPage(t, g, "path=&offset=1&limit=3")
	if resp.Total != 6 {
		t.Fatalf("total = %d, want 6", resp.Total)
	}
	var got []string
	for _, e := range resp.Entries {
		got = append(got, fmt.Sprintf("%s:%v:%d", e.Name, e.IsDir, e.Size))
		if _, err := time.Parse(time.RFC3339, e.ModTime); err != nil {
			t.Fatalf("mod_time %q: %v", e.ModTime, err)
		}
	}
	want := []string{"b-dir:true:" + fmt.Sprint(lstatSize(t, filepath.Join(dir, "b-dir"))), "B.txt:false:5", "a.txt:false:5"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("page = %v, want %v", got, want)
	}

	// A symlink is listed among the files, with the size of the link itself.
	last := listPage(t, g, "path=&offset=5&limit=10")
	if len(last.Entries) != 1 || last.Entries[0].Name != "link" || last.Entries[0].IsDir || last.Entries[0].Size != int64(len("a.txt")) {
		t.Fatalf("last page = %+v", last.Entries)
	}
}

func lstatSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// visibleName decides from the name alone what gateway.IsClientVisiblePath
// decides with a stat; the two must never disagree for a regular entry. The
// case variants are here so that a gateway rule that starts folding case is
// caught until visibleName follows it.
func TestList_VisibleNameMatchesGateway(t *testing.T) {
	g, root := newTestGateway(t, "", "")
	names := []string{
		"a.txt", ".sebastian", ".SEBASTIAN", ".sebastianx", ".SEB-TMP-x", ".Seb-Bak-x", ".seb-tmp-x", ".seb-tmp-", ".seb-bak-x", ".seb-tmpx", ".seb-bakx",
		".DS_Store", ".hidden", "..x", "a b", "дата.apk", "x.seb-tmp-",
	}
	for _, dirRel := range []string{"", "apps", "apps/icons"} {
		dirFull := filepath.Join(root, filepath.FromSlash(dirRel))
		if err := os.MkdirAll(dirFull, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			// One name at a time, so a case-insensitive volume cannot merge
			// two spellings into one entry.
			full := filepath.Join(dirFull, name)
			if err := os.WriteFile(full, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			want := gateway.IsClientVisiblePath(root, full)
			if got := g.visibleName(dirRel, name); got != want {
				t.Errorf("visibleName(%q, %q) = %v, IsClientVisiblePath = %v", dirRel, name, got, want)
			}
			os.Remove(full)
		}
	}
	// No directory entry can hold a NUL; it is never visible.
	if g.visibleName("", "a\x00b") {
		t.Error("a name with a NUL is visible")
	}
}

// A listing used to lstat every entry of the directory and keep it, so one
// page of a directory of hundreds of thousands of files cost seconds and
// hundreds of MiB. Only the page itself may cost more than the names.
func TestList_CostDoesNotGrowWithStatsPerEntry(t *testing.T) {
	g, dir := newTestGateway(t, "", "")
	icons := filepath.Join(dir, "icons")
	if err := os.Mkdir(icons, 0o755); err != nil {
		t.Fatal(err)
	}
	const n = 2000
	for i := 0; i < n; i++ {
		f, err := os.Create(filepath.Join(icons, fmt.Sprintf("com.example.app%07d.png", i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	allocs := testing.AllocsPerRun(5, func() {
		w := serve(g, http.MethodGet, "/_api/list?path=icons&limit=10", nil, noAuth())
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	})
	// Reading a name costs about three allocations (the entry, its name and
	// the kept slice); a stat per entry costs at least three more.
	if perEntry := allocs / n; perEntry > 4.5 {
		t.Fatalf("listing allocates %.1f times per directory entry, want at most 4.5 (%.0f in total)", perEntry, allocs)
	}
}

// Listings beyond maxConcurrentLists wait for a slot; one whose client gives
// up while waiting reads nothing.
func TestList_ConcurrencyIsBounded(t *testing.T) {
	g, dir := newTestGateway(t, "", "")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if cap(g.listSem) != maxConcurrentLists || maxConcurrentLists != 4 {
		t.Fatalf("listing slots = %d, want 4", cap(g.listSem))
	}
	for i := 0; i < cap(g.listSem); i++ {
		g.listSem <- struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/_api/list?path=", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.server.Handler.ServeHTTP(w, req)
	}()
	select {
	case <-done:
		t.Fatalf("listing ran with every slot taken: %d %s", w.Code, w.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	<-done
	if strings.Contains(w.Body.String(), "a.txt") {
		t.Fatalf("abandoned listing was served: %s", w.Body.String())
	}

	// A waiting listing proceeds as soon as a slot frees up.
	req = httptest.NewRequest(http.MethodGet, "/_api/list?path=", nil)
	w = httptest.NewRecorder()
	done = make(chan struct{})
	go func() {
		defer close(done)
		g.server.Handler.ServeHTTP(w, req)
	}()
	time.Sleep(20 * time.Millisecond)
	<-g.listSem
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("listing did not proceed after a slot was freed")
	}
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "a.txt") {
		t.Fatalf("listing: %d %s", w.Code, w.Body.String())
	}
}

// A symlink is shown only when where it leads may be shown: an alias of the
// reserved state directory or of a scratch file stays hidden.
func TestList_SymlinkVisibilityFollowsTarget(t *testing.T) {
	g, dir := newTestGateway(t, "", "")
	if err := os.MkdirAll(filepath.Join(dir, gateway.ReservedDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".seb-tmp-upload-1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"state": gateway.ReservedDirName, "partial": ".seb-tmp-upload-1", "ok": "a.txt"} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	for _, e := range listPage(t, g, "path=").Entries {
		names = append(names, e.Name)
	}
	if got := strings.Join(names, " "); got != "a.txt ok" {
		t.Fatalf("listing = %q, want %q", got, "a.txt ok")
	}
}
