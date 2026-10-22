package webdav

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A client that disconnects mid-upload is not a server failure: it is logged
// as an abort, nothing is published and no scratch file stays behind.
func TestPutAbortedByClientIsNotAnError(t *testing.T) {
	var log syncBuffer
	rootDir := t.TempDir()
	g := New(rootDir, Config{ListenAddr: ":0"}, slog.New(slog.NewTextHandler(&log, nil)))
	ts := httptest.NewServer(g.server.Handler)
	defer ts.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "PUT /file.apk HTTP/1.1\r\nHost: test\r\nContent-Length: 100000\r\n\r\npartial")
	time.Sleep(100 * time.Millisecond)
	conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(log.String(), "put aborted by client") {
		if time.Now().After(deadline) {
			t.Fatalf("abort not logged as such:\n%s", log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(log.String(), "level=ERROR") {
		t.Fatalf("client abort logged as an error:\n%s", log.String())
	}
	entries, _ := os.ReadDir(rootDir)
	for _, e := range entries {
		t.Errorf("left behind %s", filepath.Join(rootDir, e.Name()))
	}
}
