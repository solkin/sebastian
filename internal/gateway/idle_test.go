package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serveIdle runs handler behind LogMiddleware on a real listener, because
// deadlines only exist on real connections.
func serveIdle(t *testing.T, timeout time.Duration, handler http.HandlerFunc) string {
	t.Helper()
	previous := IdleTransferTimeout
	IdleTransferTimeout = timeout
	t.Cleanup(func() { IdleTransferTimeout = previous })
	srv := httptest.NewServer(LogMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)), handler))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// A client that sends part of a body and goes quiet used to hold the handler,
// its descriptor and its scratch file for as long as the connection lived.
func TestStalledUploadIsAbandoned(t *testing.T) {
	result := make(chan error, 1)
	addr := serveIdle(t, 300*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		result <- err
	})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PUT /x HTTP/1.1\r\nHost: test\r\nContent-Length: 1000\r\n\r\nabc")
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("a body that stopped arriving was read as complete")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled upload was not abandoned")
	}
}

// The bound is on silence, not duration: a slow upload that keeps moving
// finishes even though it takes several timeouts.
func TestSlowUploadThatKeepsMovingCompletes(t *testing.T) {
	addr := serveIdle(t, 400*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Committing after the body may take longer than the idle bound; the
		// client is merely waiting for the answer and must still get it.
		time.Sleep(time.Second)
		if r.Context().Err() != nil {
			http.Error(w, "request canceled", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%d", n)
	})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PUT /x HTTP/1.1\r\nHost: test\r\nContent-Length: 8\r\n\r\n")
	for i := 0; i < 8; i++ {
		time.Sleep(150 * time.Millisecond)
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "8" {
		t.Fatalf("slow upload: %d %q", resp.StatusCode, body)
	}
}

// A client that stops reading a large response no longer pins the handler.
func TestStalledDownloadIsAbandoned(t *testing.T) {
	result := make(chan error, 1)
	addr := serveIdle(t, 300*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("x"), 1<<16)
		for {
			if _, err := w.Write(chunk); err != nil {
				result <- err
				return
			}
		}
	})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /x HTTP/1.1\r\nHost: test\r\n\r\n")
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("write to a stalled client reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a response nobody reads was not abandoned")
	}
}

func TestLogMiddlewareRecordsTimingAndRemote(t *testing.T) {
	var log bytes.Buffer
	handler := LogMiddleware(slog.New(slog.NewJSONHandler(&log, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("GET", "/ok", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	var record map[string]any
	if err := json.Unmarshal(bytes.SplitN(log.Bytes(), []byte("\n"), 2)[0], &record); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"duration_ms", "remote", "forwarded_for"} {
		if _, ok := record[field]; !ok {
			t.Fatalf("access log lacks %s: %v", field, record)
		}
	}

	log.Reset()
	SetAccessLog(false)
	t.Cleanup(func() { SetAccessLog(true) })
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/ok", nil))
	if log.Len() != 0 {
		t.Fatalf("access log written while disabled: %s", log.String())
	}
}

func TestReservedNamesInEverySpelling(t *testing.T) {
	for _, p := range []string{".SEBASTIAN", ".Sebastian/multipart", "bucket/.SEB-TMP-upload", "bucket/.Seb-Bak-x", "bucket/a\x00b"} {
		if _, _, err := SafePath("/data", p); err == nil {
			t.Errorf("SafePath(%q) resolved a reserved or invalid name", p)
		}
	}
	if !IsReserved(".SEBASTIAN") || !IsReservedPath("/data", "/data/.Sebastian") {
		t.Fatal("another spelling of the state directory is not reserved")
	}
	if ClientVisibleName("", ".SEBASTIAN") || ClientVisibleName("bucket", ".SEB-TMP-x") || !ClientVisibleName("bucket", ".sebastianish") {
		t.Fatal("ClientVisibleName disagrees with SafePath")
	}
	if _, _, err := SafePath("/data", "bucket/.sebastianish"); err != nil {
		t.Fatalf("an ordinary name was reserved: %v", err)
	}
}

func TestCheckBasicAuthHalfConfiguredAdmitsNobody(t *testing.T) {
	for _, pair := range [][2]string{{"admin", ""}, {"", "secret"}} {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth(pair[0], pair[1])
		if CheckBasicAuth(req, pair[0], pair[1]) {
			t.Fatalf("half-configured credentials %q admitted a client", pair)
		}
	}
}
