package sebastian_test

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/gateway/httpui"
	"github.com/solkin/sebastian/internal/gateway/s3"
	"github.com/solkin/sebastian/internal/gateway/webdav"
)

// TestCrossProtocol uploads a file via S3, then reads it via WebDAV and HTTP UI
// to verify cross-protocol consistency.
func TestCrossProtocol(t *testing.T) {
	rootDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	s3Addr := freeAddr(t)
	webdavAddr := freeAddr(t)
	httpAddr := freeAddr(t)

	s3gw := s3.New(rootDir, s3.Config{ListenAddr: s3Addr}, logger)
	webdavgw := webdav.New(rootDir, webdav.Config{ListenAddr: webdavAddr}, logger)
	httpgw := httpui.New(rootDir, httpui.Config{ListenAddr: httpAddr}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go s3gw.Start(ctx)
	go webdavgw.Start(ctx)
	go httpgw.Start(ctx)

	waitReady(t, s3Addr)
	waitReady(t, webdavAddr)
	waitReady(t, httpAddr)

	// 1. Create bucket via S3.
	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/testbucket", s3Addr), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create bucket: expected 200, got %d", resp.StatusCode)
	}

	// 2. Upload file via S3.
	content := "hello cross-protocol"
	req, _ = http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/testbucket/hello.txt", s3Addr), strings.NewReader(content))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put object: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put object: expected 200, got %d", resp.StatusCode)
	}

	// 3. Read via WebDAV GET.
	resp, err = http.Get(fmt.Sprintf("http://%s/testbucket/hello.txt", webdavAddr))
	if err != nil {
		t.Fatalf("webdav get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webdav get: expected 200, got %d", resp.StatusCode)
	}
	if string(body) != content {
		t.Fatalf("webdav content mismatch: %q vs %q", string(body), content)
	}

	// 4. Read via HTTP UI download.
	resp, err = http.Get(fmt.Sprintf("http://%s/_api/dl/testbucket/hello.txt", httpAddr))
	if err != nil {
		t.Fatalf("http dl: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("http dl: expected 200, got %d", resp.StatusCode)
	}
	if string(body) != content {
		t.Fatalf("http content mismatch: %q vs %q", string(body), content)
	}

	// 5. List bucket via S3 — verify object appears.
	resp, err = http.Get(fmt.Sprintf("http://%s/testbucket", s3Addr))
	if err != nil {
		t.Fatalf("list objects: %v", err)
	}
	listBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(listBody), "hello.txt") {
		t.Fatal("hello.txt not found in S3 listing")
	}

	// 6. PROPFIND via WebDAV — verify file appears.
	req, _ = http.NewRequest("PROPFIND", fmt.Sprintf("http://%s/testbucket/", webdavAddr), nil)
	req.Header.Set("Depth", "1")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("propfind: %v", err)
	}
	propBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("propfind: expected 207, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(propBody), "hello.txt") {
		t.Fatal("hello.txt not found in WebDAV PROPFIND")
	}

	// 7. Delete via WebDAV.
	req, _ = http.NewRequest(http.MethodDelete, fmt.Sprintf("http://%s/testbucket/hello.txt", webdavAddr), nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("webdav delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("webdav delete: expected 204, got %d", resp.StatusCode)
	}

	// 8. Confirm deletion via S3 GET.
	resp, err = http.Get(fmt.Sprintf("http://%s/testbucket/hello.txt", s3Addr))
	if err != nil {
		t.Fatalf("s3 get after delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("s3 get after delete: expected 404, got %d", resp.StatusCode)
	}

	// 9. S3 ListBuckets — verify bucket exists.
	resp, err = http.Get(fmt.Sprintf("http://%s/", s3Addr))
	if err != nil {
		t.Fatalf("list buckets: %v", err)
	}
	bucketsBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	type listBucketsResult struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Buckets struct {
			Bucket []struct {
				Name string `xml:"Name"`
			} `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	var bucketsResult listBucketsResult
	xml.Unmarshal(bucketsBody, &bucketsResult)
	found := false
	for _, b := range bucketsResult.Buckets.Bucket {
		if b.Name == "testbucket" {
			found = true
		}
	}
	if !found {
		t.Fatal("testbucket not found in S3 ListBuckets")
	}

	// Cleanup.
	cancel()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	s3gw.Stop(shutCtx)
	webdavgw.Stop(shutCtx)
	httpgw.Stop(shutCtx)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s not ready", addr)
}

// TestFileVisibleAcrossProtocols creates a file directly on disk and verifies
// it's visible through all HTTP-based protocols.
func TestFileVisibleAcrossProtocols(t *testing.T) {
	rootDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	s3Addr := freeAddr(t)
	webdavAddr := freeAddr(t)
	httpAddr := freeAddr(t)

	s3gw := s3.New(rootDir, s3.Config{ListenAddr: s3Addr}, logger)
	webdavgw := webdav.New(rootDir, webdav.Config{ListenAddr: webdavAddr}, logger)
	httpgw := httpui.New(rootDir, httpui.Config{ListenAddr: httpAddr}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go s3gw.Start(ctx)
	go webdavgw.Start(ctx)
	go httpgw.Start(ctx)

	waitReady(t, s3Addr)
	waitReady(t, webdavAddr)
	waitReady(t, httpAddr)

	// Create files directly on disk.
	os.MkdirAll(rootDir+"/mybucket/subdir", 0o755)
	os.WriteFile(rootDir+"/mybucket/subdir/test.txt", []byte("disk file"), 0o644)

	// S3: get object.
	resp, _ := http.Get(fmt.Sprintf("http://%s/mybucket/subdir/test.txt", s3Addr))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "disk file" {
		t.Fatalf("s3 content: %q", string(body))
	}

	// WebDAV: get file.
	resp, _ = http.Get(fmt.Sprintf("http://%s/mybucket/subdir/test.txt", webdavAddr))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "disk file" {
		t.Fatalf("webdav content: %q", string(body))
	}

	// HTTP UI: download.
	resp, _ = http.Get(fmt.Sprintf("http://%s/_api/dl/mybucket/subdir/test.txt", httpAddr))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "disk file" {
		t.Fatalf("http content: %q", string(body))
	}

	cancel()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	s3gw.Stop(shutCtx)
	webdavgw.Stop(shutCtx)
	httpgw.Stop(shutCtx)
}
