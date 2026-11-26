package sftp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDanglingSymlinkOpenRefused(t *testing.T) {
	rootDir := t.TempDir()
	outside := t.TempDir()
	escapeTarget := filepath.Join(outside, "pwned.txt")
	if err := os.Symlink(escapeTarget, filepath.Join(rootDir, "escape")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	addr := testGateway(t, rootDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/escape")
	req = marshalUint32(req, sshFxfWrite|sshFxfCreat|sshFxfTrunc)
	req = marshalUint32(req, 0)
	writePacket(ch, sshFxpOpen, req)

	pktType, payload, err := readPacket(ch)
	if err != nil || pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got type=%d err=%v", pktType, err)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxPermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED for dangling symlink, got %d", code)
	}
	if _, err := os.Stat(escapeTarget); !os.IsNotExist(err) {
		t.Fatalf("dangling symlink allowed file creation outside root: %v", err)
	}
}

func TestTruncateEnforcesMaxUploadBytes(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, "f.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startGateway(t, rootDir, Config{
		Username:       "user",
		Password:       "pass",
		MaxUploadBytes: 16,
	})
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/f.txt")
	req = marshalUint32(req, sshFileXferAttrSize)
	req = marshalUint64(req, 32)
	writePacket(ch, sshFxpSetstat, req)
	pktType, payload, err := readPacket(ch)
	if err != nil || pktType != sshFxpStatus {
		t.Fatalf("SETSTAT: type=%d err=%v", pktType, err)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxFailure {
		t.Fatalf("expected FAILURE for oversized SETSTAT truncate, got %d", code)
	}

	handle := sftpOpenFile(t, ch, 2, "/f.txt", sshFxfRead|sshFxfWrite)
	req = nil
	req = marshalUint32(req, 3)
	req = marshalString(req, handle)
	req = marshalUint32(req, sshFileXferAttrSize)
	req = marshalUint64(req, 100)
	writePacket(ch, sshFxpFsetstat, req)
	pktType, payload, err = readPacket(ch)
	if err != nil || pktType != sshFxpStatus {
		t.Fatalf("FSETSTAT: type=%d err=%v", pktType, err)
	}
	_, rest, _ = unmarshalUint32(payload)
	code, _, _ = unmarshalUint32(rest)
	if code != sshFxFailure {
		t.Fatalf("expected FAILURE for oversized FSETSTAT truncate, got %d", code)
	}
	sftpClose(t, ch, 4, handle)
}

func TestRealpathCollapsesParentRefsAndRenameRootRefused(t *testing.T) {
	rootDir := t.TempDir()
	addr := testGateway(t, rootDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	for i, tc := range []struct{ in, want string }{
		{"../../etc/passwd", "/etc/passwd"},
		{"../..", "/"},
		{"a/b/../c", "/a/c"},
	} {
		var req []byte
		req = marshalUint32(req, uint32(i+1))
		req = marshalString(req, tc.in)
		writePacket(ch, sshFxpRealpath, req)
		pktType, payload, err := readPacket(ch)
		if err != nil || pktType != sshFxpName {
			t.Fatalf("REALPATH %q: type=%d err=%v", tc.in, pktType, err)
		}
		_, rest, _ := unmarshalUint32(payload)
		_, rest, _ = unmarshalUint32(rest)
		got, _, _ := unmarshalString(rest)
		if got != tc.want {
			t.Errorf("REALPATH %q = %q, want %q", tc.in, got, tc.want)
		}
	}

	var req []byte
	req = marshalUint32(req, 10)
	req = marshalString(req, "/")
	req = marshalString(req, "/moved")
	writePacket(ch, sshFxpRename, req)
	pktType, payload, err := readPacket(ch)
	if err != nil || pktType != sshFxpStatus {
		t.Fatalf("RENAME root: type=%d err=%v", pktType, err)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxPermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED renaming root, got %d", code)
	}
}

func TestStopForceClosesIdleConnections(t *testing.T) {
	rootDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw, err := New(rootDir, Config{
		ListenAddr:  "127.0.0.1:0",
		Username:    "user",
		Password:    "pass",
		HostKeyPath: filepath.Join(t.TempDir(), "host_key"),
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	startDone := make(chan error, 1)
	go func() { startDone <- gw.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	var addr string
	for time.Now().Before(deadline) {
		gw.mu.Lock()
		if gw.listener != nil {
			addr = gw.listener.Addr().String()
		}
		gw.mu.Unlock()
		if addr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		cancel()
		t.Fatal("SFTP gateway did not start")
	}

	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stopCancel()
	err = gw.Stop(stopCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded with active connection, got %v", err)
	}
	if err := gw.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}
	<-startDone
}
