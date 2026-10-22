package sftp

import (
	"context"
	"golang.org/x/crypto/ssh"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func startGateway(t *testing.T, syncDir string, cfg Config) string {
	t.Helper()
	cfg.HostKeyPath = filepath.Join(t.TempDir(), "host_key")
	cfg.ListenAddr = "127.0.0.1:0"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	g, err := New(syncDir, cfg, logger)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	g.listener = ln
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		g.Stop(context.Background())
	})

	go func() {
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case g.connSem <- struct{}{}:
				g.wg.Add(1)
				go g.handleConnection(conn)
			default:
				conn.Close()
			}
		}
	}()

	return addr
}

func TestMaxUploadBytesEnforced(t *testing.T) {
	syncDir := t.TempDir()
	addr := startGateway(t, syncDir, Config{
		Username:       "user",
		Password:       "pass",
		MaxUploadBytes: 8,
	})
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpenFile(t, ch, 1, "/cap.txt", sshFxfWrite|sshFxfCreat|sshFxfTrunc)

	// Within cap: 8 bytes at offset 0 is allowed.
	sftpWriteFile(t, ch, 2, handle, 0, []byte("12345678"))

	// Over cap: writing one more byte at offset 8 pushes end to 9 > 8.
	var req []byte
	req = marshalUint32(req, 3)
	req = marshalString(req, handle)
	req = marshalUint64(req, 8)
	req = marshalBytes(req, []byte("9"))
	writePacket(ch, sshFxpWrite, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxFailure {
		t.Errorf("expected FAILURE for oversized write, got %d", code)
	}
	sftpClose(t, ch, 4, handle)
}

// A half-configured credential (a username without a password, or the
// reverse) admits nobody. It used to require the empty half literally, so a
// client sending the configured username with an empty password got in.
// Configuration validation refuses such a pair; this is defence in depth.
func TestAuthFailClosedHalfConfigured(t *testing.T) {
	for _, tc := range []struct {
		name, cfgUser, cfgPass string
		tries                  [][2]string // user, password
	}{
		{"username only", "user", "", [][2]string{{"user", ""}, {"user", "not-empty"}, {"", ""}}},
		{"password only", "", "pass", [][2]string{{"", "pass"}, {"user", "pass"}, {"", ""}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := testGateway(t, t.TempDir(), tc.cfgUser, tc.cfgPass)
			for _, try := range tc.tries {
				cfg := &ssh.ClientConfig{
					User:            try[0],
					Auth:            []ssh.AuthMethod{ssh.Password(try[1])},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         2 * time.Second,
				}
				conn, err := ssh.Dial("tcp", addr, cfg)
				if err == nil {
					conn.Close()
					t.Fatalf("user %q with password %q was admitted", try[0], try[1])
				}
			}
		})
	}
}

func TestZeroLengthRead(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "z.txt"), []byte("data"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpenFile(t, ch, 1, "/z.txt", sshFxfRead)
	data, eof := sftpReadFile(t, ch, 2, handle, 0, 0)
	if eof {
		t.Fatal("zero-length read should not report EOF")
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %q", data)
	}
	sftpClose(t, ch, 3, handle)
}
