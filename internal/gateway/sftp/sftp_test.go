package sftp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testGateway starts an SFTP gateway on a random port and returns its address.
func testGateway(t *testing.T, syncDir string, user, pass string) string {
	t.Helper()

	cfg := Config{
		ListenAddr:  "127.0.0.1:0",
		Username:    user,
		Password:    pass,
		HostKeyPath: filepath.Join(t.TempDir(), "host_key"),
	}

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
			g.wg.Add(1)
			go g.handleConnection(conn)
		}
	}()

	return addr
}

// sftpClient opens an SSH connection and starts the SFTP subsystem.
func sftpClient(t *testing.T, addr, user, pass string) ssh.Channel {
	t.Helper()

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	sess, err := conn.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("request subsystem: %v", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	ch := &sshPipe{w: stdin, r: stdout}
	return ch
}

// sshPipe adapts session stdin/stdout to look like an ssh.Channel for test helpers.
type sshPipe struct {
	w io.WriteCloser
	r io.Reader
}

func (p *sshPipe) Read(data []byte) (int, error)         { return p.r.Read(data) }
func (p *sshPipe) Write(data []byte) (int, error)        { return p.w.Write(data) }
func (p *sshPipe) Close() error                          { return p.w.Close() }
func (p *sshPipe) CloseWrite() error                     { return p.w.Close() }
func (p *sshPipe) SendRequest(string, bool, []byte) (bool, error) {
	return false, fmt.Errorf("not supported")
}
func (p *sshPipe) Stderr() io.ReadWriter { return nil }

// sftpInit sends SSH_FXP_INIT and reads SSH_FXP_VERSION.
func sftpInit(t *testing.T, ch io.ReadWriter) {
	t.Helper()
	var init []byte
	init = marshalUint32(init, sftpProtocolVersion)
	if err := writePacket(ch, sshFxpInit, init); err != nil {
		t.Fatalf("write init: %v", err)
	}
	pktType, _, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read version: %v", err)
	}
	if pktType != sshFxpVersion {
		t.Fatalf("expected VERSION, got %d", pktType)
	}
}

// sftpRealpath sends SSH_FXP_REALPATH and reads the result.
func sftpRealpath(t *testing.T, ch io.ReadWriter, path string) string {
	t.Helper()
	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, path)
	if err := writePacket(ch, sshFxpRealpath, req); err != nil {
		t.Fatalf("write realpath: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read realpath: %v", err)
	}
	if pktType != sshFxpName {
		t.Fatalf("expected NAME, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload) // id
	_, rest, _ = unmarshalUint32(rest)     // count
	name, _, _ := unmarshalString(rest)
	return name
}

// sftpStat sends SSH_FXP_STAT and reads the response.
func sftpStat(t *testing.T, ch io.ReadWriter, id uint32, path string) (byte, []byte) {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, path)
	if err := writePacket(ch, sshFxpStat, req); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read stat response: %v", err)
	}
	return pktType, payload
}

// sftpOpendir sends SSH_FXP_OPENDIR and returns the handle.
func sftpOpendir(t *testing.T, ch io.ReadWriter, id uint32, path string) string {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, path)
	if err := writePacket(ch, sshFxpOpendir, req); err != nil {
		t.Fatalf("write opendir: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read opendir: %v", err)
	}
	if pktType != sshFxpHandle {
		t.Fatalf("expected HANDLE, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	handle, _, _ := unmarshalString(rest)
	return handle
}

// sftpReaddir sends SSH_FXP_READDIR and returns names (or nil on EOF).
func sftpReaddir(t *testing.T, ch io.ReadWriter, id uint32, handle string) []string {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, handle)
	if err := writePacket(ch, sshFxpReaddir, req); err != nil {
		t.Fatalf("write readdir: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read readdir: %v", err)
	}
	if pktType == sshFxpStatus {
		return nil // EOF
	}
	if pktType != sshFxpName {
		t.Fatalf("expected NAME, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	count, rest, _ := unmarshalUint32(rest)
	var names []string
	for i := uint32(0); i < count; i++ {
		name, r, _ := unmarshalString(rest)
		_, r, _ = unmarshalString(r) // long name
		r, _ = unmarshalAttrs(r)     // attrs
		rest = r
		names = append(names, name)
	}
	return names
}

// sftpOpenFile opens a file and returns the handle.
func sftpOpenFile(t *testing.T, ch io.ReadWriter, id uint32, path string, flags uint32) string {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, path)
	req = marshalUint32(req, flags)
	req = marshalUint32(req, 0) // empty attrs
	if err := writePacket(ch, sshFxpOpen, req); err != nil {
		t.Fatalf("write open: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read open: %v", err)
	}
	if pktType == sshFxpStatus {
		_, rest, _ := unmarshalUint32(payload)
		code, rest, _ := unmarshalUint32(rest)
		msg, _, _ := unmarshalString(rest)
		t.Fatalf("open failed: code=%d msg=%s", code, msg)
	}
	if pktType != sshFxpHandle {
		t.Fatalf("expected HANDLE, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	handle, _, _ := unmarshalString(rest)
	return handle
}

// sftpWriteFile writes data at the given offset.
func sftpWriteFile(t *testing.T, ch io.ReadWriter, id uint32, handle string, offset uint64, data []byte) {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, handle)
	req = marshalUint64(req, offset)
	req = marshalBytes(req, data)
	if err := writePacket(ch, sshFxpWrite, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read write resp: %v", err)
	}
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOk {
		t.Fatalf("write failed: %d", code)
	}
}

// sftpReadFile reads data from a file handle at offset.
func sftpReadFile(t *testing.T, ch io.ReadWriter, id uint32, handle string, offset uint64, length uint32) ([]byte, bool) {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, handle)
	req = marshalUint64(req, offset)
	req = marshalUint32(req, length)
	if err := writePacket(ch, sshFxpRead, req); err != nil {
		t.Fatalf("read req: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if pktType == sshFxpStatus {
		return nil, true // EOF
	}
	if pktType != sshFxpData {
		t.Fatalf("expected DATA, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	data, _, _ := unmarshalString(rest)
	return []byte(data), false
}

// sftpClose closes a handle.
func sftpClose(t *testing.T, ch io.ReadWriter, id uint32, handle string) {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, handle)
	if err := writePacket(ch, sshFxpClose, req); err != nil {
		t.Fatalf("write close: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read close resp: %v", err)
	}
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOk {
		t.Fatalf("close failed: %d", code)
	}
}

// sftpMkdir creates a directory.
func sftpMkdir(t *testing.T, ch io.ReadWriter, id uint32, path string) uint32 {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, path)
	req = marshalUint32(req, 0) // empty attrs
	if err := writePacket(ch, sshFxpMkdir, req); err != nil {
		t.Fatalf("write mkdir: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read mkdir resp: %v", err)
	}
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	return code
}

// sftpRemove removes a file.
func sftpRemove(t *testing.T, ch io.ReadWriter, id uint32, path string) uint32 {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, path)
	if err := writePacket(ch, sshFxpRemove, req); err != nil {
		t.Fatalf("write remove: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read remove resp: %v", err)
	}
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	return code
}

// sftpRmdir removes a directory.
func sftpRmdir(t *testing.T, ch io.ReadWriter, id uint32, path string) uint32 {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, path)
	if err := writePacket(ch, sshFxpRmdir, req); err != nil {
		t.Fatalf("write rmdir: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read rmdir resp: %v", err)
	}
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	return code
}

// sftpRename renames a file.
func sftpRename(t *testing.T, ch io.ReadWriter, id uint32, oldPath, newPath string) uint32 {
	t.Helper()
	var req []byte
	req = marshalUint32(req, id)
	req = marshalString(req, oldPath)
	req = marshalString(req, newPath)
	if err := writePacket(ch, sshFxpRename, req); err != nil {
		t.Fatalf("write rename: %v", err)
	}
	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read rename resp: %v", err)
	}
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	return code
}

func TestFstat(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "fstat.txt"), []byte("hello"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpenFile(t, ch, 1, "/fstat.txt", sshFxfRead)

	var req []byte
	req = marshalUint32(req, 2)
	req = marshalString(req, handle)
	writePacket(ch, sshFxpFstat, req)

	pktType, payload, err := readPacket(ch)
	if err != nil {
		t.Fatal(err)
	}
	if pktType != sshFxpAttrs {
		t.Fatalf("expected ATTRS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	_, rest, _ = unmarshalUint32(rest) // flags
	size, _, _ := unmarshalUint64(rest)
	if size != 5 {
		t.Errorf("expected size 5, got %d", size)
	}

	sftpClose(t, ch, 3, handle)
}

func TestFstatInvalidHandle(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "nonexistent-handle")
	writePacket(ch, sshFxpFstat, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxFailure {
		t.Errorf("expected FAILURE, got %d", code)
	}
}

func TestStatFile(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "info.txt"), []byte("12345"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	pktType, payload := sftpStat(t, ch, 1, "/info.txt")
	if pktType != sshFxpAttrs {
		t.Fatalf("expected ATTRS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	_, rest, _ = unmarshalUint32(rest) // flags
	size, _, _ := unmarshalUint64(rest)
	if size != 5 {
		t.Errorf("expected size 5, got %d", size)
	}
}

func TestOpenNonExistentWithoutCreat(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/no-such-file.txt")
	req = marshalUint32(req, sshFxfRead)
	req = marshalUint32(req, 0)
	writePacket(ch, sshFxpOpen, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxNoSuchFile {
		t.Errorf("expected NO_SUCH_FILE, got %d", code)
	}
}

func TestRemoveDirectory(t *testing.T) {
	syncDir := t.TempDir()
	os.Mkdir(filepath.Join(syncDir, "adir"), 0o755)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRemove(t, ch, 1, "/adir")
	if code == sshFxOk {
		t.Error("expected failure when removing directory with REMOVE")
	}
}

func TestRemoveNonExistent(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRemove(t, ch, 1, "/ghost.txt")
	if code != sshFxNoSuchFile {
		t.Errorf("expected NO_SUCH_FILE, got %d", code)
	}
}

func TestRmdirRoot(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRmdir(t, ch, 1, "/")
	if code != sshFxPermissionDenied {
		t.Errorf("expected PERMISSION_DENIED for rmdir root, got %d", code)
	}
}

func TestRmdirNonEmpty(t *testing.T) {
	syncDir := t.TempDir()
	os.Mkdir(filepath.Join(syncDir, "full"), 0o755)
	os.WriteFile(filepath.Join(syncDir, "full", "child.txt"), []byte("x"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRmdir(t, ch, 1, "/full")
	if code == sshFxOk {
		t.Error("expected failure when rmdir on non-empty directory")
	}
}

func TestMkdirDuplicate(t *testing.T) {
	syncDir := t.TempDir()
	os.Mkdir(filepath.Join(syncDir, "existing"), 0o755)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpMkdir(t, ch, 1, "/existing")
	if code == sshFxOk {
		t.Error("expected failure when mkdir on existing directory")
	}
}

func TestReaddirEmptyDirectory(t *testing.T) {
	syncDir := t.TempDir()
	os.Mkdir(filepath.Join(syncDir, "empty"), 0o755)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpendir(t, ch, 1, "/empty")
	names := sftpReaddir(t, ch, 2, handle)
	if names != nil {
		t.Errorf("expected nil (EOF) for empty dir, got %v", names)
	}
}

func TestReaddirSecondCallEOF(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "a.txt"), []byte("a"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpendir(t, ch, 1, "/")
	names := sftpReaddir(t, ch, 2, handle)
	if len(names) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(names))
	}

	var req []byte
	req = marshalUint32(req, 3)
	req = marshalString(req, handle)
	writePacket(ch, sshFxpReaddir, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxEOF {
		t.Errorf("expected EOF on consumed handle, got %d", code)
	}
}

func TestWriteAtOffset(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpenFile(t, ch, 1, "/offset.txt", sshFxfWrite|sshFxfCreat|sshFxfTrunc)
	sftpWriteFile(t, ch, 2, handle, 0, []byte("AAAA"))
	sftpWriteFile(t, ch, 3, handle, 2, []byte("BB"))
	sftpClose(t, ch, 4, handle)

	data, _ := os.ReadFile(filepath.Join(syncDir, "offset.txt"))
	if string(data) != "AABB" {
		t.Errorf("expected AABB, got %q", data)
	}
}

func TestCloseInvalidHandle(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "bogus-handle")
	writePacket(ch, sshFxpClose, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxFailure {
		t.Errorf("expected FAILURE for invalid handle, got %d", code)
	}
}

func TestReadInvalidHandle(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "bad-handle")
	req = marshalUint64(req, 0)
	req = marshalUint32(req, 1024)
	writePacket(ch, sshFxpRead, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxFailure {
		t.Errorf("expected FAILURE for invalid handle, got %d", code)
	}
}

func TestWriteInvalidHandle(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "bad-handle")
	req = marshalUint64(req, 0)
	req = marshalString(req, "data")
	writePacket(ch, sshFxpWrite, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxFailure {
		t.Errorf("expected FAILURE for invalid handle, got %d", code)
	}
}

func TestRenameNonExistent(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRename(t, ch, 1, "/ghost.txt", "/new.txt")
	if code == sshFxOk {
		t.Error("expected failure renaming non-existent file")
	}
}

func TestOpendirOnFile(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "notadir.txt"), []byte("x"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/notadir.txt")
	writePacket(ch, sshFxpOpendir, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxNoSuchFile {
		t.Errorf("expected NO_SUCH_FILE for opendir on file, got %d", code)
	}
}

func TestRealpathRoot(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	result := sftpRealpath(t, ch, ".")
	if result != "/" {
		t.Errorf("expected /, got %q", result)
	}

	result = sftpRealpath(t, ch, "/foo/bar/../baz")
	if result != "/foo/baz" {
		t.Errorf("expected /foo/baz, got %q", result)
	}
}

func TestStatRoot(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	pktType, _ := sftpStat(t, ch, 1, "/")
	if pktType != sshFxpAttrs {
		t.Fatalf("expected ATTRS for root, got %d", pktType)
	}
}

func TestStatNonExistent(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	pktType, payload := sftpStat(t, ch, 1, "/nonexistent")
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxNoSuchFile {
		t.Errorf("expected NO_SUCH_FILE, got %d", code)
	}
}

func TestListDirectory(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "alpha.txt"), []byte("alpha"), 0o644)
	os.WriteFile(filepath.Join(syncDir, "beta.txt"), []byte("beta"), 0o644)
	os.Mkdir(filepath.Join(syncDir, "subdir"), 0o755)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpendir(t, ch, 1, "/")
	names := sftpReaddir(t, ch, 2, handle)
	if len(names) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(names), names)
	}
}

func TestReadWriteFile(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	content := []byte("hello sftp world")

	handle := sftpOpenFile(t, ch, 1, "/test.txt", sshFxfWrite|sshFxfCreat|sshFxfTrunc)
	sftpWriteFile(t, ch, 2, handle, 0, content)
	sftpClose(t, ch, 3, handle)

	data, err := os.ReadFile(filepath.Join(syncDir, "test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(content) {
		t.Errorf("disk content mismatch: %q vs %q", data, content)
	}

	handle = sftpOpenFile(t, ch, 4, "/test.txt", sshFxfRead)
	readData, eof := sftpReadFile(t, ch, 5, handle, 0, 1024)
	if eof {
		t.Fatal("unexpected EOF")
	}
	if string(readData) != string(content) {
		t.Errorf("read data mismatch: %q vs %q", readData, content)
	}

	_, eof = sftpReadFile(t, ch, 6, handle, uint64(len(content)), 1024)
	if !eof {
		t.Error("expected EOF")
	}
	sftpClose(t, ch, 7, handle)
}

func TestCreateSubdirectoryFile(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpenFile(t, ch, 1, "/sub/deep/file.txt", sshFxfWrite|sshFxfCreat|sshFxfTrunc)
	sftpWriteFile(t, ch, 2, handle, 0, []byte("nested"))
	sftpClose(t, ch, 3, handle)

	data, err := os.ReadFile(filepath.Join(syncDir, "sub", "deep", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "nested" {
		t.Errorf("expected nested, got %q", data)
	}
}

func TestMkdirRmdir(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpMkdir(t, ch, 1, "/newdir")
	if code != sshFxOk {
		t.Fatalf("mkdir failed: %d", code)
	}

	fi, err := os.Stat(filepath.Join(syncDir, "newdir"))
	if err != nil || !fi.IsDir() {
		t.Fatal("directory not created")
	}

	code = sftpRmdir(t, ch, 2, "/newdir")
	if code != sshFxOk {
		t.Fatalf("rmdir failed: %d", code)
	}

	if _, err := os.Stat(filepath.Join(syncDir, "newdir")); !os.IsNotExist(err) {
		t.Error("directory not removed")
	}
}

func TestRemoveFile(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "remove-me.txt"), []byte("bye"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRemove(t, ch, 1, "/remove-me.txt")
	if code != sshFxOk {
		t.Fatalf("remove failed: %d", code)
	}

	if _, err := os.Stat(filepath.Join(syncDir, "remove-me.txt")); !os.IsNotExist(err) {
		t.Error("file not removed")
	}
}

func TestRenameFile(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "old.txt"), []byte("data"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRename(t, ch, 1, "/old.txt", "/new.txt")
	if code != sshFxOk {
		t.Fatalf("rename failed: %d", code)
	}

	if _, err := os.Stat(filepath.Join(syncDir, "old.txt")); !os.IsNotExist(err) {
		t.Error("old file still exists")
	}
	data, err := os.ReadFile(filepath.Join(syncDir, "new.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data" {
		t.Errorf("expected data, got %q", data)
	}
}

func TestPathTraversal(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	pktType, payload := sftpStat(t, ch, 1, "/../../../etc/passwd")
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS for traversal, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxNoSuchFile {
		t.Errorf("expected NO_SUCH_FILE (path gets cleaned into syncDir), got %d", code)
	}

	_, err := os.Stat(filepath.Join(syncDir, "etc", "passwd"))
	if err == nil {
		t.Error("file should not exist in syncDir")
	}
}

func TestAuthFailure(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")

	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("wrong"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	_, err := ssh.Dial("tcp", addr, config)
	if err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestNoAuthMode(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "", "")

	config := &ssh.ClientConfig{
		User:            "anyone",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("no-auth dial: %v", err)
	}
	conn.Close()
}

func TestHostKeyPersistence(t *testing.T) {
	metaDir := t.TempDir()
	keyPath := filepath.Join(metaDir, "test_host_key")

	key1, err := loadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := loadOrGenerateHostKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if key1.PublicKey().Marshal() == nil || key2.PublicKey().Marshal() == nil {
		t.Fatal("nil public keys")
	}

	if string(key1.PublicKey().Marshal()) != string(key2.PublicKey().Marshal()) {
		t.Error("host keys differ on reload")
	}
}

// --- Setstat / Fsetstat ---

func TestSetstat(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "f.txt"), []byte("x"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/f.txt")
	req = marshalUint32(req, 0) // empty attrs
	writePacket(ch, sshFxpSetstat, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOk {
		t.Errorf("expected OK for setstat, got %d", code)
	}
}

func TestFsetstat(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "f.txt"), []byte("x"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpenFile(t, ch, 1, "/f.txt", sshFxfRead)

	var req []byte
	req = marshalUint32(req, 2)
	req = marshalString(req, handle)
	req = marshalUint32(req, 0)
	writePacket(ch, sshFxpFsetstat, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOk {
		t.Errorf("expected OK for fsetstat, got %d", code)
	}
	sftpClose(t, ch, 3, handle)
}

// --- Readlink / Symlink ---

func TestReadlinkUnsupported(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/link")
	writePacket(ch, sshFxpReadlink, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOpUnsupported {
		t.Errorf("expected OP_UNSUPPORTED, got %d", code)
	}
}

func TestSymlinkUnsupported(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/target")
	req = marshalString(req, "/link")
	writePacket(ch, sshFxpSymlink, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOpUnsupported {
		t.Errorf("expected OP_UNSUPPORTED, got %d", code)
	}
}

// --- Extended: posix-rename and unknown ---

func TestExtendedPosixRename(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "old.txt"), []byte("data"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "posix-rename@openssh.com")
	req = marshalString(req, "/old.txt")
	req = marshalString(req, "/new.txt")
	writePacket(ch, sshFxpExtended, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOk {
		t.Fatalf("posix-rename failed: %d", code)
	}

	if _, err := os.Stat(filepath.Join(syncDir, "old.txt")); !os.IsNotExist(err) {
		t.Error("old file should not exist")
	}
	data, err := os.ReadFile(filepath.Join(syncDir, "new.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data" {
		t.Errorf("expected data, got %q", data)
	}
}

func TestExtendedPosixRenameTraversal(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "f.txt"), []byte("x"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "posix-rename@openssh.com")
	req = marshalString(req, "/f.txt")
	req = marshalString(req, "../../../etc/evil")
	writePacket(ch, sshFxpExtended, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxPermissionDenied {
		t.Errorf("expected PERMISSION_DENIED, got %d", code)
	}
}

func TestExtendedUnknown(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "some-unknown-extension@example.com")
	writePacket(ch, sshFxpExtended, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOpUnsupported {
		t.Errorf("expected OP_UNSUPPORTED, got %d", code)
	}
}

// --- Open flag combinations ---

func TestOpenReadWrite(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "rw.txt"), []byte("AAAA"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpenFile(t, ch, 1, "/rw.txt", sshFxfRead|sshFxfWrite)
	sftpWriteFile(t, ch, 2, handle, 2, []byte("ZZ"))
	data, _ := sftpReadFile(t, ch, 3, handle, 0, 10)
	sftpClose(t, ch, 4, handle)

	if string(data) != "AAZZ" {
		t.Errorf("expected AAZZ, got %q", data)
	}
}

func TestOpenExclusive(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "exists.txt"), []byte("x"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/exists.txt")
	req = marshalUint32(req, sshFxfWrite|sshFxfCreat|sshFxfExcl)
	req = marshalUint32(req, 0)
	writePacket(ch, sshFxpOpen, req)

	pktType, _, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS (failure), got %d", pktType)
	}
}

func TestOpenCreatOnly(t *testing.T) {
	syncDir := t.TempDir()

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	handle := sftpOpenFile(t, ch, 1, "/new.txt", sshFxfWrite|sshFxfCreat)
	sftpWriteFile(t, ch, 2, handle, 0, []byte("created"))
	sftpClose(t, ch, 3, handle)

	data, err := os.ReadFile(filepath.Join(syncDir, "new.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "created" {
		t.Fatalf("expected created, got %q", data)
	}
}

// --- Path traversal via rename ---

func TestRenameTraversalSource(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRename(t, ch, 1, "../../../etc/passwd", "/stolen.txt")
	if code == sshFxOk {
		t.Error("expected failure for traversal in source")
	}
}

func TestRenameTraversalDest(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "f.txt"), []byte("x"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRename(t, ch, 1, "/f.txt", "../../../etc/evil")
	if code == sshFxOk {
		t.Error("expected failure for traversal in destination")
	}
}

// --- Path traversal via open ---

func TestOpenTraversal(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "../../../etc/passwd")
	req = marshalUint32(req, sshFxfRead)
	req = marshalUint32(req, 0)
	writePacket(ch, sshFxpOpen, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxPermissionDenied {
		t.Errorf("expected PERMISSION_DENIED, got %d", code)
	}
}

// --- Path traversal via mkdir/rmdir/remove ---

func TestMkdirTraversal(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpMkdir(t, ch, 1, "../../../evil")
	if code == sshFxOk {
		t.Error("expected failure for traversal in mkdir")
	}
}

func TestRemoveTraversal(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRemove(t, ch, 1, "../../../etc/passwd")
	if code == sshFxOk {
		t.Error("expected failure for traversal in remove")
	}
}

func TestRmdirTraversal(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	code := sftpRmdir(t, ch, 1, "../../../etc")
	if code == sshFxOk {
		t.Error("expected failure for traversal in rmdir")
	}
}

// --- Stat traversal ---

func TestStatTraversal(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	pktType, payload := sftpStat(t, ch, 1, "../../../etc/passwd")
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code == sshFxOk {
		t.Error("should not succeed for traversal path")
	}
}

// --- Opendir traversal ---

func TestOpendirTraversal(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "../../../etc")
	writePacket(ch, sshFxpOpendir, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxPermissionDenied {
		t.Errorf("expected PERMISSION_DENIED, got %d", code)
	}
}

// --- Lstat ---

func TestLstat(t *testing.T) {
	syncDir := t.TempDir()
	os.WriteFile(filepath.Join(syncDir, "l.txt"), []byte("abc"), 0o644)

	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	req = marshalString(req, "/l.txt")
	writePacket(ch, sshFxpLstat, req)

	pktType, _, _ := readPacket(ch)
	if pktType != sshFxpAttrs {
		t.Fatalf("expected ATTRS, got %d", pktType)
	}
}

// --- Unknown packet type ---

func TestUnknownPacketType(t *testing.T) {
	syncDir := t.TempDir()
	addr := testGateway(t, syncDir, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)

	var req []byte
	req = marshalUint32(req, 1)
	writePacket(ch, 255, req)

	pktType, payload, _ := readPacket(ch)
	if pktType != sshFxpStatus {
		t.Fatalf("expected STATUS, got %d", pktType)
	}
	_, rest, _ := unmarshalUint32(payload)
	code, _, _ := unmarshalUint32(rest)
	if code != sshFxOpUnsupported {
		t.Errorf("expected OP_UNSUPPORTED, got %d", code)
	}
}
