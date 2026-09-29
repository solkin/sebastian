package sftp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendIgnoresOffsetAndEnforcesFinalSize(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	addr := startGateway(t, root, Config{Username: "user", Password: "pass", MaxUploadBytes: 7})
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)
	handle := sftpOpenFile(t, ch, 1, "/file", sshFxfWrite|sshFxfAppend)
	sftpWriteFile(t, ch, 2, handle, 99999, []byte("+new"))
	var req []byte
	req = marshalUint32(req, 3)
	req = marshalString(req, handle)
	req = marshalUint64(req, 0)
	req = marshalBytes(req, []byte("!"))
	if err := writePacket(ch, sshFxpWrite, req); err != nil {
		t.Fatal(err)
	}
	if code := readStatusCode(t, ch); code != sshFxFailure {
		t.Fatalf("oversized append returned %d", code)
	}
	sftpClose(t, ch, 4, handle)
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "old+new" {
		t.Fatalf("append: %q %v", body, err)
	}
}

func TestDirectWritesPreserveHardlinksAndSurviveDisconnect(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	alias := filepath.Join(root, "alias")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	addr := testGateway(t, root, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)
	handle := sftpOpenFile(t, ch, 1, "/file", sshFxfWrite|sshFxfTrunc)
	sftpWriteFile(t, ch, 2, handle, 0, []byte("partial"))
	for _, name := range []string{path, alias} {
		body, err := os.ReadFile(name)
		if err != nil || string(body) != "partial" {
			t.Fatalf("write not visible before CLOSE at %s: %q %v", name, body, err)
		}
	}
	ch.Close()
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "partial" {
		t.Fatalf("disconnect discarded direct write: %q %v", body, err)
	}
}
