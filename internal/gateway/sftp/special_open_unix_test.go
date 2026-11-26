//go:build unix

package sftp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/fileops"
	"golang.org/x/sys/unix"
)

func TestSFTPFIFOOpenRejectsWithoutBlockingNamespace(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	addr := testGateway(t, root, "user", "pass")
	ch := sftpClient(t, addr, "user", "pass")
	sftpInit(t, ch)
	defer func() {
		f, _ := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
		if f != nil {
			f.Close()
		}
	}()
	for _, flags := range []uint32{sshFxfRead, sshFxfWrite, sshFxfRead | sshFxfWrite | sshFxfTrunc} {
		var request []byte
		request = marshalUint32(request, 1)
		request = marshalString(request, "/fifo")
		request = marshalUint32(request, flags)
		request = marshalUint32(request, 0)
		if err := writePacket(ch, sshFxpOpen, request); err != nil {
			t.Fatal(err)
		}
		type reply struct {
			kind    byte
			payload []byte
			err     error
		}
		done := make(chan reply, 1)
		go func() { kind, payload, err := readPacket(ch); done <- reply{kind, payload, err} }()
		select {
		case r := <-done:
			if r.err != nil || r.kind != sshFxpStatus {
				t.Fatalf("special file accepted: type=%d err=%v", r.kind, r.err)
			}
			_, rest, _ := unmarshalUint32(r.payload)
			code, _, _ := unmarshalUint32(rest)
			if code == sshFxOk {
				t.Fatal("FIFO OPEN succeeded")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("SFTP FIFO OPEN blocked")
		}
	}
	done := make(chan error, 1)
	go func() { done <- fileops.Mkdir(root, filepath.Join(root, "ordinary"), 0o700, false) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SFTP FIFO held namespace mutex")
	}
}
