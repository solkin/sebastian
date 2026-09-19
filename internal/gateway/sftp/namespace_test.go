package sftp

import (
	"fmt"
	"github.com/solkin/sebastian/internal/gateway"
	"os"
	"path/filepath"
	"testing"
)

func TestReaddirHiddenEntriesAndPaging(t *testing.T) {
	for _, visibleCount := range []int{0, readdirBatchSize + 7} {
		t.Run(fmt.Sprint(visibleCount), func(t *testing.T) {
			root := t.TempDir()
			for i := 0; i < readdirBatchSize+1; i++ {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf(".seb-tmp-%04d", i)), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			reserved := filepath.Join(root, gateway.ReservedDirName)
			if err := os.Mkdir(reserved, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(reserved, filepath.Join(root, "state-alias")); err != nil {
				t.Fatal(err)
			}
			expected := map[string]bool{}
			for i := 0; i < visibleCount; i++ {
				name := fmt.Sprintf("visible-%04d", i)
				expected[name] = true
				if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			addr := testGateway(t, root, "user", "pass")
			ch := sftpClient(t, addr, "user", "pass")
			sftpInit(t, ch)
			handle := sftpOpendir(t, ch, 1, "/")
			for id := uint32(2); id < 20; id++ {
				req := marshalString(marshalUint32(nil, id), handle)
				if err := writePacket(ch, sshFxpReaddir, req); err != nil {
					t.Fatal(err)
				}
				typ, payload, err := readPacket(ch)
				if err != nil {
					t.Fatal(err)
				}
				_, rest, err := unmarshalUint32(payload)
				if err != nil {
					t.Fatal(err)
				}
				if typ == sshFxpStatus {
					code, _, err := unmarshalUint32(rest)
					if err != nil || code != sshFxEOF {
						t.Fatalf("unexpected status: %d %v", code, err)
					}
					if len(expected) != 0 {
						t.Fatalf("premature EOF: %d visible entries missing", len(expected))
					}
					return
				}
				if typ != sshFxpName {
					t.Fatalf("expected NAME, got %d", typ)
				}
				count, rest, err := unmarshalUint32(rest)
				if err != nil {
					t.Fatal(err)
				}
				if count == 0 || count > readdirBatchSize {
					t.Fatalf("invalid batch size: %d", count)
				}
				for i := uint32(0); i < count; i++ {
					name, r, err := unmarshalString(rest)
					if err != nil {
						t.Fatal(err)
					}
					_, r, err = unmarshalString(r)
					if err != nil {
						t.Fatal(err)
					}
					rest, err = unmarshalAttrs(r)
					if err != nil {
						t.Fatal(err)
					}
					if !expected[name] {
						t.Fatalf("hidden or duplicate entry: %s", name)
					}
					delete(expected, name)
				}
			}
			t.Fatal("directory enumeration did not reach EOF")
		})
	}
}
