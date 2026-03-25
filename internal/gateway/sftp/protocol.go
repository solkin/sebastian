package sftp

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

// SFTP packet types (draft-ietf-secsh-filexfer-02).
const (
	sshFxpInit          = 1
	sshFxpVersion       = 2
	sshFxpOpen          = 3
	sshFxpClose         = 4
	sshFxpRead          = 5
	sshFxpWrite         = 6
	sshFxpLstat         = 7
	sshFxpFstat         = 8
	sshFxpSetstat       = 9
	sshFxpFsetstat      = 10
	sshFxpOpendir       = 11
	sshFxpReaddir       = 12
	sshFxpRemove        = 13
	sshFxpMkdir         = 14
	sshFxpRmdir         = 15
	sshFxpRealpath      = 16
	sshFxpStat          = 17
	sshFxpRename        = 18
	sshFxpReadlink      = 19
	sshFxpSymlink       = 20
	sshFxpStatus        = 101
	sshFxpHandle        = 102
	sshFxpData          = 103
	sshFxpName          = 104
	sshFxpAttrs         = 105
	sshFxpExtended      = 200
	sshFxpExtendedReply = 201
)

// SFTP status codes.
const (
	sshFxOk               = 0
	sshFxEOF              = 1
	sshFxNoSuchFile       = 2
	sshFxPermissionDenied = 3
	sshFxFailure          = 4
	sshFxBadMessage       = 5
	sshFxOpUnsupported    = 8
)

// SFTP open flags.
const (
	sshFxfRead   = 0x00000001
	sshFxfWrite  = 0x00000002
	sshFxfAppend = 0x00000004
	sshFxfCreat  = 0x00000008
	sshFxfTrunc  = 0x00000010
	sshFxfExcl   = 0x00000020
)

// SFTP attribute flags.
const (
	sshFileXferAttrSize        = 0x00000001
	sshFileXferAttrUIDGID      = 0x00000002
	sshFileXferAttrPermissions = 0x00000004
	sshFileXferAttrACModTime   = 0x00000008
)

const sftpProtocolVersion = 3

// readPacket reads a single SFTP packet: 4-byte length + payload.
func readPacket(r io.Reader) (byte, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 || length > 1<<24 {
		return 0, nil, fmt.Errorf("invalid packet length: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return payload[0], payload[1:], nil
}

// writePacket writes a single SFTP packet.
func writePacket(w io.Writer, pktType byte, data []byte) error {
	length := uint32(1 + len(data))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], length)
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write([]byte{pktType}); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// Binary marshaling helpers.

func marshalUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func marshalUint64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func marshalString(b []byte, s string) []byte {
	b = marshalUint32(b, uint32(len(s)))
	return append(b, s...)
}

func marshalBytes(b []byte, data []byte) []byte {
	b = marshalUint32(b, uint32(len(data)))
	return append(b, data...)
}

func unmarshalUint32(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("short buffer for uint32")
	}
	return binary.BigEndian.Uint32(b[:4]), b[4:], nil
}

func unmarshalUint64(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fmt.Errorf("short buffer for uint64")
	}
	return binary.BigEndian.Uint64(b[:8]), b[8:], nil
}

func unmarshalString(b []byte) (string, []byte, error) {
	length, rest, err := unmarshalUint32(b)
	if err != nil {
		return "", nil, err
	}
	if uint32(len(rest)) < length {
		return "", nil, fmt.Errorf("short buffer for string")
	}
	return string(rest[:length]), rest[length:], nil
}

// marshalFileInfo encodes os.FileInfo into SFTP name entry format.
func marshalFileInfo(b []byte, name string, fi os.FileInfo) []byte {
	b = marshalString(b, name)
	b = marshalString(b, longName(name, fi))
	b = marshalAttrs(b, fi)
	return b
}

// marshalAttrs encodes file attributes.
func marshalAttrs(b []byte, fi os.FileInfo) []byte {
	flags := uint32(sshFileXferAttrSize | sshFileXferAttrPermissions | sshFileXferAttrACModTime)
	if fi == nil {
		return marshalUint32(b, 0)
	}
	b = marshalUint32(b, flags)
	b = marshalUint64(b, uint64(fi.Size()))
	b = marshalUint32(b, fileModeToSFTP(fi.Mode()))
	mtime := fi.ModTime().Unix()
	b = marshalUint32(b, uint32(mtime)) // atime
	b = marshalUint32(b, uint32(mtime)) // mtime
	return b
}

// unmarshalAttrs skips over attributes in a packet (we don't use most of them).
func unmarshalAttrs(b []byte) ([]byte, error) {
	flags, rest, err := unmarshalUint32(b)
	if err != nil {
		return nil, err
	}
	if flags&sshFileXferAttrSize != 0 {
		if len(rest) < 8 {
			return nil, fmt.Errorf("short attrs")
		}
		rest = rest[8:]
	}
	if flags&sshFileXferAttrUIDGID != 0 {
		if len(rest) < 8 {
			return nil, fmt.Errorf("short attrs")
		}
		rest = rest[8:]
	}
	if flags&sshFileXferAttrPermissions != 0 {
		if len(rest) < 4 {
			return nil, fmt.Errorf("short attrs")
		}
		rest = rest[4:]
	}
	if flags&sshFileXferAttrACModTime != 0 {
		if len(rest) < 8 {
			return nil, fmt.Errorf("short attrs")
		}
		rest = rest[8:]
	}
	return rest, nil
}

func fileModeToSFTP(mode os.FileMode) uint32 {
	var m uint32
	if mode.IsDir() {
		m = 0o40000
	} else {
		m = 0o100000
	}
	m |= uint32(mode.Perm())
	return m
}

func longName(name string, fi os.FileInfo) string {
	mode := fi.Mode()
	var typeChar byte = '-'
	if mode.IsDir() {
		typeChar = 'd'
	}

	perm := mode.Perm()
	perms := [9]byte{'-', '-', '-', '-', '-', '-', '-', '-', '-'}
	for i, c := range "rwxrwxrwx" {
		if perm&(1<<uint(8-i)) != 0 {
			perms[i] = byte(c)
		}
	}

	t := fi.ModTime()
	var dateStr string
	if time.Since(t) > 180*24*time.Hour {
		dateStr = t.Format("Jan _2  2006")
	} else {
		dateStr = t.Format("Jan _2 15:04")
	}

	return fmt.Sprintf("%c%s 1 owner group %12d %s %s",
		typeChar, perms, fi.Size(), dateStr, name)
}
