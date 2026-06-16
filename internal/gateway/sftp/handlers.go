package sftp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type handleEntry struct {
	path    string
	file    *os.File
	isDir   bool
	entries []os.DirEntry // directory entries, populated lazily on first READDIR
	dirPos  int           // index of the next entry to return
	dirRead bool          // whether entries has been populated
}

type session struct {
	g       *Gateway
	ch      ssh.Channel
	handles map[string]*handleEntry
	mu      sync.Mutex
}

func (g *Gateway) serveSFTP(ch ssh.Channel) {
	s := &session{
		g:       g,
		ch:      ch,
		handles: make(map[string]*handleEntry),
	}
	defer s.closeAllHandles()

	pktType, payload, err := readPacket(ch)
	if err != nil {
		g.logger.Error("sftp read init failed", "error", err)
		return
	}
	if pktType != sshFxpInit {
		g.logger.Error("expected SSH_FXP_INIT", "got", pktType)
		return
	}
	_ = payload

	var resp []byte
	resp = marshalUint32(resp, sftpProtocolVersion)
	if err := writePacket(ch, sshFxpVersion, resp); err != nil {
		return
	}

	for {
		pktType, payload, err := readPacket(ch)
		if err != nil {
			if err != io.EOF {
				g.logger.Debug("sftp read error", "error", err)
			}
			return
		}
		s.handlePacket(pktType, payload)
	}
}

func (s *session) handlePacket(pktType byte, payload []byte) {
	switch pktType {
	case sshFxpRealpath:
		s.handleRealpath(payload)
	case sshFxpStat:
		s.handleStat(payload)
	case sshFxpLstat:
		s.handleStat(payload)
	case sshFxpFstat:
		s.handleFstat(payload)
	case sshFxpOpendir:
		s.handleOpendir(payload)
	case sshFxpReaddir:
		s.handleReaddir(payload)
	case sshFxpOpen:
		s.handleOpen(payload)
	case sshFxpRead:
		s.handleRead(payload)
	case sshFxpWrite:
		s.handleWrite(payload)
	case sshFxpClose:
		s.handleClose(payload)
	case sshFxpRemove:
		s.handleRemove(payload)
	case sshFxpMkdir:
		s.handleMkdir(payload)
	case sshFxpRmdir:
		s.handleRmdir(payload)
	case sshFxpRename:
		s.handleRename(payload)
	case sshFxpSetstat:
		s.handleSetstat(payload)
	case sshFxpFsetstat:
		s.handleFsetstat(payload)
	case sshFxpReadlink:
		s.handleReadlink(payload)
	case sshFxpSymlink:
		s.handleSymlink(payload)
	case sshFxpExtended:
		s.handleExtended(payload)
	default:
		id, _, _ := unmarshalUint32(payload)
		s.sendStatus(id, sshFxOpUnsupported, "unsupported operation")
	}
}

func (s *session) handleRealpath(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	path, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	cleaned := filepath.ToSlash(filepath.Clean(path))
	if cleaned == "." || cleaned == "" {
		cleaned = "/"
	}
	if cleaned[0] != '/' {
		cleaned = "/" + cleaned
	}

	var resp []byte
	resp = marshalUint32(resp, id)
	resp = marshalUint32(resp, 1) // count
	resp = marshalString(resp, cleaned)
	resp = marshalString(resp, cleaned) // long name
	resp = marshalUint32(resp, 0)       // empty attrs
	writePacket(s.ch, sshFxpName, resp)
}

func (s *session) handleStat(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	path, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	fullPath, err := s.g.resolvePath(path)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}

	fi, err := os.Stat(fullPath)
	if err != nil {
		s.sendStatus(id, sshFxNoSuchFile, "no such file")
		return
	}

	var resp []byte
	resp = marshalUint32(resp, id)
	resp = marshalAttrs(resp, fi)
	writePacket(s.ch, sshFxpAttrs, resp)
}

func (s *session) handleFstat(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	handle, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	s.mu.Lock()
	entry, ok := s.handles[handle]
	s.mu.Unlock()
	if !ok {
		s.sendStatus(id, sshFxFailure, "invalid handle")
		return
	}

	fi, err := os.Stat(entry.path)
	if err != nil {
		s.sendStatus(id, sshFxNoSuchFile, "no such file")
		return
	}

	var resp []byte
	resp = marshalUint32(resp, id)
	resp = marshalAttrs(resp, fi)
	writePacket(s.ch, sshFxpAttrs, resp)
}

func (s *session) handleOpendir(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	path, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	fullPath, err := s.g.resolvePath(path)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}

	fi, err := os.Stat(fullPath)
	if err != nil || !fi.IsDir() {
		s.sendStatus(id, sshFxNoSuchFile, "not a directory")
		return
	}

	handle := s.newHandle(fullPath, nil, true)

	var resp []byte
	resp = marshalUint32(resp, id)
	resp = marshalString(resp, handle)
	writePacket(s.ch, sshFxpHandle, resp)
}

// readdirBatchSize bounds how many entries a single SSH_FXP_READDIR returns, so
// large directories are paged across replies instead of sent in one huge packet.
const readdirBatchSize = 256

func (s *session) handleReaddir(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	handle, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	// Populate the entry list once (under the lock), then hand out a bounded batch
	// per call. All handle state is mutated under s.mu so concurrent READDIRs on
	// the same handle cannot race.
	s.mu.Lock()
	entry, ok := s.handles[handle]
	if !ok || !entry.isDir {
		s.mu.Unlock()
		s.sendStatus(id, sshFxFailure, "invalid handle")
		return
	}
	if !entry.dirRead {
		entries, rerr := os.ReadDir(entry.path)
		if rerr != nil {
			s.mu.Unlock()
			s.sendStatus(id, sshFxFailure, "read failed")
			return
		}
		entry.entries = entries
		entry.dirRead = true
	}
	start := entry.dirPos
	end := start + readdirBatchSize
	if end > len(entry.entries) {
		end = len(entry.entries)
	}
	batch := entry.entries[start:end]
	entry.dirPos = end
	s.mu.Unlock()

	// Marshal into a temporary buffer first so the entry count reflects only the
	// entries we actually emit (an entry may vanish between ReadDir and Info).
	var body []byte
	count := 0
	for _, e := range batch {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		body = marshalFileInfo(body, e.Name(), fi)
		count++
	}

	if count == 0 {
		s.sendStatus(id, sshFxEOF, "")
		return
	}

	var resp []byte
	resp = marshalUint32(resp, id)
	resp = marshalUint32(resp, uint32(count))
	resp = append(resp, body...)
	writePacket(s.ch, sshFxpName, resp)
}

func (s *session) handleOpen(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	path, rest, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	pflags, rest, err := unmarshalUint32(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	_, _ = unmarshalAttrs(rest)

	fullPath, err := s.g.resolvePath(path)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}

	var flag int
	if pflags&sshFxfRead != 0 && pflags&sshFxfWrite != 0 {
		flag = os.O_RDWR
	} else if pflags&sshFxfWrite != 0 {
		flag = os.O_WRONLY
	} else {
		flag = os.O_RDONLY
	}

	if pflags&sshFxfCreat != 0 {
		flag |= os.O_CREATE
	}
	if pflags&sshFxfTrunc != 0 {
		flag |= os.O_TRUNC
	}
	if pflags&sshFxfAppend != 0 {
		flag |= os.O_APPEND
	}
	if pflags&sshFxfExcl != 0 {
		flag |= os.O_EXCL
	}

	if pflags&sshFxfCreat != 0 {
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			s.sendStatus(id, sshFxFailure, "mkdir failed")
			return
		}
	}

	f, err := os.OpenFile(fullPath, flag, 0o644)
	if err != nil {
		if os.IsNotExist(err) {
			s.sendStatus(id, sshFxNoSuchFile, "no such file")
		} else if os.IsPermission(err) {
			s.sendStatus(id, sshFxPermissionDenied, "permission denied")
		} else {
			s.sendStatus(id, sshFxFailure, err.Error())
		}
		return
	}

	handle := s.newHandle(fullPath, f, false)
	s.g.logger.Debug("file opened", "path", path, "flags", pflags)

	var resp []byte
	resp = marshalUint32(resp, id)
	resp = marshalString(resp, handle)
	writePacket(s.ch, sshFxpHandle, resp)
}

func (s *session) handleRead(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	handle, rest, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	offset, rest, err := unmarshalUint64(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	length, _, err := unmarshalUint32(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	s.mu.Lock()
	entry, ok := s.handles[handle]
	s.mu.Unlock()
	if !ok || entry.file == nil {
		s.sendStatus(id, sshFxFailure, "invalid handle")
		return
	}

	if length > 1<<18 {
		length = 1 << 18
	}

	buf := make([]byte, length)
	n, err := entry.file.ReadAt(buf, int64(offset))
	if n == 0 {
		if err == io.EOF {
			s.sendStatus(id, sshFxEOF, "")
		} else {
			s.sendStatus(id, sshFxFailure, "read error")
		}
		return
	}

	var resp []byte
	resp = marshalUint32(resp, id)
	resp = marshalBytes(resp, buf[:n])
	writePacket(s.ch, sshFxpData, resp)
}

func (s *session) handleWrite(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	handle, rest, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	offset, rest, err := unmarshalUint64(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	data, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	s.mu.Lock()
	entry, ok := s.handles[handle]
	s.mu.Unlock()
	if !ok || entry.file == nil {
		s.sendStatus(id, sshFxFailure, "invalid handle")
		return
	}

	_, err = entry.file.WriteAt([]byte(data), int64(offset))
	if err != nil {
		s.sendStatus(id, sshFxFailure, "write error")
		return
	}

	s.sendStatus(id, sshFxOk, "")
}

func (s *session) handleClose(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	handle, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	s.mu.Lock()
	entry, ok := s.handles[handle]
	if ok {
		delete(s.handles, handle)
	}
	s.mu.Unlock()

	if !ok {
		s.sendStatus(id, sshFxFailure, "invalid handle")
		return
	}

	if entry.file != nil {
		entry.file.Close()
	}
	s.sendStatus(id, sshFxOk, "")
}

func (s *session) handleRemove(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	path, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	fullPath, err := s.g.resolvePath(path)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}

	fi, err := os.Stat(fullPath)
	if err != nil {
		s.sendStatus(id, sshFxNoSuchFile, "no such file")
		return
	}
	if fi.IsDir() {
		s.sendStatus(id, sshFxFailure, "is a directory, use rmdir")
		return
	}

	if err := os.Remove(fullPath); err != nil {
		s.sendStatus(id, sshFxFailure, err.Error())
		return
	}

	s.g.logger.Info("file removed", "path", path)
	s.sendStatus(id, sshFxOk, "")
}

func (s *session) handleMkdir(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	path, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	fullPath, err := s.g.resolvePath(path)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}

	if err := os.Mkdir(fullPath, 0o755); err != nil {
		if os.IsExist(err) {
			s.sendStatus(id, sshFxFailure, "already exists")
		} else {
			s.sendStatus(id, sshFxFailure, err.Error())
		}
		return
	}

	s.g.logger.Info("directory created", "path", path)
	s.sendStatus(id, sshFxOk, "")
}

func (s *session) handleRmdir(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	path, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	fullPath, err := s.g.resolvePath(path)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}

	absRoot, _ := filepath.Abs(s.g.rootDir)
	absPath, _ := filepath.Abs(fullPath)
	if absPath == absRoot {
		s.sendStatus(id, sshFxPermissionDenied, "cannot remove root")
		return
	}

	if err := os.Remove(fullPath); err != nil {
		s.sendStatus(id, sshFxFailure, err.Error())
		return
	}

	s.g.logger.Info("directory removed", "path", path)
	s.sendStatus(id, sshFxOk, "")
}

func (s *session) handleRename(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		return
	}
	oldPath, rest, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	newPath, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	oldFull, err := s.g.resolvePath(oldPath)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}
	newFull, err := s.g.resolvePath(newPath)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}

	if err := os.Rename(oldFull, newFull); err != nil {
		s.sendStatus(id, sshFxFailure, err.Error())
		return
	}

	s.g.logger.Info("renamed", "from", oldPath, "to", newPath)
	s.sendStatus(id, sshFxOk, "")
}

// handleSetstat applies attributes to a path (SSH_FXP_SETSTAT). Only size
// (truncate), permissions (chmod) and access/mod times (chtimes) are applied;
// ownership is ignored. Previously this silently returned success without doing
// anything, so a client's chmod/truncate was reported as done but lost.
func (s *session) handleSetstat(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	path, rest, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	attrs, _, err := parseAttrs(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	full, err := s.g.resolvePath(path)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}
	if err := applyAttrs(attrs, full, nil); err != nil {
		s.sendStatus(id, sshFxFailure, err.Error())
		return
	}
	s.sendStatus(id, sshFxOk, "")
}

// handleFsetstat applies attributes to an open handle (SSH_FXP_FSETSTAT).
func (s *session) handleFsetstat(payload []byte) {
	id, rest, err := unmarshalUint32(payload)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	handle, rest, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	attrs, _, err := parseAttrs(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	s.mu.Lock()
	entry := s.handles[handle]
	s.mu.Unlock()
	if entry == nil || entry.file == nil {
		s.sendStatus(id, sshFxFailure, "invalid handle")
		return
	}
	if err := applyAttrs(attrs, entry.path, entry.file); err != nil {
		s.sendStatus(id, sshFxFailure, err.Error())
		return
	}
	s.sendStatus(id, sshFxOk, "")
}

// applyAttrs applies the supported attribute changes to a file, identified
// either by an open *os.File (f, preferred when set) or by path.
func applyAttrs(a fileAttrs, path string, f *os.File) error {
	if a.hasSize {
		if f != nil {
			if err := f.Truncate(int64(a.size)); err != nil {
				return err
			}
		} else if err := os.Truncate(path, int64(a.size)); err != nil {
			return err
		}
	}
	if a.hasPerm {
		mode := os.FileMode(a.perm & 0o777)
		if f != nil {
			if err := f.Chmod(mode); err != nil {
				return err
			}
		} else if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	if a.hasTimes {
		// *os.File has no Chtimes; times are always applied by path.
		if err := os.Chtimes(path, time.Unix(int64(a.atime), 0), time.Unix(int64(a.mtime), 0)); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) handleReadlink(payload []byte) {
	id, _, _ := unmarshalUint32(payload)
	s.sendStatus(id, sshFxOpUnsupported, "symlinks not supported")
}

func (s *session) handleSymlink(payload []byte) {
	id, _, _ := unmarshalUint32(payload)
	s.sendStatus(id, sshFxOpUnsupported, "symlinks not supported")
}

func (s *session) handleExtended(payload []byte) {
	id, rest, _ := unmarshalUint32(payload)
	extName, _, _ := unmarshalString(rest)

	if extName == "posix-rename@openssh.com" {
		s.handlePosixRename(id, rest)
		return
	}

	s.sendStatus(id, sshFxOpUnsupported, fmt.Sprintf("unsupported extension: %s", extName))
}

func (s *session) handlePosixRename(id uint32, rest []byte) {
	_, rest, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	oldPath, rest, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}
	newPath, _, err := unmarshalString(rest)
	if err != nil {
		s.sendStatus(id, sshFxBadMessage, "bad message")
		return
	}

	oldFull, err := s.g.resolvePath(oldPath)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}
	newFull, err := s.g.resolvePath(newPath)
	if err != nil {
		s.sendStatus(id, sshFxPermissionDenied, "access denied")
		return
	}

	if err := os.Rename(oldFull, newFull); err != nil {
		s.sendStatus(id, sshFxFailure, err.Error())
		return
	}

	s.g.logger.Info("posix-renamed", "from", oldPath, "to", newPath)
	s.sendStatus(id, sshFxOk, "")
}

// sendStatus writes an SSH_FXP_STATUS response.
func (s *session) sendStatus(id uint32, code uint32, msg string) {
	var resp []byte
	resp = marshalUint32(resp, id)
	resp = marshalUint32(resp, code)
	resp = marshalString(resp, msg)
	resp = marshalString(resp, "") // language tag
	writePacket(s.ch, sshFxpStatus, resp)
}

func (s *session) newHandle(path string, f *os.File, isDir bool) string {
	buf := make([]byte, 8)
	rand.Read(buf)
	handle := hex.EncodeToString(buf)
	s.mu.Lock()
	s.handles[handle] = &handleEntry{path: path, file: f, isDir: isDir}
	s.mu.Unlock()
	return handle
}

func (s *session) closeAllHandles() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.handles {
		if entry.file != nil {
			entry.file.Close()
		}
	}
	s.handles = nil
}
