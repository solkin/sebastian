package fileops

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Per-entry manifests permit interrupted deletion to resume: absent entries are
// harmless, but a new child or an edited file anywhere in the tree is a conflict.
// Directory mtimes/sizes are excluded because removing children changes them.
type replacementEntry struct {
	Name   string      `json:"name"`
	Device uint64      `json:"device"`
	Inode  uint64      `json:"inode"`
	Mode   os.FileMode `json:"mode"`
	Size   int64       `json:"size,omitempty"`
	Mtime  int64       `json:"mtime,omitempty"`
	Hash   string      `json:"hash,omitempty"`
	Link   string      `json:"link,omitempty"`
}

func replacementTree(r *os.Root, name string) ([]replacementEntry, error) {
	var entries []replacementEntry
	var walk func(string, string) error
	walk = func(path, rel string) error {
		info, err := r.Lstat(path)
		if err != nil {
			return err
		}
		device, inode, err := objectIdentity(filepath.Join(r.Name(), path), info)
		if err != nil {
			return err
		}
		entry := replacementEntry{Name: rel, Device: device, Inode: inode, Mode: info.Mode()}
		switch {
		case info.IsDir():
			entries = append(entries, entry)
			f, err := r.Open(path)
			if err != nil {
				return err
			}
			children, err := f.ReadDir(-1)
			err = errors.Join(err, f.Close())
			if err != nil {
				return err
			}
			for _, child := range children {
				if err := walk(filepath.Join(path, child.Name()), filepath.Join(rel, child.Name())); err != nil {
					return err
				}
			}
		case info.Mode().IsRegular():
			f, err := r.Open(path)
			if err != nil {
				return err
			}
			opened, err := f.Stat()
			if err != nil || !os.SameFile(info, opened) {
				f.Close()
				return fmt.Errorf("replacement file changed while opening: %s", path)
			}
			h := sha256.New()
			n, err := io.Copy(h, f)
			err = errors.Join(err, f.Close())
			if err != nil {
				return err
			}
			if n != info.Size() {
				return fmt.Errorf("replacement file changed while reading: %s", path)
			}
			entry.Size, entry.Mtime, entry.Hash = n, info.ModTime().UnixNano(), hex.EncodeToString(h.Sum(nil))
			entries = append(entries, entry)
		case info.Mode()&os.ModeSymlink != 0:
			entry.Link, err = r.Readlink(path)
			if err != nil {
				return err
			}
			entries = append(entries, entry)
		default:
			return fmt.Errorf("unsupported replacement object: %s", path)
		}
		after, err := r.Lstat(path)
		if err != nil {
			return err
		}
		if !os.SameFile(info, after) || info.Mode() != after.Mode() || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
			return fmt.Errorf("replacement object changed during snapshot: %s", path)
		}
		return nil
	}
	if _, err := r.Lstat(name); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := walk(name, "."); err != nil {
		return nil, err
	}
	return entries, nil
}

func matchesReplacement(got, want []replacementEntry, allowMissing bool) bool {
	if !allowMissing && len(got) != len(want) {
		return false
	}
	byName := make(map[string]replacementEntry, len(want))
	for _, e := range want {
		byName[e.Name] = e
	}
	for _, e := range got {
		if expected, ok := byName[e.Name]; !ok || e != expected {
			return false
		}
	}
	return true
}

func validateReplacementTree(tree []replacementEntry) error {
	if len(tree) == 0 {
		return nil
	}
	seen := make(map[string]os.FileMode, len(tree))
	for i, e := range tree {
		if (i == 0 && e.Name != ".") || (i != 0 && !localReplacementName(e.Name)) {
			return fmt.Errorf("invalid replacement manifest name %q", e.Name)
		}
		if _, ok := seen[e.Name]; ok {
			return fmt.Errorf("duplicate replacement manifest name %q", e.Name)
		}
		if i != 0 {
			if mode, ok := seen[filepath.Dir(e.Name)]; !ok || !mode.IsDir() {
				return fmt.Errorf("missing replacement manifest parent for %q", e.Name)
			}
		}
		if e.Mode.IsRegular() {
			if hash, err := hex.DecodeString(e.Hash); err != nil || len(hash) != sha256.Size || e.Size < 0 {
				return fmt.Errorf("invalid replacement manifest checksum")
			}
		} else if !e.Mode.IsDir() && e.Mode&os.ModeSymlink == 0 {
			return fmt.Errorf("invalid replacement manifest type")
		}
		seen[e.Name] = e.Mode
	}
	// Keep validation independent of JSON's permissive missing-field defaults.
	if tree[0].Inode == 0 {
		return fmt.Errorf("missing replacement object identity")
	}
	return nil
}
