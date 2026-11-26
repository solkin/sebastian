// Package fileops serializes namespace mutations and makes published changes durable.
// It has no indexing, watcher, or replication dependencies.
package fileops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

type rootState struct {
	mu            sync.Mutex
	recoveryClean atomic.Bool
}

var roots sync.Map
var rootsMu sync.Mutex // binds alternate names to one stable state

func root(dir string) *rootState {
	abs, _ := filepath.Abs(dir)
	if v, ok := roots.Load(abs); ok {
		return v.(*rootState)
	}
	rootsMu.Lock()
	defer rootsMu.Unlock()
	if v, ok := roots.Load(abs); ok {
		return v.(*rootState)
	}
	real := canonical(abs)
	v, ok := roots.Load(real)
	if !ok {
		v = new(rootState)
		roots.Store(real, v)
	}
	// Keep an established spelling bound even if a symlink/mount is replaced.
	roots.Store(abs, v)
	return v.(*rootState)
}

// Lock serializes mutations through alternate spellings of the same root.
// Callers must not acquire it recursively.
func Lock(dir string) func() {
	r := root(dir)
	r.mu.Lock()
	return r.mu.Unlock
}

// Do completes pending recovery before allowing another mutation.
func Do(dir string, fn func() error) error {
	unlock := Lock(dir)
	defer unlock()
	if err := RecoverIfNeededLocked(dir); err != nil {
		return err
	}
	return fn()
}

func canonical(path string) string {
	abs, _ := filepath.Abs(path)
	if resolved, err := ResolvePath(abs); err == nil {
		return resolved
	}
	return abs
}

func ResolvePath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	suffix := ""
	for {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			return filepath.Join(resolved, suffix), nil
		}
		if (!os.IsNotExist(err) && !errors.Is(err, syscall.ENOTDIR)) || path == filepath.Dir(path) {
			return "", err
		}
		suffix = filepath.Join(filepath.Base(path), suffix)
		path = filepath.Dir(path)
	}
}

func Mkdir(root, path string, mode os.FileMode, parents bool) error {
	return Do(root, func() error {
		var err error
		if parents {
			err = os.MkdirAll(path, mode)
		} else {
			err = os.Mkdir(path, mode)
		}
		if err != nil {
			return err
		}
		return SyncParents(path, root)
	})
}

func Remove(root, path string, recursive bool) error {
	return Do(root, func() error {
		var err error
		if recursive {
			err = os.RemoveAll(path)
		} else {
			err = os.Remove(path)
		}
		if err != nil {
			return err
		}
		return SyncSurvivingParent(path, root)
	})
}

func Rename(root, src, dst string) error {
	return Do(root, func() error {
		if err := os.Rename(src, dst); err != nil {
			return err
		}
		return errors.Join(SyncParents(filepath.Dir(src), root), SyncParents(filepath.Dir(dst), root))
	})
}

// Publish flushes the scratch inode and changed directories before acknowledging.
func Publish(root, scratch, dst string) error {
	f, err := os.OpenFile(scratch, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	return Do(root, func() error {
		if err := os.Rename(scratch, dst); err != nil {
			return err
		}
		return SyncParents(filepath.Dir(dst), root)
	})
}

// SyncParents persists every directory entry up to and including the root,
// covering parent directories that MkdirAll may have just created.
func SyncParents(dir, boundary string) error {
	base, err := filepath.Abs(canonical(boundary))
	if err != nil {
		return err
	}
	current, err := filepath.Abs(canonical(dir))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, current)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("directory is outside sync root")
	}
	for {
		if err := SyncDir(current); err != nil {
			return err
		}
		if current == base {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("directory is outside sync root")
		}
		current = parent
	}
}

// SyncSurvivingParent also works after recursive removal of parent directories.
func SyncSurvivingParent(path, boundary string) error {
	parent := filepath.Dir(path)
	for {
		info, err := os.Stat(parent)
		if err == nil && info.IsDir() {
			return SyncParents(parent, boundary)
		}
		if err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTDIR) {
			return err
		}
		if parent == filepath.Dir(parent) {
			return os.ErrNotExist
		}
		parent = filepath.Dir(parent)
	}
}
