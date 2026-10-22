package fileops

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// PublishIf is Publish for a write that depends on what the destination is
// now, such as an S3 PUT with If-None-Match or If-Match. precondition is handed
// the destination's current stat (or the error stating it) under the root
// lock, in the same lock hold as the rename, so no other mutation can create or
// replace the destination between the check and the publication; a non-nil
// result refuses the write and is returned as is, leaving the scratch file to
// the caller. A nil precondition publishes unconditionally.
//
// The returned stat describes the published generation. It is taken from the
// scratch file before the rename, which keeps its inode, size and timestamp,
// so it names exactly what this call published even if another write replaces
// the destination right after the lock is released.
func PublishIf(root, scratch, dest string, precondition func(current os.FileInfo, err error) error) (os.FileInfo, error) {
	f, err := os.OpenFile(scratch, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return nil, err
	}
	var info os.FileInfo
	err = Do(root, func() error {
		if precondition != nil {
			current, statErr := os.Stat(dest)
			if err := precondition(current, statErr); err != nil {
				return err
			}
		}
		published, err := os.Stat(scratch)
		if err != nil {
			return err
		}
		if err := os.Rename(scratch, dest); err != nil {
			return err
		}
		info = published
		return SyncParents(filepath.Dir(dest), root)
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// SameGeneration reports whether two stat results name the same unchanged
// file: the same inode with the same size, timestamp and mode. A caller that
// read a file without holding the root lock uses it to prove that the bytes it
// read all belong to the generation it opened.
func SameGeneration(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() &&
		a.ModTime().Equal(b.ModTime()) && a.Mode() == b.Mode()
}

// TryLock is Lock that does not wait: ok is false when another mutation of
// the root holds it. It lets a test observe whether long work holds the lock.
func TryLock(dir string) (unlock func(), ok bool) {
	abs, _ := filepath.Abs(dir)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	value, _ := roots.LoadOrStore(abs, new(sync.Mutex))
	mutex := value.(*sync.Mutex)
	if !mutex.TryLock() {
		return nil, false
	}
	return mutex.Unlock, true
}
