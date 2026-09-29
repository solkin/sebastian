//go:build unix

package fileops

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// AcquireLease prevents two daemon processes from mutating the same
// volume. The OS releases it on exit, including SIGKILL; the lock file
// is never deleted (unlinking it would allow locking a different inode).
func AcquireLease(dir string) (func() error, error) {
	f, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another daemon owns %s: %w", dir, err)
	}
	return f.Close, nil
}
