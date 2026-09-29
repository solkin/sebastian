package fileops

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func AcquireLease(dir string) (func() error, error) {
	f, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var lock windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock); err != nil {
		f.Close()
		return nil, err
	}
	return f.Close, nil
}
