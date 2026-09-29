package fileops

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

// Windows filesystems do not generally permit FlushFileBuffers on directories.
// Keep file flushes and namespace operations usable, without promising Unix
// directory durability when the platform refuses it.
func SyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	if errors.Is(syncErr, windows.ERROR_ACCESS_DENIED) || errors.Is(syncErr, windows.ERROR_INVALID_HANDLE) || errors.Is(syncErr, windows.ERROR_INVALID_FUNCTION) {
		syncErr = nil
	}
	return errors.Join(syncErr, f.Close())
}
