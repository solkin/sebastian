package fileops

import (
	"fmt"
	"os"
	"syscall"
)

// OpenRegular opens a regular file for reading without blocking on special files
// such as FIFOs. Directories return a wrapped syscall.EISDIR.
func OpenRegular(path string) (*os.File, error) {
	return OpenRegularFile(path, os.O_RDONLY, 0)
}

// OpenRegularFile opens a regular file with the requested flags without blocking
// on special files such as FIFOs. Directories return a wrapped syscall.EISDIR.
func OpenRegularFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag|nonblockFlag, perm)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		if info.IsDir() {
			err = fmt.Errorf("is a directory: %w", syscall.EISDIR)
		} else {
			err = fmt.Errorf("not a regular file: %s", path)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
