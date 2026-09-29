//go:build !windows

package fileops

import (
	"errors"
	"os"
)

func SyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
