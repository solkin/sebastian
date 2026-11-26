package fileops

import (
	"os"
	"sync"
)

var activeScratch sync.Map

// CreateTemp reserves scratch files against the janitor for their full lifetime,
// including an upload that is stalled or has a client-supplied historical mtime.
// The owner must defer ReleaseTemp immediately after a successful call.
func CreateTemp(dir, pattern string) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err == nil {
		activeScratch.Store(canonical(f.Name()), true)
	}
	return f, err
}
func ReleaseTemp(f *os.File)         { activeScratch.Delete(canonical(f.Name())) }
func ScratchActive(path string) bool { _, ok := activeScratch.Load(canonical(path)); return ok }

// RetainTemp reserves an existing scratch path against the janitor.
func RetainTemp(path string) { activeScratch.Store(canonical(path), true) }

// ReleaseTempPath ends a reservation made by CreateTemp or RetainTemp.
func ReleaseTempPath(path string) { activeScratch.Delete(canonical(path)) }
