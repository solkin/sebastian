//go:build !windows

package gateway

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxSymlinks is how many symlinks filepath.EvalSymlinks follows while
// resolving one path before it gives up.
const maxSymlinks = 255

// evalDeepestAncestor returns filepath.EvalSymlinks of the deepest ancestor of
// the clean absolute path p (p itself included) that EvalSymlinks can resolve,
// joined with the components below that ancestor, which do not exist yet.
//
// EvalSymlinks does not say how far it got before failing, so finding that
// ancestor with it means retrying one ancestor after another, each retry
// walking the path from the root again: quadratic in the path's length.
// Instead p is walked once, resolving each component exactly as EvalSymlinks
// would, down to the first one that fails.
func evalDeepestAncestor(p string) string {
	dest, rest := "/", strings.TrimPrefix(p, "/")
	links := 0
	for rest != "" {
		name, next, _ := strings.Cut(rest, "/")
		resolved, ok := evalEntry(dest, name, &links)
		if !ok {
			break
		}
		dest, rest = resolved, next
	}
	return filepath.Join(dest, rest)
}

// evalEntry resolves the entry name of dir, a path as evalDeepestAncestor has
// resolved it so far, taking the steps filepath.EvalSymlinks takes: a symlink
// is replaced by its target, relative to the link's directory unless absolute,
// whose components are resolved in turn; "." is skipped; ".." drops the last
// resolved component; and at most maxSymlinks links are followed along the
// whole path, counted in links. Even the intermediate paths match EvalSymlinks'
// own, so every Lstat and Readlink is one it would make, and evalEntry fails
// exactly where EvalSymlinks would fail on the path ending in name, including
// below a file, where the first Lstat fails.
func evalEntry(dir, name string, links *int) (dest string, ok bool) {
	dest = dir
	for path := name; path != ""; {
		elem, rest, more := strings.Cut(path, "/")
		path = rest
		switch elem {
		case "", ".":
			continue
		case "..":
			// Drop the last component. Like EvalSymlinks, append the ".." for
			// Lstat to resolve instead when dest is "/" or a top-level name, or
			// already ends in such a "..".
			if i := strings.LastIndexByte(dest, '/'); i > 0 && dest[i+1:] != ".." {
				dest = dest[:i]
			} else {
				dest = strings.TrimSuffix(dest, "/") + "/.."
			}
			continue
		}
		if strings.HasSuffix(dest, "/") {
			dest += elem
		} else {
			dest += "/" + elem
		}
		info, err := os.Lstat(dest)
		if err != nil {
			return "", false
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			// Only the final element may be something other than a directory.
			if !info.IsDir() && more {
				return "", false
			}
			continue
		}
		*links++
		if *links > maxSymlinks {
			return "", false
		}
		target, err := os.Readlink(dest)
		if err != nil {
			return "", false
		}
		if strings.HasPrefix(target, "/") {
			dest = "/"
		} else if i := strings.LastIndexByte(dest, '/'); i > 0 {
			dest = dest[:i]
		} else {
			dest = "/"
		}
		if more {
			target += "/" + rest
		}
		path = target
	}
	return dest, true
}
