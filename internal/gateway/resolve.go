//go:build !windows

package gateway

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxSymlinks is how many symlinks resolvePath follows while resolving one
// path before it gives up.
const maxSymlinks = 255

// resolvePath walks the clean absolute path p once from "/", resolving every
// symlink component along the way — including dangling symlinks whose targets
// do not exist yet, so a link pointing outside the root or into a reserved
// directory is still resolved to its target and refused before any create call
// can follow it.
func resolvePath(p string) (string, error) {
	dest := "/"
	links := 0
	for path := strings.TrimPrefix(p, "/"); path != ""; {
		elem, rest, more := strings.Cut(path, "/")
		path = rest
		switch elem {
		case "", ".":
			continue
		case "..":
			if i := strings.LastIndexByte(dest, '/'); i > 0 {
				dest = dest[:i]
			} else {
				dest = "/"
			}
			continue
		}
		next := dest + "/" + elem
		if dest == "/" {
			next = "/" + elem
		}
		info, err := os.Lstat(next)
		if err != nil {
			if more {
				return filepath.Clean(next + "/" + rest), nil
			}
			return filepath.Clean(next), nil
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			dest = next
			if !info.IsDir() && more {
				return dest, nil
			}
			continue
		}
		links++
		if links > maxSymlinks {
			return "", fmt.Errorf("too many symlinks")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(target, "/") {
			dest = "/"
		}
		if more {
			path = target + "/" + rest
		} else {
			path = target
		}
	}
	return dest, nil
}
