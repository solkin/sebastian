package gateway

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxSymlinks = 255

// resolvePath walks the clean absolute Windows path p top-down from its volume
// root, resolving every symlink component including dangling links.
func resolvePath(p string) (string, error) {
	vol := filepath.VolumeName(p)
	dest := vol + `\`
	restPath := strings.TrimLeft(strings.TrimPrefix(p, vol), `\/`)
	links := 0
	for path := filepath.ToSlash(restPath); path != ""; {
		elem, rest, more := strings.Cut(path, "/")
		path = rest
		switch elem {
		case "", ".":
			continue
		case "..":
			if parent := filepath.Dir(dest); parent != dest {
				dest = parent
			}
			continue
		}
		next := filepath.Join(dest, elem)
		info, err := os.Lstat(next)
		if err != nil {
			if more {
				return filepath.Clean(filepath.Join(next, filepath.FromSlash(rest))), nil
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
		if filepath.IsAbs(target) {
			tVol := filepath.VolumeName(target)
			if tVol == "" {
				tVol = vol
			}
			vol = tVol
			dest = vol + `\`
			target = strings.TrimLeft(strings.TrimPrefix(target, tVol), `\/`)
		}
		target = filepath.ToSlash(target)
		if more {
			path = target + "/" + rest
		} else {
			path = target
		}
	}
	if resolved, err := filepath.EvalSymlinks(dest); err == nil {
		return resolved, nil
	}
	return dest, nil
}
