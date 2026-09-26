package gateway

import "path/filepath"

// evalDeepestAncestor returns filepath.EvalSymlinks of the deepest ancestor of
// the clean absolute path p (p itself included) that EvalSymlinks can resolve,
// joined with the components below that ancestor, which do not exist yet.
//
// Windows paths carry volume names and resolve by their own rules, which the
// single walk in resolve.go does not model, so here EvalSymlinks is still asked
// about one ancestor after another, from p up: quadratic in the path's length.
func evalDeepestAncestor(p string) string {
	cur, rest := p, ""
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			if rest != "" {
				resolved = filepath.Join(resolved, rest)
			}
			return resolved
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}
