package gateway

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// Resolving a path whose tail does not exist used to retry EvalSymlinks on each
// ancestor from the leaf up, every retry walking the path again: quadratic in
// its length, so this path took several seconds. It is walked once now, and the
// bound is generous. 512 components would not catch a regression: the old walk
// took only about 15 ms for them.
func TestSafePath_DeepMissingPathIsLinear(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows still asks EvalSymlinks about each ancestor; see resolve_windows.go")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	const depth = 32768
	deep := "bucket/" + strings.Repeat("a/", depth-1) + "a"
	start := time.Now()
	rel, full, err := SafePath(root, deep)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("resolving %d missing components took %v", depth, elapsed)
	}
	if err != nil {
		t.Fatal(err)
	}
	if rel != deep || full != filepath.Join(root, deep) {
		t.Fatalf("got rel=%.40q... full=%.40q...", rel, full)
	}
}

// A missing tail is appended to what its deepest existing ancestor resolves to,
// so escapes and reserved aliases are refused wherever the link sits above it.
func TestSafePath_SymlinksAtDepthAboveMissingTail(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	for _, dir := range []string{"a/b/c/d", "a/" + tempFilePrefix + "x", ReservedDirName + "/multipart"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"esc":           outside,
		"a/b/esc":       outside,
		"a/b/c/d/esc":   outside,
		"a/in":          filepath.Join(root, "a", "b", "c"),
		"a/b/c/d/rel":   "../..",
		"a/b/c/d/up":    "../../../../..",
		"a/b/state":     filepath.Join(root, ReservedDirName),
		"a/b/c/scratch": filepath.Join(root, "a", tempFilePrefix+"x"),
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Skipf("symlinks unsupported: %v", err)
		}
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}

	tail := strings.Repeat("x/", 511) + "x"
	for _, tc := range []struct {
		prefix   string
		resolved string // relative to the root; empty when the path is refused
	}{
		{"a/b/c/d", "a/b/c/d"},
		{"a/in", "a/b/c"},
		{"a/in/d/rel", "a/b"},
		{"esc", ""},
		{"a/b/esc", ""},
		{"a/b/c/d/esc", ""},
		{"a/b/c/d/up", ""},
		{"a/b/state", ""},
		{"a/b/c/scratch", ""},
	} {
		_, full, err := SafePath(root, tc.prefix+"/"+tail)
		if tc.resolved == "" {
			if err == nil {
				t.Errorf("SafePath(%q + tail) succeeded, want an error", tc.prefix)
			}
			continue
		}
		if err != nil {
			t.Errorf("SafePath(%q + tail): %v", tc.prefix, err)
			continue
		}
		resolved, _, _, err := resolveNoSymlinkEscape(root, full)
		if want := filepath.Join(realRoot, tc.resolved, tail); err != nil || resolved != want {
			t.Errorf("%q + tail resolved to %.60q..., %v; want %.60q...", tc.prefix, resolved, err, want)
		}
	}
}

// referenceResolve is resolveNoSymlinkEscape as it was before the single walk:
// EvalSymlinks retried on each ancestor from the leaf up. It is quadratic in the
// path's length but plainly what the resolver means, so it is the oracle below.
func referenceResolve(rootDir, full string) (resolvedPath, realRoot string, rootResolved bool, err error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", "", false, err
	}
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", "", false, err
	}
	realRoot, err = filepath.EvalSymlinks(absRoot)
	if err != nil {
		return absFull, absRoot, false, nil
	}
	cur, rest := absFull, ""
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			if rest != "" {
				resolved = filepath.Join(resolved, rest)
			}
			if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
				return "", realRoot, true, fmt.Errorf("path traversal")
			}
			return resolved, realRoot, true, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return absFull, realRoot, true, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// The single walk must agree with the search it replaced on every path of up to
// two components over a tree that holds each kind of link at three depths, with
// and without a missing tail, on a fixed sample of deeper paths, and on targeted
// paths through link chains, loops, long names and directories that cannot be
// searched.
func TestResolveNoSymlinkEscape_MatchesReference(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	for _, dir := range []string{"d/d/d", "d/" + tempFilePrefix + "x", ReservedDirName + "/multipart", "nx/sub"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Only a first link that cannot be made means symlinks are unsupported.
	created := 0
	symlink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			if created == 0 {
				t.Skipf("symlinks unsupported: %v", err)
			}
			t.Fatal(err)
		}
		created++
	}

	// Every level holds the same entries, so each kind of link sits at depths 1
	// to 3, and relative targets land somewhere different at each. Paths are
	// made of the links' names, a directory, a file and a missing name.
	names := []string{"d", "f", "m"}
	for i, dir := range []string{root, filepath.Join(root, "d"), filepath.Join(root, "d", "d")} {
		if err := os.WriteFile(filepath.Join(dir, "f"), []byte("f"), 0o644); err != nil {
			t.Fatal(err)
		}
		for name, target := range map[string]string{
			"in":    filepath.Join(root, "d"),
			"rel":   "d",
			"up":    "..", // leaves the root from the top level
			"back":  filepath.Join("..", filepath.Base(dir), "d"),
			"dd":    "d/..",
			"nest":  "in/d", // a link inside a target, with more to follow
			"top":   "/",
			"out":   outside,
			"outf":  filepath.Join(outside, "secret"),
			"dang":  filepath.Join(root, "missing"),
			"dango": filepath.Join(outside, "missing"),
			"res":   filepath.Join(root, ReservedDirName),
			"tmp":   filepath.Join(root, "d", tempFilePrefix+"x"),
			"fl":    "f",
			"fls":   "f/", // a file used as a directory
			"odd":   root + "//d/./d/",
		} {
			symlink(target, filepath.Join(dir, name))
			if i == 0 {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names) // the sample below must not depend on map order

	// Top-level links whose resolution is costly or unusual.
	symlink("loop", filepath.Join(root, "loop"))
	symlink("pong", filepath.Join(root, "ping"))
	symlink("ping", filepath.Join(root, "pong"))
	symlink(filepath.Join(root, "nx", "sub"), filepath.Join(root, "nxl"))
	// ".." above "/", in an absolute target and in a relative one.
	symlink("/"+strings.Repeat("../", 3)+strings.TrimPrefix(root, "/"), filepath.Join(root, "dots"))
	symlink(strings.Repeat("../", 40)+strings.TrimPrefix(root, "/")+"/d", filepath.Join(root, "climb"))
	// cN reaches d through N links: past the kernel's limits (32 on macOS, 40 on
	// Linux) and up to EvalSymlinks' own, 255 along the whole path.
	symlink("d", filepath.Join(root, "c1"))
	for n := 2; n <= 256; n++ {
		symlink(fmt.Sprintf("c%d", n-1), filepath.Join(root, fmt.Sprintf("c%d", n)))
	}
	if err := os.Chmod(filepath.Join(root, "nx"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(root, "nx"), 0o755) })

	tail := strings.Repeat("t/", 7) + "t"
	var paths []string
	for _, a := range names {
		paths = append(paths, a, a+"/"+tail)
		for _, b := range names {
			paths = append(paths, a+"/"+b, a+"/"+b+"/"+tail)
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		elems := make([]string, 3+rng.IntN(2))
		for i := range elems {
			elems[i] = names[rng.IntN(len(names))]
		}
		paths = append(paths, strings.Join(elems, "/"))
	}
	for _, n := range []int{33, 41, 253, 254, 255, 256} {
		for _, rest := range []string{"", "/m/x", "/in/m", "/fl/x"} {
			paths = append(paths, fmt.Sprintf("c%d%s", n, rest))
		}
	}
	paths = append(paths, "loop", "loop/m", "ping/m", "nx/sub", "nx/sub/m", "nxl/m", "dots/d/m", "climb/d/m",
		"d/"+strings.Repeat("n", 300), "d/"+strings.Repeat("n", 300)+"/x")

	accepted, refused, mismatches := 0, 0, 0
	check := func(rootDir, p string) {
		t.Helper()
		full := filepath.Join(rootDir, p)
		gotPath, gotRoot, gotOK, gotErr := resolveNoSymlinkEscape(rootDir, full)
		wantPath, wantRoot, wantOK, wantErr := referenceResolve(rootDir, full)
		if gotPath != wantPath || gotRoot != wantRoot || gotOK != wantOK || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
			t.Errorf("%s under %s: got (%q, %q, %v, %v), want (%q, %q, %v, %v)",
				p, rootDir, gotPath, gotRoot, gotOK, gotErr, wantPath, wantRoot, wantOK, wantErr)
			if mismatches++; mismatches == 20 {
				t.FailNow()
			}
		}
		if wantOK && wantErr != nil {
			refused++
		} else if wantOK {
			accepted++
		}
	}
	rootLink := filepath.Join(base, "link")
	symlink(root, rootLink)
	for _, rootDir := range []string{root, rootLink} {
		for _, p := range paths {
			check(rootDir, p)
		}
	}
	// Under a root that cannot be resolved, only the caller's textual check stands.
	for _, p := range []string{"d", "m/x", "out/x"} {
		check(filepath.Join(base, "missing"), p)
	}
	// Guard against a tree that no longer exercises both outcomes.
	if accepted < 500 || refused < 500 {
		t.Fatalf("only %d paths accepted and %d refused under a resolvable root", accepted, refused)
	}
}
