//go:build unix

package fileops

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func replacementCut(t *testing.T, root string, move, directory, recovery bool, cut string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestReplacementProcessCuts$")
	cmd.Env = append(os.Environ(), "SEBASTIAN_REPLACE_ROOT="+root, fmt.Sprintf("SEBASTIAN_REPLACE_MOVE=%v", move), fmt.Sprintf("SEBASTIAN_REPLACE_DIRECTORY=%v", directory), fmt.Sprintf("SEBASTIAN_REPLACE_RECOVER=%v", recovery), "SEBASTIAN_REPLACE_CUT="+cut)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("child: %v %s", err, out)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("wrong child failure: %v %s", err, out)
	}
}

func replacementJournal(t *testing.T, root string) (string, replacement) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, ".sebastian", "transactions", "replace-*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("journal: %v %v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var state replacement
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return paths[0], state
}

func assertReplacementResult(t *testing.T, root string, move, directory, existing, committed bool) {
	t.Helper()
	suffix := ""
	if directory {
		suffix = "/file"
	}
	if committed {
		wantBody(t, filepath.Join(root, "dst")+suffix, "new")
	} else if existing {
		wantBody(t, filepath.Join(root, "dst")+suffix, "old")
	} else if _, err := os.Lstat(filepath.Join(root, "dst")); !os.IsNotExist(err) {
		t.Fatalf("uncommitted destination remains: %v", err)
	}
	if move && committed {
		if _, err := os.Lstat(filepath.Join(root, "src")); !os.IsNotExist(err) {
			t.Fatalf("MOVE source remains: %v", err)
		}
	} else {
		wantBody(t, filepath.Join(root, "src")+suffix, "new")
	}
	if pending, err := ReplacementPendingLocked(root); err != nil || pending {
		t.Fatalf("journal remains: %v %v", pending, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".seb-bak-") || strings.HasPrefix(e.Name(), ".seb-tmp-replace-") {
			t.Fatalf("leaked transaction object %s", e.Name())
		}
	}
}

func TestReplacementRecoveryInterruptedAgain(t *testing.T) {
	for _, move := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			for _, committed := range []bool{false, true} {
				cuts := []string{"rollback-source", "rollback-destination"}
				if committed {
					cuts = []string{"cleanup-backup"}
					if existing {
						cuts = append(cuts, "cleanup-entry")
					}
				} else if !move {
					cuts = append(cuts, "cleanup-entry", "cleanup-copy")
				}
				for _, cut := range cuts {
					t.Run(fmt.Sprintf("move=%v/old=%v/committed=%v/%s", move, existing, committed, cut), func(t *testing.T) {
						root := t.TempDir()
						mustWrite(t, filepath.Join(root, "src", "file"), "new")
						if existing {
							mustWrite(t, filepath.Join(root, "dst", "file"), "old")
							mustWrite(t, filepath.Join(root, "dst", "nested", "other"), "another old file")
						}
						first := "published"
						if committed {
							first = "committed"
						}
						replacementCut(t, root, move, true, false, first)
						replacementCut(t, root, move, true, true, cut)
						for range 2 {
							if err := RecoverLocked(root); err != nil {
								t.Fatal(err)
							}
						}
						assertReplacementResult(t, root, move, true, existing, committed)
					})
				}
			}
		}
	}
}

func TestReplacementRelocationAtEveryBoundary(t *testing.T) {
	for _, move := range []bool{false, true} {
		for _, directory := range []bool{false, true} {
			for _, existing := range []bool{false, true} {
				for _, cut := range []string{"prepared", "backed-up", "published", "committed", "cleaned"} {
					t.Run(fmt.Sprintf("move=%v/dir=%v/old=%v/%s", move, directory, existing, cut), func(t *testing.T) {
						parent := t.TempDir()
						root := filepath.Join(parent, "before")
						suffix := ""
						if directory {
							suffix = "/file"
						}
						mustWrite(t, filepath.Join(root, "src")+suffix, "new")
						if existing {
							mustWrite(t, filepath.Join(root, "dst")+suffix, "old")
						}
						replacementCut(t, root, move, directory, false, cut)
						after := filepath.Join(parent, "after")
						if err := os.Rename(root, after); err != nil {
							t.Fatal(err)
						}
						for range 2 {
							if err := RecoverLocked(after); err != nil {
								t.Fatal(err)
							}
						}
						assertReplacementResult(t, after, move, directory, existing, cut == "committed" || cut == "cleaned")
					})
				}
			}
		}
	}
}

func TestReplacementRecoveryPreservesChangedTree(t *testing.T) {
	for _, committed := range []bool{false, true} {
		for _, edit := range []string{"rewrite-preserving-attributes", "new-child", "replaced-child", "missing-child", "symlink-child"} {
			t.Run(fmt.Sprintf("committed=%v/%s", committed, edit), func(t *testing.T) {
				root := t.TempDir()
				mustWrite(t, filepath.Join(root, "src", "file"), "new")
				mustWrite(t, filepath.Join(root, "dst", "file"), "old")
				cut := "published"
				if committed {
					cut = "committed"
				}
				replacementCut(t, root, false, true, false, cut)
				journal, state := replacementJournal(t, root)
				target := filepath.Join(root, state.Destination)
				if committed {
					target = filepath.Join(root, state.Backup)
				}
				file := filepath.Join(target, "file")
				info, err := os.Stat(file)
				if err != nil {
					t.Fatal(err)
				}
				switch edit {
				case "rewrite-preserving-attributes":
					mustWrite(t, file, "XXX")
					if err = os.Chtimes(file, info.ModTime(), info.ModTime()); err != nil {
						t.Fatal(err)
					}
				case "new-child":
					mustWrite(t, filepath.Join(target, "new-child"), "offline data")
				case "replaced-child":
					atomicRecoveryEdit(t, file, "offline replacement")
				case "missing-child":
					if err = os.Remove(file); err != nil {
						t.Fatal(err)
					}
				case "symlink-child":
					if err = os.Remove(file); err != nil {
						t.Fatal(err)
					}
					if err = os.Symlink(filepath.Join(t.TempDir(), "outside"), file); err != nil {
						t.Fatal(err)
					}
				}
				// Missing backup entries are valid after interrupted committed cleanup.
				if committed && edit == "missing-child" {
					if err = RecoverLocked(root); err != nil {
						t.Fatal(err)
					}
					assertReplacementResult(t, root, false, true, true, true)
					return
				}
				for range 2 {
					if err = RecoverLocked(root); err == nil {
						t.Fatal("accepted a changed recovery tree")
					}
					if _, err = os.Stat(journal); err != nil {
						t.Fatal("discarded journal", err)
					}
				}
				switch edit {
				case "rewrite-preserving-attributes":
					wantBody(t, file, "XXX")
				case "new-child":
					wantBody(t, filepath.Join(target, "new-child"), "offline data")
				case "replaced-child":
					wantBody(t, file, "offline replacement")
				case "symlink-child":
					if _, err = os.Readlink(file); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestReplacementRecoveryLegacyAndMalformedJournals(t *testing.T) {
	for _, kind := range []string{"legacy", "truncated", "absolute", "escape", "overlap", "private", "empty", "unknown-version", "symlink-journal", "symlink-journal-dir"} {
		t.Run(kind, func(t *testing.T) {
			root := interruptedReplacement(t, false)
			journal, state := replacementJournal(t, root)
			backup := filepath.Join(root, state.Backup)
			switch kind {
			case "legacy":
				data := fmt.Sprintf(`{"destination":%q,"source":"","backup":%q,"had_destination":true,"committed":false}`, filepath.Join(root, state.Destination), backup)
				if err := os.WriteFile(journal, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.WriteFile(journal, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink-journal":
				other := filepath.Join(t.TempDir(), "journal.json")
				if err := os.Rename(journal, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, journal); err != nil {
					t.Fatal(err)
				}
			case "symlink-journal-dir":
				other := filepath.Join(t.TempDir(), "journals")
				dir := filepath.Dir(journal)
				if err := os.Rename(dir, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, dir); err != nil {
					t.Fatal(err)
				}
			default:
				switch kind {
				case "absolute":
					state.Destination = filepath.Join(root, state.Destination)
				case "escape":
					state.Destination = "../outside"
				case "overlap":
					state.Source = state.Destination
				case "private":
					state.Destination = ".sebastian/storage-id"
				case "empty":
					state.New = nil
				case "unknown-version":
					state.Format = 99
				}
				if err := writeReplacement(journal, state); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if err := RecoverLocked(root); err == nil {
					t.Fatal("accepted unsafe journal")
				}
			}
			wantBody(t, backup, "original destination")
			wantBody(t, filepath.Join(root, "dir", "destination"), "published copy")
		})
	}
}

func TestReplacementPermissionFailureCanRetry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged permissions")
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "src", "file"), "new")
	mustWrite(t, filepath.Join(root, "dst", "file"), "old")
	replacementCut(t, root, false, true, false, "committed")
	journal, state := replacementJournal(t, root)
	file := filepath.Join(root, state.Backup, "file")
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(file, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(file, info.Mode())
	if err = RecoverLocked(root); err == nil {
		t.Fatal("recovery accepted unreadable backup")
	}
	if _, err = os.Stat(journal); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(file, info.Mode()); err != nil {
		t.Fatal(err)
	}
	wantBody(t, file, "old")
	if err = RecoverLocked(root); err != nil {
		t.Fatal(err)
	}
	assertReplacementResult(t, root, false, true, true, true)
}

func TestReplacementBlockedMoveResumesWithoutLosingEitherSource(t *testing.T) {
	root := interruptedReplacement(t, true)
	source := filepath.Join(root, "source")
	mustWrite(t, source, "new offline source")
	for range 2 {
		if err := RecoverLocked(root); err == nil {
			t.Fatal("accepted occupied rollback source")
		}
	}
	saved := filepath.Join(root, "saved-offline-source")
	if err := os.Rename(source, saved); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := RecoverLocked(root); err != nil {
			t.Fatal(err)
		}
	}
	wantBody(t, saved, "new offline source")
	wantBody(t, source, "original source")
	wantBody(t, filepath.Join(root, "dir", "destination"), "original destination")
}
