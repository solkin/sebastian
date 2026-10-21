//go:build unix

package fileops

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReplacementProcessCuts(t *testing.T) {
	if root := os.Getenv("SEBASTIAN_REPLACE_ROOT"); root != "" {
		checkpoint := func(step string) {
			if step == os.Getenv("SEBASTIAN_REPLACE_CUT") {
				killReplacementProcess(t)
			}
		}
		if os.Getenv("SEBASTIAN_REPLACE_RECOVER") == "true" {
			err := recoverLocked(root, checkpoint)
			t.Fatalf("recovery child missed cut: %v", err)
		}
		src, dst := filepath.Join(root, "src"), filepath.Join(root, "dst")
		move := os.Getenv("SEBASTIAN_REPLACE_MOVE") == "true"
		directory := os.Getenv("SEBASTIAN_REPLACE_DIRECTORY") == "true"
		moveSrc := ""
		if move {
			moveSrc = src
		}
		var build func(string) error
		if !move {
			build = func(stage string) error {
				if directory {
					if err := os.Mkdir(stage, 0700); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(stage, "file"), []byte("new"), 0600)
				}
				return os.WriteFile(stage, []byte("new"), 0600)
			}
		}
		err := replaceLocked(root, moveSrc, dst, build, checkpoint)
		t.Fatalf("child missed cut: %v", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, move := range []bool{false, true} {
		for _, directory := range []bool{false, true} {
			for _, existing := range []bool{false, true} {
				for _, cut := range []string{"prepared", "backed-up", "published", "committed", "cleaned"} {
					t.Run(fmt.Sprintf("move=%v/dir=%v/exists=%v/%s", move, directory, existing, cut), func(t *testing.T) {
						root := t.TempDir()
						src, dst := filepath.Join(root, "src"), filepath.Join(root, "dst")
						suffix := ""
						if directory {
							suffix = "/file"
						}
						mustWrite(t, src+suffix, "new")
						if existing {
							mustWrite(t, dst+suffix, "old")
						}
						cmd := exec.Command(binary, "-test.run=^TestReplacementProcessCuts$")
						cmd.Env = append(os.Environ(), "SEBASTIAN_REPLACE_ROOT="+root, fmt.Sprintf("SEBASTIAN_REPLACE_MOVE=%v", move), fmt.Sprintf("SEBASTIAN_REPLACE_DIRECTORY=%v", directory), "SEBASTIAN_REPLACE_CUT="+cut)
						out, err := cmd.CombinedOutput()
						var exit *exec.ExitError
						if !errors.As(err, &exit) {
							t.Fatalf("child: %v %s", err, out)
						}
						status, ok := exit.Sys().(syscall.WaitStatus)
						if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
							t.Fatalf("wrong child failure: %v %s", err, out)
						}
						for range 2 {
							if err = RecoverLocked(root); err != nil {
								t.Fatal(err)
							}
						}
						committed := cut == "committed" || cut == "cleaned"
						if committed {
							wantBody(t, dst+suffix, "new")
						} else if existing {
							wantBody(t, dst+suffix, "old")
						} else if _, err = os.Stat(dst); !os.IsNotExist(err) {
							t.Fatal("uncommitted destination exists")
						}
						if move && committed {
							if _, err = os.Stat(src); !os.IsNotExist(err) {
								t.Fatal("move source survived commit")
							}
						} else {
							wantBody(t, src+suffix, "new")
						}
						entries, _ := os.ReadDir(root)
						for _, e := range entries {
							if strings.HasPrefix(e.Name(), ".seb-bak-") {
								t.Fatalf("backup leaked: %s", e.Name())
							}
						}
					})
				}
			}
		}
	}
}

// A self-directed SIGKILL can be delivered after Kill returns. Keep the child at
// the chosen boundary so no cleanup runs while the signal is pending.
func killReplacementProcess(t *testing.T) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}
