//go:build unix

package fileops

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestLeaseExcludesAnotherProcessAndSurvivesKill(t *testing.T) {
	if dir := os.Getenv("SEBASTIAN_LEASE_CHILD"); dir != "" {
		release, err := AcquireLease(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		fmt.Println("locked")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	root := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestLeaseExcludesAnotherProcessAndSurvivesKill$")
	cmd.Env = append(os.Environ(), "SEBASTIAN_LEASE_CHILD="+root)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child startup: %q %v", line, err)
	}
	if release, err := AcquireLease(root); err == nil {
		release()
		t.Fatal("two processes acquired the same lease")
	}
	cmd.Process.Kill()
	cmd.Wait()
	release, err := AcquireLease(root)
	if err != nil {
		t.Fatalf("lease remained after SIGKILL: %v", err)
	}
	release()
}
