package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestGatewayWithoutCredentialsFailsBeforeOpeningStorage(t *testing.T) {
	dir := t.TempDir()
	rootDir := filepath.Join(dir, "files")
	path := filepath.Join(dir, "config.yaml")
	data := fmt.Sprintf("root_dir: %q\ngateways:\n  s3:\n    enabled: true\n    access_key: only-key\n", rootDir)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(path); err == nil || !strings.Contains(err.Error(), "needs both") {
		t.Fatalf("expected half-configured S3 to fail startup, got %v", err)
	}
	if _, err := os.Stat(rootDir); !os.IsNotExist(err) {
		t.Fatalf("startup touched storage %s: %v", rootDir, err)
	}
}

func TestComponentListenFailureIsReturned(t *testing.T) {
	for _, gw := range []string{"s3", "webdav", "http", "sftp"} {
		t.Run(gw, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			dir := t.TempDir()
			data := fmt.Sprintf("root_dir: %q\ngateways:\n", filepath.Join(dir, "files"))
			for _, name := range []string{"s3", "webdav", "http", "sftp"} {
				addr := "127.0.0.1:0"
				if name == gw {
					addr = ln.Addr().String()
				}
				data += fmt.Sprintf("  %s:\n    enabled: true\n    allow_anonymous: true\n    listen_addr: %q\n", name, addr)
				if name == "sftp" {
					data += fmt.Sprintf("    host_key_path: %q\n", filepath.Join(dir, "sftp_host_key"))
				}
			}
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := run(path); !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatalf("listen failure must reach main: %v", err)
			}
		})
	}
}
