package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnknownYAMLFieldRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("root_dir: /tmp/s\nunknown_field: true\ngateways:\n  http:\n    enabled: true\n    allow_anonymous: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown YAML field to fail Load")
	}
}

func TestWhitespaceCredentialsAndPortCollisionRefused(t *testing.T) {
	dir := t.TempDir()
	wsPath := filepath.Join(dir, "ws.yaml")
	wsData := "root_dir: /tmp/s\ngateways:\n  http:\n    enabled: true\n    username: \"   \"\n    password: \"   \"\n"
	os.WriteFile(wsPath, []byte(wsData), 0o600)
	if _, err := Load(wsPath); err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("expected whitespace credentials error, got %v", err)
	}

	dupPath := filepath.Join(dir, "dup.yaml")
	dupData := "root_dir: /tmp/s\ngateways:\n  http:\n    enabled: true\n    allow_anonymous: true\n    listen_addr: \":9200\"\n  webdav:\n    enabled: true\n    allow_anonymous: true\n    listen_addr: \":9200\"\n"
	os.WriteFile(dupPath, []byte(dupData), 0o600)
	if _, err := Load(dupPath); err == nil || !strings.Contains(err.Error(), "conflicts with") {
		t.Fatalf("expected port collision error, got %v", err)
	}

	partPath := filepath.Join(dir, "part.yaml")
	partData := "root_dir: /tmp/s\ngateways:\n  http:\n    enabled: true\n    allow_anonymous: true\nmultipart:\n  max_part_bytes: 1024\n"
	os.WriteFile(partPath, []byte(partData), 0o600)
	if _, err := Load(partPath); err == nil || !strings.Contains(err.Error(), "min_part_bytes") {
		t.Fatalf("expected one-sided max_part_bytes < default min_part_bytes to fail, got %v", err)
	}
}
