package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	path := writeYAML(t, `
root_dir: /tmp/test
gateways:
  s3:
    enabled: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.RootDir != "/tmp/test" {
		t.Fatalf("expected /tmp/test, got %s", cfg.RootDir)
	}
	if cfg.Gateways.S3.ListenAddr != ":9200" {
		t.Fatalf("expected default S3 addr :9200, got %s", cfg.Gateways.S3.ListenAddr)
	}
	if cfg.Gateways.WebDAV.ListenAddr != ":9300" {
		t.Fatalf("expected default WebDAV addr :9300, got %s", cfg.Gateways.WebDAV.ListenAddr)
	}
	if cfg.Gateways.HTTP.ListenAddr != ":9400" {
		t.Fatalf("expected default HTTP addr :9400, got %s", cfg.Gateways.HTTP.ListenAddr)
	}
	if cfg.Gateways.SFTP.ListenAddr != ":9500" {
		t.Fatalf("expected default SFTP addr :9500, got %s", cfg.Gateways.SFTP.ListenAddr)
	}
}

func TestLoad_FullConfig(t *testing.T) {
	path := writeYAML(t, `
root_dir: /data/files
gateways:
  s3:
    enabled: true
    listen_addr: ":8200"
    access_key: admin
    secret_key: secret123
  webdav:
    enabled: true
    listen_addr: ":8300"
    username: user
    password: pass
  http:
    enabled: true
    listen_addr: ":8400"
  sftp:
    enabled: true
    listen_addr: ":8500"
    host_key_path: /etc/sebastian/host_key
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Gateways.S3.Enabled {
		t.Fatal("S3 should be enabled")
	}
	if cfg.Gateways.S3.ListenAddr != ":8200" {
		t.Fatalf("expected :8200, got %s", cfg.Gateways.S3.ListenAddr)
	}
	if cfg.Gateways.S3.AccessKey != "admin" {
		t.Fatalf("expected admin, got %s", cfg.Gateways.S3.AccessKey)
	}
	if cfg.Gateways.WebDAV.Username != "user" {
		t.Fatalf("expected user, got %s", cfg.Gateways.WebDAV.Username)
	}
	if cfg.Gateways.SFTP.HostKeyPath != "/etc/sebastian/host_key" {
		t.Fatalf("expected host_key_path, got %s", cfg.Gateways.SFTP.HostKeyPath)
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	path := writeYAML(t, `
root_dir: /original
gateways:
  s3:
    enabled: true
    access_key: file-key
`)
	t.Setenv("SEBASTIAN_ROOT_DIR", "/from-env")
	t.Setenv("SEBASTIAN_S3_ACCESS_KEY", "env-key")
	t.Setenv("SEBASTIAN_S3_LISTEN_ADDR", ":7200")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.RootDir != "/from-env" {
		t.Fatalf("expected /from-env, got %s", cfg.RootDir)
	}
	if cfg.Gateways.S3.AccessKey != "env-key" {
		t.Fatalf("expected env-key, got %s", cfg.Gateways.S3.AccessKey)
	}
	if cfg.Gateways.S3.ListenAddr != ":7200" {
		t.Fatalf("expected :7200, got %s", cfg.Gateways.S3.ListenAddr)
	}
}

func TestLoad_BoolEnvOverride(t *testing.T) {
	path := writeYAML(t, `
root_dir: /tmp/test
gateways:
  s3:
    enabled: false
`)
	t.Setenv("SEBASTIAN_S3_ENABLED", "true")
	t.Setenv("SEBASTIAN_HTTP_ENABLED", "1")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Gateways.S3.Enabled {
		t.Fatal("S3 should be enabled by env")
	}
	if !cfg.Gateways.HTTP.Enabled {
		t.Fatal("HTTP should be enabled by env")
	}
}

func TestLoad_NoGateways(t *testing.T) {
	path := writeYAML(t, `
root_dir: /tmp/test
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error when no gateways enabled")
	}
}

func TestLoad_SFTPWithoutHostKeyPath(t *testing.T) {
	path := writeYAML(t, `
root_dir: /tmp/test
gateways:
  sftp:
    enabled: true
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error when SFTP enabled without host_key_path")
	}
}

func TestLoad_NoFile(t *testing.T) {
	t.Setenv("SEBASTIAN_ROOT_DIR", "/tmp/test")
	t.Setenv("SEBASTIAN_S3_ENABLED", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load without file: %v", err)
	}
	if cfg.RootDir != "/tmp/test" {
		t.Fatalf("expected /tmp/test, got %s", cfg.RootDir)
	}
}

func TestLoad_BadYAML(t *testing.T) {
	path := writeYAML(t, `invalid: [`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for bad YAML")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"yes", true},
		{"YES", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"", false},
		{"anything", false},
	}
	for _, tt := range tests {
		got := parseBool(tt.input)
		if got != tt.want {
			t.Errorf("parseBool(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return path
}
