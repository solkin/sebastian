package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestSecurityWarnings(t *testing.T) {
	open := &Config{Gateways: Gateways{
		S3:     S3Config{Enabled: true},
		WebDAV: WebDAVConfig{Enabled: true},
		HTTP:   HTTPConfig{Enabled: true},
		SFTP:   SFTPConfig{Enabled: true},
	}}
	if got := SecurityWarnings(open); len(got) != 4 {
		t.Fatalf("expected 4 warnings for open gateways, got %d: %v", len(got), got)
	}

	secured := &Config{Gateways: Gateways{
		S3:     S3Config{Enabled: true, AccessKey: "a", SecretKey: "b"},
		WebDAV: WebDAVConfig{Enabled: true, Username: "u", Password: "p"},
		HTTP:   HTTPConfig{Enabled: false},
		SFTP:   SFTPConfig{Enabled: true, Username: "u", Password: "p"},
	}}
	if got := SecurityWarnings(secured); len(got) != 0 {
		t.Fatalf("expected no warnings for secured/disabled gateways, got %v", got)
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

func TestLoad_MultipartDefaults(t *testing.T) {
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
	// An omitted active-upload limit is finite; explicit zero stays unlimited.
	if cfg.Multipart.MaxActiveUploads != 10000 {
		t.Fatalf("max_active_uploads = %d, want 10000", cfg.Multipart.MaxActiveUploads)
	}
	cfg.Multipart.MaxActiveUploads = 0
	if cfg.Multipart != (MultipartConfig{}) {
		t.Fatalf("expected zero multipart config, got %+v", cfg.Multipart)
	}
}

func TestLoad_MultipartConfig(t *testing.T) {
	path := writeYAML(t, `
root_dir: /tmp/test
multipart:
  min_part_bytes: 1048576
  max_part_bytes: 104857600
  max_parts: 500
  max_active_uploads: 20
  max_concurrent_part_uploads: 4
  upload_ttl: 48h
  cleanup_interval: 15m
  temp_file_max_age: 6h
gateways:
  s3:
    enabled: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m := cfg.Multipart
	if m.MinPartBytes != 1048576 || m.MaxPartBytes != 104857600 {
		t.Fatalf("part size limits = %d/%d", m.MinPartBytes, m.MaxPartBytes)
	}
	if m.MaxParts != 500 || m.MaxActiveUploads != 20 || m.MaxConcurrentPartUploads != 4 {
		t.Fatalf("count limits = %+v", m)
	}
	if m.UploadTTL != 48*time.Hour || m.CleanupInterval != 15*time.Minute || m.TempFileMaxAge != 6*time.Hour {
		t.Fatalf("durations = %v/%v/%v", m.UploadTTL, m.CleanupInterval, m.TempFileMaxAge)
	}
}

func TestLoad_MultipartEnvOverride(t *testing.T) {
	path := writeYAML(t, `
root_dir: /tmp/test
multipart:
  max_parts: 500
  upload_ttl: 48h
gateways:
  s3:
    enabled: true
`)
	t.Setenv("SEBASTIAN_MULTIPART_MAX_PARTS", "77")
	t.Setenv("SEBASTIAN_MULTIPART_MIN_PART_BYTES", "2048")
	t.Setenv("SEBASTIAN_MULTIPART_MAX_CONCURRENT_PART_UPLOADS", "8")
	t.Setenv("SEBASTIAN_MULTIPART_UPLOAD_TTL", "90m")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Multipart.MaxParts != 77 {
		t.Fatalf("max_parts = %d, want 77", cfg.Multipart.MaxParts)
	}
	if cfg.Multipart.MinPartBytes != 2048 {
		t.Fatalf("min_part_bytes = %d, want 2048", cfg.Multipart.MinPartBytes)
	}
	if cfg.Multipart.MaxConcurrentPartUploads != 8 {
		t.Fatalf("max_concurrent_part_uploads = %d, want 8", cfg.Multipart.MaxConcurrentPartUploads)
	}
	if cfg.Multipart.UploadTTL != 90*time.Minute {
		t.Fatalf("upload_ttl = %v, want 90m", cfg.Multipart.UploadTTL)
	}
}

func TestLoad_MultipartInvalidValues(t *testing.T) {
	cases := map[string]string{
		"min above max": `
multipart:
  min_part_bytes: 100
  max_part_bytes: 10
`,
		"negative max parts": `
multipart:
  max_parts: -1
`,
		"negative ttl": `
multipart:
  upload_ttl: -1h
`,
	}
	for name, fragment := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeYAML(t, "root_dir: /tmp/test\ngateways:\n  s3:\n    enabled: true\n"+fragment)
			if _, err := Load(path); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
