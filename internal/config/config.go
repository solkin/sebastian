// Package config loads and validates sebastian configuration from YAML files
// and environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration.
type Config struct {
	RootDir string `yaml:"root_dir"`
	// MaxUploadBytes caps the size of a single uploaded object/file across the S3,
	// WebDAV, and HTTP UI gateways. 0 means unlimited.
	MaxUploadBytes int64           `yaml:"max_upload_bytes"`
	Multipart      MultipartConfig `yaml:"multipart"`
	Gateways       Gateways        `yaml:"gateways"`
}

// MultipartConfig holds limits and retention settings for S3 multipart uploads.
// Sizes are in bytes; durations use Go duration syntax ("24h", "30m").
type MultipartConfig struct {
	// MinPartBytes is the minimum size of every part but the last (S3: 5 MiB).
	MinPartBytes int64 `yaml:"min_part_bytes"`
	// MaxPartBytes is the maximum size of a single part (S3: 5 GiB).
	MaxPartBytes int64 `yaml:"max_part_bytes"`
	// MaxParts is the highest accepted part number (S3: 10000).
	MaxParts int `yaml:"max_parts"`
	// MaxActiveUploads caps simultaneously staged uploads; 0 means unlimited.
	MaxActiveUploads int `yaml:"max_active_uploads"`
	// MaxConcurrentPartUploads caps in-flight part uploads across all uploads;
	// 0 means unlimited. Requests over the cap are rejected with SlowDown, which
	// every S3 SDK retries with backoff.
	MaxConcurrentPartUploads int `yaml:"max_concurrent_part_uploads"`
	// UploadTTL is how long an untouched incomplete upload is kept before the
	// janitor discards it.
	UploadTTL time.Duration `yaml:"upload_ttl"`
	// CleanupInterval is how often the janitor sweeps.
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
	// TempFileMaxAge is how old an orphaned atomic-write scratch file must be
	// before a running server removes it.
	TempFileMaxAge time.Duration `yaml:"temp_file_max_age"`
}

// Gateways groups all gateway configurations.
type Gateways struct {
	S3     S3Config     `yaml:"s3"`
	WebDAV WebDAVConfig `yaml:"webdav"`
	HTTP   HTTPConfig   `yaml:"http"`
	SFTP   SFTPConfig   `yaml:"sftp"`
}

// S3Config holds S3 gateway settings.
type S3Config struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	AccessKey  string `yaml:"access_key"`
	SecretKey  string `yaml:"secret_key"`
	Domain     string `yaml:"domain"`
}

// WebDAVConfig holds WebDAV gateway settings.
type WebDAVConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
}

// HTTPConfig holds HTTP UI gateway settings.
type HTTPConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
}

// SFTPConfig holds SFTP gateway settings.
type SFTPConfig struct {
	Enabled     bool   `yaml:"enabled"`
	ListenAddr  string `yaml:"listen_addr"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	HostKeyPath string `yaml:"host_key_path"`
}

// Load reads configuration from a YAML file, applies environment variable
// overrides, and sets defaults.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	applyDefaults(cfg)
	applyEnv(cfg)

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.RootDir == "" {
		cfg.RootDir = "/data/files"
	}
	if cfg.Gateways.S3.ListenAddr == "" {
		cfg.Gateways.S3.ListenAddr = ":9200"
	}
	if cfg.Gateways.WebDAV.ListenAddr == "" {
		cfg.Gateways.WebDAV.ListenAddr = ":9300"
	}
	if cfg.Gateways.HTTP.ListenAddr == "" {
		cfg.Gateways.HTTP.ListenAddr = ":9400"
	}
	if cfg.Gateways.SFTP.ListenAddr == "" {
		cfg.Gateways.SFTP.ListenAddr = ":9500"
	}

	// Unset multipart fields stay zero and are resolved to the S3-compatible
	// defaults by the multipart store, so there is a single source of truth for
	// them.
}

func applyEnv(cfg *Config) {
	envMap := map[string]*string{
		"SEBASTIAN_ROOT_DIR":           &cfg.RootDir,
		"SEBASTIAN_S3_LISTEN_ADDR":     &cfg.Gateways.S3.ListenAddr,
		"SEBASTIAN_S3_ACCESS_KEY":      &cfg.Gateways.S3.AccessKey,
		"SEBASTIAN_S3_SECRET_KEY":      &cfg.Gateways.S3.SecretKey,
		"SEBASTIAN_S3_DOMAIN":          &cfg.Gateways.S3.Domain,
		"SEBASTIAN_WEBDAV_LISTEN_ADDR": &cfg.Gateways.WebDAV.ListenAddr,
		"SEBASTIAN_WEBDAV_USERNAME":    &cfg.Gateways.WebDAV.Username,
		"SEBASTIAN_WEBDAV_PASSWORD":    &cfg.Gateways.WebDAV.Password,
		"SEBASTIAN_HTTP_LISTEN_ADDR":   &cfg.Gateways.HTTP.ListenAddr,
		"SEBASTIAN_HTTP_USERNAME":      &cfg.Gateways.HTTP.Username,
		"SEBASTIAN_HTTP_PASSWORD":      &cfg.Gateways.HTTP.Password,
		"SEBASTIAN_SFTP_LISTEN_ADDR":   &cfg.Gateways.SFTP.ListenAddr,
		"SEBASTIAN_SFTP_USERNAME":      &cfg.Gateways.SFTP.Username,
		"SEBASTIAN_SFTP_PASSWORD":      &cfg.Gateways.SFTP.Password,
		"SEBASTIAN_SFTP_HOST_KEY_PATH": &cfg.Gateways.SFTP.HostKeyPath,
	}
	for env, ptr := range envMap {
		if v := os.Getenv(env); v != "" {
			*ptr = v
		}
	}

	envBoolMap := map[string]*bool{
		"SEBASTIAN_S3_ENABLED":     &cfg.Gateways.S3.Enabled,
		"SEBASTIAN_WEBDAV_ENABLED": &cfg.Gateways.WebDAV.Enabled,
		"SEBASTIAN_HTTP_ENABLED":   &cfg.Gateways.HTTP.Enabled,
		"SEBASTIAN_SFTP_ENABLED":   &cfg.Gateways.SFTP.Enabled,
	}
	for env, ptr := range envBoolMap {
		if v := os.Getenv(env); v != "" {
			*ptr = parseBool(v)
		}
	}

	if v := os.Getenv("SEBASTIAN_MAX_UPLOAD_BYTES"); v != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && n >= 0 {
			cfg.MaxUploadBytes = n
		}
	}

	envInt64Map := map[string]*int64{
		"SEBASTIAN_MULTIPART_MIN_PART_BYTES": &cfg.Multipart.MinPartBytes,
		"SEBASTIAN_MULTIPART_MAX_PART_BYTES": &cfg.Multipart.MaxPartBytes,
	}
	for env, ptr := range envInt64Map {
		if v := os.Getenv(env); v != "" {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && n >= 0 {
				*ptr = n
			}
		}
	}

	envIntMap := map[string]*int{
		"SEBASTIAN_MULTIPART_MAX_PARTS":                   &cfg.Multipart.MaxParts,
		"SEBASTIAN_MULTIPART_MAX_ACTIVE_UPLOADS":          &cfg.Multipart.MaxActiveUploads,
		"SEBASTIAN_MULTIPART_MAX_CONCURRENT_PART_UPLOADS": &cfg.Multipart.MaxConcurrentPartUploads,
	}
	for env, ptr := range envIntMap {
		if v := os.Getenv(env); v != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
				*ptr = n
			}
		}
	}

	envDurationMap := map[string]*time.Duration{
		"SEBASTIAN_MULTIPART_UPLOAD_TTL":        &cfg.Multipart.UploadTTL,
		"SEBASTIAN_MULTIPART_CLEANUP_INTERVAL":  &cfg.Multipart.CleanupInterval,
		"SEBASTIAN_MULTIPART_TEMP_FILE_MAX_AGE": &cfg.Multipart.TempFileMaxAge,
	}
	for env, ptr := range envDurationMap {
		if v := os.Getenv(env); v != "" {
			if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
				*ptr = d
			}
		}
	}
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes"
}

func validate(cfg *Config) error {
	if cfg.RootDir == "" {
		return fmt.Errorf("root_dir is required")
	}

	anyEnabled := cfg.Gateways.S3.Enabled || cfg.Gateways.WebDAV.Enabled ||
		cfg.Gateways.HTTP.Enabled || cfg.Gateways.SFTP.Enabled

	if !anyEnabled {
		return fmt.Errorf("at least one gateway must be enabled")
	}

	if cfg.Gateways.SFTP.Enabled && cfg.Gateways.SFTP.HostKeyPath == "" {
		return fmt.Errorf("sftp.host_key_path is required when SFTP gateway is enabled")
	}

	m := cfg.Multipart
	if m.MinPartBytes < 0 || m.MaxPartBytes < 0 {
		return fmt.Errorf("multipart part size limits must not be negative")
	}
	// A minimum above the maximum would reject every multi-part upload with a
	// contradictory pair of errors, so refuse it at startup instead.
	if m.MinPartBytes > 0 && m.MaxPartBytes > 0 && m.MinPartBytes > m.MaxPartBytes {
		return fmt.Errorf("multipart.min_part_bytes must not exceed multipart.max_part_bytes")
	}
	if m.MaxParts < 0 {
		return fmt.Errorf("multipart.max_parts must not be negative")
	}
	if m.MaxActiveUploads < 0 || m.MaxConcurrentPartUploads < 0 {
		return fmt.Errorf("multipart upload count limits must not be negative")
	}
	if m.UploadTTL < 0 || m.CleanupInterval < 0 || m.TempFileMaxAge < 0 {
		return fmt.Errorf("multipart durations must not be negative")
	}

	return nil
}

// SecurityWarnings returns messages for enabled gateways that run without any
// credentials configured. Such gateways accept unauthenticated access (the
// documented open mode), which is easy to enable by accident — e.g. a default
// container run — so the operator is warned at startup rather than silently
// exposing the filesystem.
func SecurityWarnings(cfg *Config) []string {
	var warnings []string
	g := cfg.Gateways
	if g.S3.Enabled && g.S3.AccessKey == "" && g.S3.SecretKey == "" {
		warnings = append(warnings, "S3 gateway is enabled without access_key/secret_key; it accepts unauthenticated requests")
	}
	if g.WebDAV.Enabled && g.WebDAV.Username == "" && g.WebDAV.Password == "" {
		warnings = append(warnings, "WebDAV gateway is enabled without username/password; it accepts unauthenticated requests")
	}
	if g.HTTP.Enabled && g.HTTP.Username == "" && g.HTTP.Password == "" {
		warnings = append(warnings, "HTTP UI gateway is enabled without username/password; it accepts unauthenticated requests")
	}
	if g.SFTP.Enabled && g.SFTP.Username == "" && g.SFTP.Password == "" {
		warnings = append(warnings, "SFTP gateway is enabled without username/password; it accepts unauthenticated connections")
	}
	return warnings
}
