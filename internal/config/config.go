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
	// AccessLog writes one line per request at info level. At a thousand
	// requests a second that is tens of gigabytes a day.
	AccessLog bool `yaml:"access_log"`
	// MaxUploadBytes caps the size of a single uploaded object/file across the S3,
	// WebDAV, SFTP, and HTTP UI gateways. 0 means unlimited.
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
	// AllowAnonymous is the only way to serve the gateway without
	// credentials; see checkCredentials.
	AllowAnonymous bool   `yaml:"allow_anonymous"`
	Domain         string `yaml:"domain"`
	// Buckets are created at startup when missing, so that they exist before a
	// client that cannot create them, or should not, first asks for them.
	Buckets []string `yaml:"buckets"`
}

// WebDAVConfig holds WebDAV gateway settings.
type WebDAVConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ListenAddr     string `yaml:"listen_addr"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	AllowAnonymous bool   `yaml:"allow_anonymous"`
}

// HTTPConfig holds HTTP UI gateway settings.
type HTTPConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ListenAddr     string `yaml:"listen_addr"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	AllowAnonymous bool   `yaml:"allow_anonymous"`
}

// SFTPConfig holds SFTP gateway settings.
type SFTPConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ListenAddr     string `yaml:"listen_addr"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	AllowAnonymous bool   `yaml:"allow_anonymous"`
	HostKeyPath    string `yaml:"host_key_path"`
}

// Load reads configuration from a YAML file, applies environment variable
// overrides, and sets defaults.
func Load(path string) (*Config, error) {
	// Seed this default before YAML parsing: an explicit zero means unlimited.
	cfg := &Config{AccessLog: true, Multipart: MultipartConfig{MaxActiveUploads: 10000}}

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
	if err := applyEnv(cfg); err != nil {
		return nil, fmt.Errorf("environment: %w", err)
	}

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

	// Other unset multipart fields are resolved by the multipart store.
}

// applyEnv overrides settings with environment variables. A nonempty value
// that does not parse stops startup: falling back silently to a default left an
// operator running with a limit, a gateway or a duration nobody asked for.
func applyEnv(cfg *Config) error {
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

	if v := os.Getenv("SEBASTIAN_S3_BUCKETS"); v != "" {
		cfg.Gateways.S3.Buckets = splitList(v)
	}

	envBoolMap := map[string]*bool{
		"SEBASTIAN_ACCESS_LOG":             &cfg.AccessLog,
		"SEBASTIAN_S3_ENABLED":             &cfg.Gateways.S3.Enabled,
		"SEBASTIAN_S3_ALLOW_ANONYMOUS":     &cfg.Gateways.S3.AllowAnonymous,
		"SEBASTIAN_WEBDAV_ENABLED":         &cfg.Gateways.WebDAV.Enabled,
		"SEBASTIAN_WEBDAV_ALLOW_ANONYMOUS": &cfg.Gateways.WebDAV.AllowAnonymous,
		"SEBASTIAN_HTTP_ENABLED":           &cfg.Gateways.HTTP.Enabled,
		"SEBASTIAN_HTTP_ALLOW_ANONYMOUS":   &cfg.Gateways.HTTP.AllowAnonymous,
		"SEBASTIAN_SFTP_ENABLED":           &cfg.Gateways.SFTP.Enabled,
		"SEBASTIAN_SFTP_ALLOW_ANONYMOUS":   &cfg.Gateways.SFTP.AllowAnonymous,
	}
	for env, ptr := range envBoolMap {
		if v := os.Getenv(env); v != "" {
			b, err := parseBool(v)
			if err != nil {
				return fmt.Errorf("%s: %w", env, err)
			}
			*ptr = b
		}
	}

	envInt64Map := map[string]*int64{
		"SEBASTIAN_MAX_UPLOAD_BYTES":         &cfg.MaxUploadBytes,
		"SEBASTIAN_MULTIPART_MIN_PART_BYTES": &cfg.Multipart.MinPartBytes,
		"SEBASTIAN_MULTIPART_MAX_PART_BYTES": &cfg.Multipart.MaxPartBytes,
	}
	for env, ptr := range envInt64Map {
		if v := os.Getenv(env); v != "" {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return fmt.Errorf("%s: %w", env, err)
			}
			*ptr = n
		}
	}

	envIntMap := map[string]*int{
		"SEBASTIAN_MULTIPART_MAX_PARTS":                   &cfg.Multipart.MaxParts,
		"SEBASTIAN_MULTIPART_MAX_ACTIVE_UPLOADS":          &cfg.Multipart.MaxActiveUploads,
		"SEBASTIAN_MULTIPART_MAX_CONCURRENT_PART_UPLOADS": &cfg.Multipart.MaxConcurrentPartUploads,
	}
	for env, ptr := range envIntMap {
		if v := os.Getenv(env); v != "" {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%s: %w", env, err)
			}
			*ptr = n
		}
	}

	envDurationMap := map[string]*time.Duration{
		"SEBASTIAN_MULTIPART_UPLOAD_TTL":        &cfg.Multipart.UploadTTL,
		"SEBASTIAN_MULTIPART_CLEANUP_INTERVAL":  &cfg.Multipart.CleanupInterval,
		"SEBASTIAN_MULTIPART_TEMP_FILE_MAX_AGE": &cfg.Multipart.TempFileMaxAge,
	}
	for env, ptr := range envDurationMap {
		if v := os.Getenv(env); v != "" {
			d, err := time.ParseDuration(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%s: %w", env, err)
			}
			*ptr = d
		}
	}
	return nil
}

// splitList reads a comma-separated list, dropping blanks around and between
// its items.
func splitList(s string) []string {
	var items []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("must be true/false, yes/no, or 1/0")
	}
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
	if err := checkCredentials(cfg); err != nil {
		return err
	}

	if cfg.MaxUploadBytes < 0 {
		return fmt.Errorf("max_upload_bytes must not be negative")
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

// credentialPair is one gateway's authentication settings, named for errors.
type credentialPair struct {
	gateway, first, second string
	a, b                   string
	enabled, anonymous     bool
}

func credentialPairs(cfg *Config) []credentialPair {
	g := cfg.Gateways
	return []credentialPair{
		{"gateways.s3", "access_key", "secret_key", g.S3.AccessKey, g.S3.SecretKey, g.S3.Enabled, g.S3.AllowAnonymous},
		{"gateways.webdav", "username", "password", g.WebDAV.Username, g.WebDAV.Password, g.WebDAV.Enabled, g.WebDAV.AllowAnonymous},
		{"gateways.http", "username", "password", g.HTTP.Username, g.HTTP.Password, g.HTTP.Enabled, g.HTTP.AllowAnonymous},
		{"gateways.sftp", "username", "password", g.SFTP.Username, g.SFTP.Password, g.SFTP.Enabled, g.SFTP.AllowAnonymous},
	}
}

// checkCredentials fails closed. An enabled gateway needs both credentials,
// unless it explicitly allows anonymous access with neither. A missing
// environment variable used to open the whole directory for anonymous writes,
// and one credential alone was worse than none: an empty secret key or
// password is a value anyone can sign or log in with.
func checkCredentials(cfg *Config) error {
	for _, p := range credentialPairs(cfg) {
		if !p.enabled {
			continue
		}
		switch {
		case p.a == "" && p.b == "" && !p.anonymous:
			return fmt.Errorf("%s is enabled without %s/%s; set both, or set %s.allow_anonymous: true to serve without authentication", p.gateway, p.first, p.second, p.gateway)
		case (p.a == "") != (p.b == ""):
			return fmt.Errorf("%s needs both %s and %s; one alone lets anyone in with an empty value", p.gateway, p.first, p.second)
		case isPlaceholder(p.a) || isPlaceholder(p.b):
			return fmt.Errorf("%s credentials still contain an example placeholder (changeme); set real values", p.gateway)
		}
	}
	return nil
}

// isPlaceholder recognizes the example values shipped in .env.example, which
// are public and therefore not credentials.
func isPlaceholder(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "changeme")
}

// SecurityWarnings returns messages for gateways an operator explicitly opened
// to anonymous access: allowed, but anyone who reaches them can read, write
// and delete.
func SecurityWarnings(cfg *Config) []string {
	var warnings []string
	for _, p := range credentialPairs(cfg) {
		if p.enabled && p.anonymous && p.a == "" && p.b == "" {
			warnings = append(warnings, p.gateway+" allows anonymous access; anyone who reaches it can read, write and delete")
		}
	}
	return warnings
}
