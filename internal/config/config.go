// Package config loads and validates sebastian configuration from YAML files
// and environment variables.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration.
type Config struct {
	RootDir  string   `yaml:"root_dir"`
	Gateways Gateways `yaml:"gateways"`
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

	return nil
}
