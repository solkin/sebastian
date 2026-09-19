package config

import (
	"testing"
)

func TestUploadLimitContract(t *testing.T) {
	cases := []struct {
		name, yaml, activeEnv, uploadEnv string
		active                           int
		upload                           int64
		invalid                          bool
	}{
		{name: "defaults", active: 10000},
		{name: "yaml unlimited", yaml: "multipart:\n  max_active_uploads: 0\n", active: 0},
		{name: "yaml caps", yaml: "multipart:\n  max_active_uploads: 7\nmax_upload_bytes: 42\n", active: 7, upload: 42},
		{name: "env overrides yaml", yaml: "multipart:\n  max_active_uploads: 7\nmax_upload_bytes: 42\n", activeEnv: "9", uploadEnv: "84", active: 9, upload: 84},
		{name: "env explicit unlimited", yaml: "multipart:\n  max_active_uploads: 7\nmax_upload_bytes: 42\n", activeEnv: "0", uploadEnv: "0", active: 0},
		{name: "env restores cap", yaml: "multipart:\n  max_active_uploads: 0\n", activeEnv: "5", active: 5},
		{name: "negative upload", yaml: "max_upload_bytes: -1\n", invalid: true},
		{name: "negative active", yaml: "multipart:\n  max_active_uploads: -1\n", invalid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SEBASTIAN_S3_ENABLED", "true")
			t.Setenv("SEBASTIAN_MULTIPART_MAX_ACTIVE_UPLOADS", tc.activeEnv)
			t.Setenv("SEBASTIAN_MAX_UPLOAD_BYTES", tc.uploadEnv)
			cfg, err := Load(writeYAML(t, tc.yaml))
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid limits accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Multipart.MaxActiveUploads != tc.active || cfg.MaxUploadBytes != tc.upload {
				t.Fatalf("limits = active:%d bytes:%d; want active:%d bytes:%d", cfg.Multipart.MaxActiveUploads, cfg.MaxUploadBytes, tc.active, tc.upload)
			}
		})
	}
}
