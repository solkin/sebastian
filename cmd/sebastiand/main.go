// Package main is the entry point for sebastiand — a single-node file server
// that projects S3, WebDAV, SFTP, and HTTP UI protocols onto a local directory.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/solkin/sebastian/internal/config"
	"github.com/solkin/sebastian/internal/gateway"
	"github.com/solkin/sebastian/internal/gateway/httpui"
	"github.com/solkin/sebastian/internal/gateway/s3"
	"github.com/solkin/sebastian/internal/gateway/sftp"
	"github.com/solkin/sebastian/internal/gateway/webdav"
	"github.com/solkin/sebastian/internal/multipart"
)

func main() {
	configPath := flag.String("config", "", "path to config file (optional, env vars also work)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(cfg.RootDir, 0o755); err != nil {
		logger.Error("failed to create root_dir", "path", cfg.RootDir, "error", err)
		os.Exit(1)
	}

	// Clear scratch files left by a previous crash before serving any requests.
	// No upload can be in flight yet, so age is irrelevant here.
	gateway.SweepTempFiles(cfg.RootDir, 0, logger)

	logger.Info("sebastian starting",
		"root_dir", cfg.RootDir,
		"s3", cfg.Gateways.S3.Enabled,
		"webdav", cfg.Gateways.WebDAV.Enabled,
		"http", cfg.Gateways.HTTP.Enabled,
		"sftp", cfg.Gateways.SFTP.Enabled,
	)

	for _, warning := range config.SecurityWarnings(cfg) {
		logger.Warn("insecure configuration", "detail", warning)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gateways []gateway.Gateway
	errCh := make(chan error, 4)

	// The multipart staging store is only reachable through the S3 API, but its
	// janitor also sweeps scratch files written by the other gateways, so it runs
	// whenever S3 is enabled.
	var mpStore *multipart.Store
	if cfg.Gateways.S3.Enabled {
		store, err := multipart.New(cfg.RootDir, multipart.Limits{
			MinPartBytes:       cfg.Multipart.MinPartBytes,
			MaxPartBytes:       cfg.Multipart.MaxPartBytes,
			MaxParts:           cfg.Multipart.MaxParts,
			MaxObjectBytes:     cfg.MaxUploadBytes,
			MaxActiveUploads:   cfg.Multipart.MaxActiveUploads,
			MaxConcurrentParts: cfg.Multipart.MaxConcurrentPartUploads,
			UploadTTL:          cfg.Multipart.UploadTTL,
			CleanupInterval:    cfg.Multipart.CleanupInterval,
			TempFileMaxAge:     cfg.Multipart.TempFileMaxAge,
		}, logger)
		if err != nil {
			logger.Error("failed to initialize multipart store", "error", err)
			os.Exit(1)
		}
		mpStore = store

		gw := s3.New(cfg.RootDir, s3.Config{
			ListenAddr:     cfg.Gateways.S3.ListenAddr,
			AccessKey:      cfg.Gateways.S3.AccessKey,
			SecretKey:      cfg.Gateways.S3.SecretKey,
			Domain:         cfg.Gateways.S3.Domain,
			MaxUploadBytes: cfg.MaxUploadBytes,
			Multipart:      mpStore,
		}, logger)
		gateways = append(gateways, gw)
	}

	if cfg.Gateways.WebDAV.Enabled {
		gw := webdav.New(cfg.RootDir, webdav.Config{
			ListenAddr:     cfg.Gateways.WebDAV.ListenAddr,
			Username:       cfg.Gateways.WebDAV.Username,
			Password:       cfg.Gateways.WebDAV.Password,
			MaxUploadBytes: cfg.MaxUploadBytes,
		}, logger)
		gateways = append(gateways, gw)
	}

	if cfg.Gateways.HTTP.Enabled {
		gw := httpui.New(cfg.RootDir, httpui.Config{
			ListenAddr:     cfg.Gateways.HTTP.ListenAddr,
			Username:       cfg.Gateways.HTTP.Username,
			Password:       cfg.Gateways.HTTP.Password,
			MaxUploadBytes: cfg.MaxUploadBytes,
		}, logger)
		gateways = append(gateways, gw)
	}

	if cfg.Gateways.SFTP.Enabled {
		gw, err := sftp.New(cfg.RootDir, sftp.Config{
			ListenAddr:     cfg.Gateways.SFTP.ListenAddr,
			Username:       cfg.Gateways.SFTP.Username,
			Password:       cfg.Gateways.SFTP.Password,
			HostKeyPath:    cfg.Gateways.SFTP.HostKeyPath,
			MaxUploadBytes: cfg.MaxUploadBytes,
		}, logger)
		if err != nil {
			logger.Error("failed to create SFTP gateway", "error", err)
			os.Exit(1)
		}
		gateways = append(gateways, gw)
	}

	if mpStore != nil {
		go multipart.NewJanitor(mpStore, logger).Run(ctx)
	}

	for _, gw := range gateways {
		gw := gw
		go func() {
			if err := gw.Start(ctx); err != nil {
				errCh <- fmt.Errorf("%s: %w", gw.Name(), err)
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		logger.Error("gateway error, shutting down", "error", err)
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	for _, gw := range gateways {
		if err := gw.Stop(shutdownCtx); err != nil {
			logger.Error("gateway stop error", "gateway", gw.Name(), "error", err)
		}
	}

	logger.Info("sebastian stopped")
}
