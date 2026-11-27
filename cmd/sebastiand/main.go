// Package main is the entry point for sebastiand — a single-node file server
// that projects S3, WebDAV, SFTP, and HTTP UI protocols onto a local directory.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/solkin/sebastian/internal/config"
	"github.com/solkin/sebastian/internal/fileops"
	"github.com/solkin/sebastian/internal/gateway"
	"github.com/solkin/sebastian/internal/gateway/httpui"
	"github.com/solkin/sebastian/internal/gateway/s3"
	"github.com/solkin/sebastian/internal/gateway/sftp"
	"github.com/solkin/sebastian/internal/gateway/webdav"
	"github.com/solkin/sebastian/internal/logging"
	"github.com/solkin/sebastian/internal/multipart"
)

// version is the release this binary was built from.
var version = "1.8.1"

// shutdownDrain is how long open transfers may finish after a stop signal.
// It stays below Docker's default 10 s grace period, so a stop with a slow
// download in flight ends in an orderly exit rather than SIGKILL.
const shutdownDrain = 8 * time.Second

func main() {
	configPath := flag.String("config", "", "path to config file (optional, env vars also work)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("sebastiand", version)
		return
	}
	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logs := logging.NewAsync(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	defer logs.Close()
	logger := slog.New(logs)

	if err := os.MkdirAll(cfg.RootDir, 0o755); err != nil {
		return fmt.Errorf("create root_dir %s: %w", cfg.RootDir, err)
	}

	private := filepath.Join(cfg.RootDir, ".sebastian")
	if info, err := os.Lstat(private); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("private state directory must be a real directory: %s", private)
	}
	if err := os.MkdirAll(private, 0o700); err != nil {
		return fmt.Errorf("create private state: %w", err)
	}
	releaseVolume, err := fileops.AcquireLease(private)
	if err != nil {
		return fmt.Errorf("acquire volume lease: %w", err)
	}
	defer releaseVolume()
	if err := fileops.Do(cfg.RootDir, func() error { return fileops.CheckOrphanedBackups(cfg.RootDir, nil) }); err != nil {
		return fmt.Errorf("recover filesystem replacements: %w", err)
	}

	// Clear scratch files left by a previous crash before serving any requests.
	// No upload can be in flight yet, so age is irrelevant here.
	gateway.SweepTempFiles(cfg.RootDir, 0, logger)

	gateway.SetAccessLog(cfg.AccessLog)

	logger.Info("sebastian starting",
		"version", version,
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
			return fmt.Errorf("initialize multipart store: %w", err)
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
		if err := gw.CreateBuckets(cfg.Gateways.S3.Buckets); err != nil {
			return fmt.Errorf("create buckets: %w", err)
		}
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
			return fmt.Errorf("create SFTP gateway: %w", err)
		}
		gateways = append(gateways, gw)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	if mpStore != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			multipart.NewJanitor(mpStore, logger).Run(ctx)
		}()
	} else {
		interval := cfg.Multipart.CleanupInterval
		if interval <= 0 {
			interval = multipart.DefaultCleanupInterval
		}
		maxAge := cfg.Multipart.TempFileMaxAge
		if maxAge <= 0 {
			maxAge = multipart.DefaultTempFileMaxAge
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			runTempFileJanitor(ctx, cfg.RootDir, interval, maxAge, logger)
		}()
	}

	for _, gw := range gateways {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := gw.Start(ctx); err != nil {
				err = fmt.Errorf("%s: %w", gw.Name(), err)
				logger.Error("gateway error, shutting down", "error", err)
				select {
				case errCh <- err:
				default:
				}
				cancel()
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig)
	case <-ctx.Done():
	}

	cancel()

	// Every gateway drains at once within one budget. When the drain expires,
	// Stop forcibly closes lingering transfers so shutdown ends cleanly.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownDrain)
	defer shutdownCancel()
	var stopping sync.WaitGroup
	for _, gw := range gateways {
		stopping.Add(1)
		go func() {
			defer stopping.Done()
			if err := gw.Stop(shutdownCtx); err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					logger.Warn("gateway closed transfers still open after the drain period", "gateway", gw.Name(), "drain", shutdownDrain)
				} else {
					logger.Error("gateway stop error", "gateway", gw.Name(), "error", err)
				}
			}
		}()
	}
	stopping.Wait()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		logger.Warn("background components did not stop within grace period")
	}

	logger.Info("sebastian stopped")
	if dropped := logs.Dropped(); dropped > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d log records were dropped; the log consumer could not keep up\n", dropped)
	}
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func runTempFileJanitor(ctx context.Context, rootDir string, interval, maxAge time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gateway.SweepTempFiles(rootDir, maxAge, logger)
		}
	}
}
