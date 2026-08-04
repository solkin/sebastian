package multipart

import (
	"context"
	"log/slog"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
)

// Janitor periodically reclaims space that no client will ever ask for again:
// multipart uploads that were initiated but never completed or aborted, and
// atomic-write scratch files orphaned by a process that died mid-write.
//
// It runs one sweep immediately at start — a server that was down past the TTL
// should not wait a full interval before cleaning up — and then on a ticker.
type Janitor struct {
	store  *Store
	logger *slog.Logger
}

// NewJanitor returns a janitor for the store.
func NewJanitor(store *Store, logger *slog.Logger) *Janitor {
	return &Janitor{
		store:  store,
		logger: logger.With("component", "multipart-janitor"),
	}
}

// Run sweeps until ctx is cancelled.
func (j *Janitor) Run(ctx context.Context) {
	interval := j.store.limits.CleanupInterval
	j.logger.Info("multipart janitor started",
		"interval", interval.String(),
		"upload_ttl", j.store.limits.UploadTTL.String(),
		"temp_file_max_age", j.store.limits.TempFileMaxAge.String(),
	)

	j.sweep()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			j.logger.Info("multipart janitor stopped")
			return
		case <-ticker.C:
			j.sweep()
		}
	}
}

// sweep runs one cleanup pass.
func (j *Janitor) sweep() {
	if removed := j.store.Cleanup(time.Now()); removed > 0 {
		j.logger.Info("expired multipart uploads removed", "count", removed)
	}
	// Age-bounded so a scratch file belonging to an upload that is still streaming
	// is never pulled out from under it.
	gateway.SweepTempFiles(j.store.rootDir, j.store.limits.TempFileMaxAge, j.logger)
}
