// Package logging keeps writing a log line from becoming an outage.
//
// slog writes synchronously: whichever goroutine logs is the one that waits for
// the write to complete. In this daemon that goroutine is routinely holding the
// volume's commit lock or the store's write mutex, so a log consumer that stops
// reading — a paused sidecar, a stalled pipe — stops the node. The daemon writes
// to stdout, which it does not own and cannot bound.
//
// Records are therefore handed to a writer goroutine through a fixed queue. When
// the queue fills, records are dropped and counted rather than made to wait.
// Losing log lines under pressure is a much smaller problem than a file server
// that stops accepting writes because nobody is reading its output.
package logging

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// QueueDepth is how many records may be in flight before dropping starts. It is
// generous enough that an ordinary burst never drops, and small enough that the
// memory it can hold is bounded and obvious.
const QueueDepth = 4096

type entry struct {
	handler slog.Handler
	record  slog.Record
}

// Async is a slog.Handler that never blocks its caller.
type Async struct {
	inner   slog.Handler
	shared  *shared
	dropped *atomic.Int64
}

type shared struct {
	queue chan entry
	// stop ends the writer. The queue itself is never closed: a record logged
	// during or after shutdown would then be a send on a closed channel, and
	// taking the process down over a log line is exactly the failure this
	// package exists to prevent.
	stop   chan struct{}
	closed sync.Once
	wg     sync.WaitGroup
}

// NewAsync wraps a handler. Close flushes what is queued and stops the writer.
func NewAsync(inner slog.Handler) *Async {
	h := &Async{
		inner:   inner,
		shared:  &shared{queue: make(chan entry, QueueDepth), stop: make(chan struct{})},
		dropped: new(atomic.Int64),
	}
	h.shared.wg.Add(1)
	go h.run()
	return h
}

func (h *Async) run() {
	defer h.shared.wg.Done()
	// Report drops on a slow cadence: the report itself must not become the
	// thing that floods a log consumer that is already struggling.
	report := time.NewTicker(time.Minute)
	defer report.Stop()
	reported := int64(0)
	for {
		select {
		case e := <-h.shared.queue:
			_ = e.handler.Handle(context.Background(), e.record)
		case <-report.C:
			if total := h.dropped.Load(); total > reported {
				h.inner.Handle(context.Background(), slog.NewRecord(
					time.Now(), slog.LevelWarn,
					"log records dropped; the log consumer is not keeping up", 0,
				))
				reported = total
			}
		case <-h.shared.stop:
			// Write what is already queued, then leave. Records that arrive
			// after this simply have nobody to write them.
			for {
				select {
				case e := <-h.shared.queue:
					_ = e.handler.Handle(context.Background(), e.record)
				default:
					return
				}
			}
		}
	}
}

// Enabled reports whether a level is worth formatting at all.
func (h *Async) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle queues a record. It never waits: a full queue drops.
func (h *Async) Handle(ctx context.Context, r slog.Record) error {
	select {
	case h.shared.queue <- entry{handler: h.inner, record: r.Clone()}:
	default:
		h.dropped.Add(1)
	}
	return nil
}

func (h *Async) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Async{inner: h.inner.WithAttrs(attrs), shared: h.shared, dropped: h.dropped}
}

func (h *Async) WithGroup(name string) slog.Handler {
	return &Async{inner: h.inner.WithGroup(name), shared: h.shared, dropped: h.dropped}
}

// Dropped counts records discarded because the consumer fell behind.
func (h *Async) Dropped() int64 { return h.dropped.Load() }

// Close drains what is queued and stops the writer. Records logged afterwards
// are accepted and discarded rather than written, so a late log line from a
// deferred shutdown step is harmless.
func (h *Async) Close() {
	h.shared.closed.Do(func() {
		close(h.shared.stop)
		h.shared.wg.Wait()
	})
}
