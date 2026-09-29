package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingHandler stands in for a log consumer that stopped reading.
type blockingHandler struct {
	mu      sync.Mutex
	lines   []string
	release chan struct{}
}

func (h *blockingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *blockingHandler) Handle(_ context.Context, r slog.Record) error {
	if h.release != nil {
		<-h.release
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, r.Message)
	return nil
}

func (h *blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *blockingHandler) WithGroup(string) slog.Handler      { return h }

func (h *blockingHandler) written() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

// The property the daemon depends on: a consumer that never reads must not stop
// the goroutine that logs, because that goroutine is often holding a lock every
// write on the volume needs.
func TestLoggingDoesNotBlockOnAStalledConsumer(t *testing.T) {
	stalled := &blockingHandler{release: make(chan struct{})}
	async := NewAsync(stalled)
	logger := slog.New(async)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < QueueDepth*2; i++ {
			logger.Info("record", "i", i)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("logging blocked behind a consumer that never read")
	}
	if async.Dropped() == 0 {
		t.Fatal("a full queue did not drop anything")
	}

	close(stalled.release)
	async.Close()
	if len(stalled.written()) == 0 {
		t.Fatal("nothing was written once the consumer resumed")
	}
}

// Ordinary logging must still arrive, in order, with its attributes.
func TestRecordsReachTheHandlerInOrder(t *testing.T) {
	sink := &blockingHandler{}
	async := NewAsync(sink)
	logger := slog.New(async).With("node", "n1")

	for _, message := range []string{"first", "second", "third"} {
		logger.Info(message)
	}
	async.Close()

	got := strings.Join(sink.written(), ",")
	if got != "first,second,third" {
		t.Fatalf("written = %q, want first,second,third", got)
	}
	if async.Dropped() != 0 {
		t.Fatalf("dropped %d records with an idle consumer", async.Dropped())
	}
}

// A derived logger shares the queue, so WithAttrs must not create a second
// writer goroutine or a second drop counter.
func TestDerivedHandlersShareOneWriter(t *testing.T) {
	sink := &blockingHandler{}
	async := NewAsync(sink)
	derived, ok := async.WithAttrs([]slog.Attr{slog.String("k", "v")}).(*Async)
	if !ok {
		t.Fatal("WithAttrs did not return an async handler")
	}
	if derived.shared != async.shared || derived.dropped != async.dropped {
		t.Fatal("derived handler does not share the queue and counter")
	}
	slog.New(derived).Info("from derived")
	async.Close()
	if got := sink.written(); len(got) != 1 || got[0] != "from derived" {
		t.Fatalf("written = %v", got)
	}
}

// A deferred shutdown step that logs must not take the process down with it.
// Closing the queue channel instead of signalling the writer made a late record
// a send on a closed channel — a panic, over a log line.
func TestLoggingAfterCloseIsHarmless(t *testing.T) {
	sink := &blockingHandler{}
	async := NewAsync(sink)
	logger := slog.New(async)
	logger.Info("before close")
	async.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("logging after Close panicked: %v", r)
		}
	}()
	logger.Info("after close")
	if err := async.Handle(context.Background(), slog.Record{}); err != nil {
		t.Fatalf("Handle after Close: %v", err)
	}
	if got := sink.written(); len(got) != 1 || got[0] != "before close" {
		t.Fatalf("written = %v, want only what was logged before Close", got)
	}
}

// Close must write what was already queued, even behind a consumer that was
// slow up to that moment.
func TestCloseDrainsWhatIsQueued(t *testing.T) {
	sink := &blockingHandler{}
	async := NewAsync(sink)
	logger := slog.New(async)
	for i := range 100 {
		logger.Info(fmt.Sprintf("record-%d", i))
	}
	async.Close()
	if got := sink.written(); len(got) != 100 {
		t.Fatalf("Close wrote %d of 100 queued records", len(got))
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	async := NewAsync(&blockingHandler{})
	async.Close()
	async.Close()
}
