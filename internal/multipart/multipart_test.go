package multipart

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testStore returns a store over a fresh root directory with small part limits so
// tests do not have to move megabytes to exercise the size rules.
func testStore(t *testing.T, limits Limits) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	if limits.MinPartBytes == 0 {
		limits.MinPartBytes = 4
	}
	if limits.MaxPartBytes == 0 {
		limits.MaxPartBytes = 1 << 20
	}
	s, err := New(root, limits, testLogger())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return s, root
}

func md5Hex(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

// compositeETag computes the S3 multipart ETag for a sequence of part payloads.
func compositeETag(parts [][]byte) string {
	h := md5.New()
	for _, p := range parts {
		sum := md5.Sum(p)
		h.Write(sum[:])
	}
	return fmt.Sprintf("%s-%d", hex.EncodeToString(h.Sum(nil)), len(parts))
}

// writeParts stages payloads as parts 1..N and returns the completion list.
func writeParts(t *testing.T, s *Store, uploadID string, payloads [][]byte) []CompletePart {
	t.Helper()
	var list []CompletePart
	for i, p := range payloads {
		part, err := s.WritePart(uploadID, i+1, bytes.NewReader(p), Checksums{})
		if err != nil {
			t.Fatalf("write part %d: %v", i+1, err)
		}
		if part.ETag != md5Hex(p) {
			t.Fatalf("part %d etag = %s, want %s", i+1, part.ETag, md5Hex(p))
		}
		list = append(list, CompletePart{Number: part.Number, ETag: part.ETag})
	}
	return list
}

func TestCreateAndGet(t *testing.T) {
	s, root := testStore(t, Limits{})

	up, err := s.Create("photos", "2026/img.jpg")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !ValidUploadID(up.ID) {
		t.Fatalf("upload id %q is not well-formed", up.ID)
	}

	got, err := s.Get(up.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Bucket != "photos" || got.Key != "2026/img.jpg" {
		t.Fatalf("got %+v, want bucket=photos key=2026/img.jpg", got)
	}

	// Staging must live under the reserved directory, out of every bucket.
	staging := filepath.Join(root, gateway.ReservedDirName, stagingDirName, up.ID)
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("staging dir missing: %v", err)
	}
}

func TestGetUnknownUpload(t *testing.T) {
	s, _ := testStore(t, Limits{})

	for _, id := range []string{"", "nope", strings.Repeat("a", 32), "../../etc/passwd"} {
		if _, err := s.Get(id); !errors.Is(err, ErrNoSuchUpload) {
			t.Fatalf("Get(%q) error = %v, want ErrNoSuchUpload", id, err)
		}
	}
}

func TestCompleteAssemblesObject(t *testing.T) {
	s, root := testStore(t, Limits{})

	up, err := s.Create("bucket", "big.bin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	payloads := [][]byte{
		bytes.Repeat([]byte("a"), 10),
		bytes.Repeat([]byte("b"), 10),
		bytes.Repeat([]byte("c"), 3),
	}
	list := writeParts(t, s, up.ID, payloads)

	dest := filepath.Join(root, "bucket", "big.bin")
	res, err := s.Complete(up.ID, list, dest)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	want := bytes.Join(payloads, nil)
	if res.Size != int64(len(want)) {
		t.Fatalf("size = %d, want %d", res.Size, len(want))
	}
	if res.ETag != compositeETag(payloads) {
		t.Fatalf("etag = %s, want %s", res.ETag, compositeETag(payloads))
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("object content mismatch: got %q, want %q", got, want)
	}

	// The staging directory is gone, and a second completion is rejected exactly
	// as S3 rejects it.
	if _, err := s.Get(up.ID); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("upload still present after complete: %v", err)
	}
	if _, err := s.Complete(up.ID, list, dest); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("second complete error = %v, want ErrNoSuchUpload", err)
	}
}

func TestCompleteRejectsBadPartList(t *testing.T) {
	s, root := testStore(t, Limits{MinPartBytes: 8})
	dest := filepath.Join(root, "bucket", "obj")

	newUpload := func(t *testing.T) (string, []CompletePart) {
		t.Helper()
		up, err := s.Create("bucket", "obj")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		list := writeParts(t, s, up.ID, [][]byte{
			bytes.Repeat([]byte("a"), 10),
			bytes.Repeat([]byte("b"), 10),
		})
		return up.ID, list
	}

	t.Run("empty list", func(t *testing.T) {
		id, _ := newUpload(t)
		if _, err := s.Complete(id, nil, dest); !errors.Is(err, ErrEmptyPartList) {
			t.Fatalf("error = %v, want ErrEmptyPartList", err)
		}
	})

	t.Run("descending order", func(t *testing.T) {
		id, list := newUpload(t)
		reversed := []CompletePart{list[1], list[0]}
		if _, err := s.Complete(id, reversed, dest); !errors.Is(err, ErrInvalidPartOrder) {
			t.Fatalf("error = %v, want ErrInvalidPartOrder", err)
		}
	})

	t.Run("duplicate part number", func(t *testing.T) {
		id, list := newUpload(t)
		dup := []CompletePart{list[0], list[0]}
		if _, err := s.Complete(id, dup, dest); !errors.Is(err, ErrInvalidPartOrder) {
			t.Fatalf("error = %v, want ErrInvalidPartOrder", err)
		}
	})

	t.Run("wrong etag", func(t *testing.T) {
		id, list := newUpload(t)
		bad := []CompletePart{{Number: list[0].Number, ETag: md5Hex([]byte("something else"))}, list[1]}
		if _, err := s.Complete(id, bad, dest); !errors.Is(err, ErrInvalidPart) {
			t.Fatalf("error = %v, want ErrInvalidPart", err)
		}
	})

	t.Run("missing part", func(t *testing.T) {
		id, list := newUpload(t)
		missing := append(append([]CompletePart{}, list...), CompletePart{Number: 7, ETag: md5Hex([]byte("x"))})
		if _, err := s.Complete(id, missing, dest); !errors.Is(err, ErrInvalidPart) {
			t.Fatalf("error = %v, want ErrInvalidPart", err)
		}
	})

	t.Run("nothing is published on failure", func(t *testing.T) {
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Fatalf("destination exists after failed completions: %v", err)
		}
	})
}

func TestCompleteRejectsUndersizedPart(t *testing.T) {
	s, root := testStore(t, Limits{MinPartBytes: 16})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	list := writeParts(t, s, up.ID, [][]byte{
		bytes.Repeat([]byte("a"), 4), // below the minimum and not last
		bytes.Repeat([]byte("b"), 4),
	})

	dest := filepath.Join(root, "bucket", "obj")
	if _, err := s.Complete(up.ID, list, dest); !errors.Is(err, ErrPartTooSmall) {
		t.Fatalf("error = %v, want ErrPartTooSmall", err)
	}

	// A single small part is the last part, so it is allowed.
	up2, err := s.Create("bucket", "small")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	list2 := writeParts(t, s, up2.ID, [][]byte{[]byte("tiny")})
	if _, err := s.Complete(up2.ID, list2, filepath.Join(root, "bucket", "small")); err != nil {
		t.Fatalf("single small part should complete: %v", err)
	}
}

func TestCompleteRejectsOversizedObject(t *testing.T) {
	s, root := testStore(t, Limits{MinPartBytes: 4, MaxObjectBytes: 12})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	list := writeParts(t, s, up.ID, [][]byte{
		bytes.Repeat([]byte("a"), 8),
		bytes.Repeat([]byte("b"), 8),
	})

	if _, err := s.Complete(up.ID, list, filepath.Join(root, "bucket", "obj")); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("error = %v, want ErrObjectTooLarge", err)
	}
}

func TestWritePartLimits(t *testing.T) {
	s, _ := testStore(t, Limits{MaxPartBytes: 8, MaxParts: 5})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := s.WritePart(up.ID, 0, bytes.NewReader([]byte("x")), Checksums{}); !errors.Is(err, ErrInvalidPartNumber) {
		t.Fatalf("part 0 error = %v, want ErrInvalidPartNumber", err)
	}
	if _, err := s.WritePart(up.ID, 6, bytes.NewReader([]byte("x")), Checksums{}); !errors.Is(err, ErrInvalidPartNumber) {
		t.Fatalf("part 6 error = %v, want ErrInvalidPartNumber", err)
	}
	if _, err := s.WritePart(up.ID, 1, bytes.NewReader(bytes.Repeat([]byte("x"), 9)), Checksums{}); !errors.Is(err, ErrPartTooLarge) {
		t.Fatalf("oversized part error = %v, want ErrPartTooLarge", err)
	}

	// The rejected part left nothing behind.
	parts, _, _, err := s.ListParts(up.ID, 0, 100)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 0 {
		t.Fatalf("expected no staged parts, got %d", len(parts))
	}
}

func TestWritePartContentMD5(t *testing.T) {
	s, _ := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	payload := []byte("hello world")
	sum := md5.Sum(payload)
	good := base64Std(sum[:])

	if _, err := s.WritePart(up.ID, 1, bytes.NewReader(payload), Checksums{ContentMD5: good}); err != nil {
		t.Fatalf("matching Content-MD5 rejected: %v", err)
	}

	otherSum := md5.Sum([]byte("different"))
	if _, err := s.WritePart(up.ID, 2, bytes.NewReader(payload), Checksums{ContentMD5: base64Std(otherSum[:])}); !errors.Is(err, ErrBadDigest) {
		t.Fatalf("error = %v, want ErrBadDigest", err)
	}
	if _, err := s.WritePart(up.ID, 3, panicReader{}, Checksums{ContentMD5: "not base64!!"}); !errors.Is(err, ErrBadDigest) {
		t.Fatalf("error = %v, want ErrBadDigest", err)
	}

	parts, _, _, err := s.ListParts(up.ID, 0, 100)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 1 || parts[0].Number != 1 {
		t.Fatalf("only the verified part should be staged, got %+v", parts)
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("body must not be read after malformed checksum metadata")
}

func TestWritePartReplacesSamePartNumber(t *testing.T) {
	s, root := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// A client retrying a part after a failure sends the same part number again,
	// possibly with different bytes. The newest upload must win, and exactly one
	// file may remain on disk for that number.
	if _, err := s.WritePart(up.ID, 1, bytes.NewReader([]byte("first attempt")), Checksums{}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	final := []byte("second attempt")
	part, err := s.WritePart(up.ID, 1, bytes.NewReader(final), Checksums{})
	if err != nil {
		t.Fatalf("second write: %v", err)
	}

	parts, _, _, err := s.ListParts(up.ID, 0, 100)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 1 {
		t.Fatalf("expected 1 staged part, got %d: %+v", len(parts), parts)
	}
	if parts[0].ETag != md5Hex(final) {
		t.Fatalf("etag = %s, want %s", parts[0].ETag, md5Hex(final))
	}

	dest := filepath.Join(root, "bucket", "obj")
	if _, err := s.Complete(up.ID, []CompletePart{{Number: 1, ETag: part.ETag}}, dest); err != nil {
		t.Fatalf("complete: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if !bytes.Equal(got, final) {
		t.Fatalf("object = %q, want %q", got, final)
	}
}

// errReader fails partway through, standing in for a client that disconnects
// mid-part.
type errReader struct {
	data []byte
	n    int
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.n >= len(r.data) {
		return 0, errors.New("connection reset")
	}
	n := copy(p, r.data[r.n:r.n+1])
	r.n += n
	return n, nil
}

func TestWritePartAbortedMidStreamLeavesNothing(t *testing.T) {
	s, _ := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := s.WritePart(up.ID, 1, &errReader{data: []byte("partial data")}, Checksums{}); err == nil {
		t.Fatal("expected an error from the interrupted body")
	}

	parts, _, _, err := s.ListParts(up.ID, 0, 100)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 0 {
		t.Fatalf("interrupted part must not be staged, got %+v", parts)
	}

	// Only the descriptor remains; the scratch file was removed.
	entries, err := os.ReadDir(s.uploadDir(up.ID))
	if err != nil {
		t.Fatalf("read upload dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != metaFileName {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("upload dir should hold only the descriptor, got %v", names)
	}
}

func TestAbortDiscardsUpload(t *testing.T) {
	s, root := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	list := writeParts(t, s, up.ID, [][]byte{bytes.Repeat([]byte("a"), 8)})

	if err := s.Abort(up.ID); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if err := s.Abort(up.ID); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("second abort error = %v, want ErrNoSuchUpload", err)
	}

	// Every later operation on an aborted upload behaves as if it never existed.
	if _, err := s.WritePart(up.ID, 2, bytes.NewReader([]byte("more")), Checksums{}); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("write after abort error = %v, want ErrNoSuchUpload", err)
	}
	if _, err := s.Complete(up.ID, list, filepath.Join(root, "bucket", "obj")); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("complete after abort error = %v, want ErrNoSuchUpload", err)
	}
	if _, _, _, err := s.ListParts(up.ID, 0, 100); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("list after abort error = %v, want ErrNoSuchUpload", err)
	}
}

func TestConcurrentPartUploads(t *testing.T) {
	s, root := testStore(t, Limits{MinPartBytes: 4})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	const parts = 16
	payloads := make([][]byte, parts)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 32)
	}

	var wg sync.WaitGroup
	results := make([]Part, parts)
	errs := make([]error, parts)
	for i := 0; i < parts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = s.WritePart(up.ID, i+1, bytes.NewReader(payloads[i]), Checksums{})
		}(i)
	}
	wg.Wait()

	list := make([]CompletePart, 0, parts)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("part %d: %v", i+1, err)
		}
		list = append(list, CompletePart{Number: results[i].Number, ETag: results[i].ETag})
	}

	dest := filepath.Join(root, "bucket", "obj")
	res, err := s.Complete(up.ID, list, dest)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if res.ETag != compositeETag(payloads) {
		t.Fatalf("etag = %s, want %s", res.ETag, compositeETag(payloads))
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if !bytes.Equal(got, bytes.Join(payloads, nil)) {
		t.Fatal("concurrently uploaded parts assembled in the wrong order or content")
	}
}

func TestConcurrentSamePartNumber(t *testing.T) {
	s, _ := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Two clients racing on the same part number: whichever lands last wins, but
	// the staging directory must never end up holding two files for one part.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.WritePart(up.ID, 1, bytes.NewReader(bytes.Repeat([]byte{byte('a' + i)}, 64)), Checksums{})
		}(i)
	}
	wg.Wait()

	parts, _, _, err := s.ListParts(up.ID, 0, 100)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 1 {
		t.Fatalf("expected exactly 1 staged part, got %d: %+v", len(parts), parts)
	}
}

func TestConcurrentPartUploadCap(t *testing.T) {
	s, _ := testStore(t, Limits{MaxConcurrentParts: 1})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Hold the single slot with a body that blocks until released, then confirm a
	// second part is turned away rather than queued.
	release := make(chan struct{})
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.WritePart(up.ID, 1, &blockingReader{started: started, release: release, data: []byte("hello")}, Checksums{})
		done <- err
	}()

	<-started
	if _, err := s.WritePart(up.ID, 2, bytes.NewReader([]byte("second")), Checksums{}); !errors.Is(err, ErrBusy) {
		close(release)
		t.Fatalf("error = %v, want ErrBusy", err)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first part: %v", err)
	}

	// With the slot free again the next part is accepted.
	if _, err := s.WritePart(up.ID, 2, bytes.NewReader([]byte("second")), Checksums{}); err != nil {
		t.Fatalf("part after slot freed: %v", err)
	}
}

// blockingReader signals once it is read and then waits, so a test can hold an
// upload slot open deterministically.
type blockingReader struct {
	started  chan struct{}
	release  chan struct{}
	data     []byte
	signaled bool
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if !r.signaled {
		r.signaled = true
		close(r.started)
		<-r.release
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestActiveUploadCap(t *testing.T) {
	s, _ := testStore(t, Limits{MaxActiveUploads: 2})

	first, err := s.Create("bucket", "a")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Create("bucket", "b"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Create("bucket", "c"); !errors.Is(err, ErrTooManyUploads) {
		t.Fatalf("error = %v, want ErrTooManyUploads", err)
	}

	// Aborting frees a slot.
	if err := s.Abort(first.ID); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if _, err := s.Create("bucket", "c"); err != nil {
		t.Fatalf("create after abort: %v", err)
	}
}

func TestListPartsPagination(t *testing.T) {
	s, _ := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 1; i <= 5; i++ {
		if _, err := s.WritePart(up.ID, i, bytes.NewReader([]byte{byte(i)}), Checksums{}); err != nil {
			t.Fatalf("write part %d: %v", i, err)
		}
	}

	parts, truncated, next, err := s.ListParts(up.ID, 0, 2)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 2 || !truncated || next != 2 {
		t.Fatalf("page 1: parts=%d truncated=%v next=%d", len(parts), truncated, next)
	}
	if parts[0].Number != 1 || parts[1].Number != 2 {
		t.Fatalf("page 1 numbers = %d,%d, want 1,2", parts[0].Number, parts[1].Number)
	}

	parts, truncated, _, err = s.ListParts(up.ID, next, 10)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 3 || truncated {
		t.Fatalf("page 2: parts=%d truncated=%v", len(parts), truncated)
	}
	if parts[0].Number != 3 {
		t.Fatalf("page 2 starts at %d, want 3", parts[0].Number)
	}
}

func TestRestartRecoveryChoosesNewestDuplicatePart(t *testing.T) {
	s, root := testStore(t, Limits{})
	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	oldBody := []byte("old")
	oldPart, err := s.WritePart(up.ID, 1, bytes.NewReader(oldBody), Checksums{})
	if err != nil {
		t.Fatalf("write old part: %v", err)
	}
	oldPath := filepath.Join(s.uploadDir(up.ID), partFileName(1, oldPart.ETag))
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oldPath, past, past); err != nil {
		t.Fatalf("age old part: %v", err)
	}

	// Simulate a process dying after the replacement rename but before the old
	// digest-named file was removed.
	newBody := []byte("replacement")
	newETag := md5Hex(newBody)
	newPath := filepath.Join(s.uploadDir(up.ID), partFileName(1, newETag))
	if err := os.WriteFile(newPath, newBody, 0o600); err != nil {
		t.Fatalf("write replacement part: %v", err)
	}

	parts, truncated, _, err := s.ListParts(up.ID, 0, 1000)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if truncated || len(parts) != 1 {
		t.Fatalf("parts=%d truncated=%v, want one recovered part", len(parts), truncated)
	}
	if parts[0].ETag != newETag || parts[0].Size != int64(len(newBody)) {
		t.Fatalf("recovered part = %+v, want replacement etag=%s size=%d", parts[0], newETag, len(newBody))
	}

	dest := filepath.Join(root, "bucket", "obj")
	if _, err := s.Complete(up.ID, []CompletePart{{Number: 1, ETag: newETag}}, dest); err != nil {
		t.Fatalf("complete recovered upload: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read completed object: %v", err)
	}
	if !bytes.Equal(got, newBody) {
		t.Fatalf("completed body = %q, want %q", got, newBody)
	}
}

func TestListUploads(t *testing.T) {
	s, _ := testStore(t, Limits{})

	if _, err := s.Create("photos", "b.jpg"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Create("photos", "a.jpg"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Create("docs", "c.pdf"); err != nil {
		t.Fatalf("create: %v", err)
	}

	ups, truncated, err := s.List("photos", "", "", "", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ups) != 2 || truncated {
		t.Fatalf("got %d uploads (truncated=%v), want 2", len(ups), truncated)
	}
	if ups[0].Key != "a.jpg" || ups[1].Key != "b.jpg" {
		t.Fatalf("uploads not ordered by key: %s, %s", ups[0].Key, ups[1].Key)
	}

	// Pagination resumes strictly after the marker pair.
	page, truncated, err := s.List("photos", "", "", "", 1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page) != 1 || !truncated {
		t.Fatalf("page = %d uploads, truncated=%v", len(page), truncated)
	}
	next, _, err := s.List("photos", "", page[0].Key, page[0].ID, 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(next) != 1 || next[0].Key != "b.jpg" {
		t.Fatalf("second page = %+v, want only b.jpg", next)
	}

	// Prefix filtering and bucket scoping.
	filtered, _, err := s.List("photos", "a", "", "", 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Key != "a.jpg" {
		t.Fatalf("prefix filter = %+v", filtered)
	}
	hasDocs, err := s.HasUploads("docs")
	if err != nil {
		t.Fatalf("HasUploads(docs): %v", err)
	}
	hasEmpty, err := s.HasUploads("empty")
	if err != nil {
		t.Fatalf("HasUploads(empty): %v", err)
	}
	if !hasDocs || hasEmpty {
		t.Fatal("HasUploads did not scope to the bucket")
	}
}

func TestHasUploadsDoesNotHideStagingErrors(t *testing.T) {
	s, _ := testStore(t, Limits{})
	if err := os.Rename(s.stagingDir, s.stagingDir+"-unavailable"); err != nil {
		t.Fatalf("hide staging dir: %v", err)
	}
	if _, err := s.HasUploads("bucket"); err == nil {
		t.Fatal("HasUploads treated an unavailable staging area as empty")
	}
}

func TestCompleteRejectsDestinationOutsideRoot(t *testing.T) {
	s, root := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	list := writeParts(t, s, up.ID, [][]byte{[]byte("data")})

	outside := filepath.Join(filepath.Dir(root), "escaped.bin")
	if _, err := s.Complete(up.ID, list, outside); err == nil {
		t.Fatal("expected completion outside the root to be refused")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("file created outside root: %v", err)
	}

	reserved := filepath.Join(root, gateway.ReservedDirName, "sneaky.bin")
	if _, err := s.Complete(up.ID, list, reserved); err == nil {
		t.Fatal("expected completion into the reserved dir to be refused")
	}

	aliasDir := filepath.Join(root, "bucket")
	if err := os.Mkdir(aliasDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(aliasDir, "state-alias")
	if err := os.Symlink(filepath.Join(root, gateway.ReservedDirName), alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := s.Complete(up.ID, list, filepath.Join(alias, "sneaky.bin")); err == nil {
		t.Fatal("expected completion through a symlink into the reserved dir to be refused")
	}
}

func TestCompleteDetectsCorruptedPart(t *testing.T) {
	s, root := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	payload := bytes.Repeat([]byte("a"), 32)
	list := writeParts(t, s, up.ID, [][]byte{payload})

	// Corrupt the staged bytes behind the store's back, keeping the file name (and
	// therefore the recorded digest) unchanged.
	partPath := filepath.Join(s.uploadDir(up.ID), partFileName(1, md5Hex(payload)))
	if err := os.WriteFile(partPath, bytes.Repeat([]byte("b"), 32), 0o600); err != nil {
		t.Fatalf("corrupt part: %v", err)
	}

	dest := filepath.Join(root, "bucket", "obj")
	if _, err := s.Complete(up.ID, list, dest); !errors.Is(err, ErrCorruptPart) {
		t.Fatalf("error = %v, want ErrCorruptPart", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("a corrupted upload must not publish an object")
	}
}

func TestRestartRecoversUploads(t *testing.T) {
	root := t.TempDir()
	limits := Limits{MinPartBytes: 4}

	first, err := New(root, limits, testLogger())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	up, err := first.Create("bucket", "resumed.bin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	head := bytes.Repeat([]byte("a"), 16)
	if _, err := first.WritePart(up.ID, 1, bytes.NewReader(head), Checksums{}); err != nil {
		t.Fatalf("write part: %v", err)
	}

	// A new process comes up over the same directory: nothing is held in memory,
	// so the upload must still be addressable.
	second, err := New(root, limits, testLogger())
	if err != nil {
		t.Fatalf("restart store: %v", err)
	}

	got, err := second.Get(up.ID)
	if err != nil {
		t.Fatalf("upload lost across restart: %v", err)
	}
	if got.Bucket != "bucket" || got.Key != "resumed.bin" {
		t.Fatalf("descriptor = %+v", got)
	}
	parts, _, _, err := second.ListParts(up.ID, 0, 100)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 1 || parts[0].ETag != md5Hex(head) {
		t.Fatalf("staged part lost across restart: %+v", parts)
	}

	tail := bytes.Repeat([]byte("b"), 8)
	tailPart, err := second.WritePart(up.ID, 2, bytes.NewReader(tail), Checksums{})
	if err != nil {
		t.Fatalf("write part after restart: %v", err)
	}

	dest := filepath.Join(root, "bucket", "resumed.bin")
	res, err := second.Complete(up.ID, []CompletePart{
		{Number: 1, ETag: md5Hex(head)},
		{Number: 2, ETag: tailPart.ETag},
	}, dest)
	if err != nil {
		t.Fatalf("complete after restart: %v", err)
	}
	if res.ETag != compositeETag([][]byte{head, tail}) {
		t.Fatalf("etag = %s, want %s", res.ETag, compositeETag([][]byte{head, tail}))
	}

	content, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if !bytes.Equal(content, append(append([]byte{}, head...), tail...)) {
		t.Fatal("object assembled after restart has wrong content")
	}
}

func TestCleanupExpiresIdleUploads(t *testing.T) {
	s, _ := testStore(t, Limits{UploadTTL: time.Hour})

	stale, err := s.Create("bucket", "stale")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WritePart(stale.ID, 1, bytes.NewReader([]byte("data")), Checksums{}); err != nil {
		t.Fatalf("write part: %v", err)
	}
	fresh, err := s.Create("bucket", "fresh")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Backdate the stale upload's directory and its contents past the TTL.
	backdate(t, s.uploadDir(stale.ID), time.Now().Add(-2*time.Hour))

	if removed := s.Cleanup(time.Now()); removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if _, err := s.Get(stale.ID); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("stale upload survived: %v", err)
	}
	if _, err := s.Get(fresh.ID); err != nil {
		t.Fatalf("fresh upload was removed: %v", err)
	}

	// A second pass has nothing left to do.
	if removed := s.Cleanup(time.Now()); removed != 0 {
		t.Fatalf("second pass removed = %d, want 0", removed)
	}
}

func TestCleanupKeepsUploadWithRecentPart(t *testing.T) {
	s, _ := testStore(t, Limits{UploadTTL: time.Hour})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// The upload was initiated long ago but a part arrived just now: a long-running
	// transfer must not be collected out from under the client.
	backdate(t, s.uploadDir(up.ID), time.Now().Add(-5*time.Hour))
	if _, err := s.WritePart(up.ID, 1, bytes.NewReader([]byte("recent")), Checksums{}); err != nil {
		t.Fatalf("write part: %v", err)
	}

	if removed := s.Cleanup(time.Now()); removed != 0 {
		t.Fatalf("removed = %d, want 0", removed)
	}
	if _, err := s.Get(up.ID); err != nil {
		t.Fatalf("active upload was removed: %v", err)
	}
}

func TestCleanupRemovesStrayEntries(t *testing.T) {
	s, _ := testStore(t, Limits{UploadTTL: time.Hour})

	junk := filepath.Join(s.stagingDir, "not-an-upload")
	if err := os.WriteFile(junk, []byte("junk"), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(junk, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	s.Cleanup(time.Now())
	if _, err := os.Stat(junk); !os.IsNotExist(err) {
		t.Fatalf("stray entry survived cleanup: %v", err)
	}
}

func TestSweepTempFilesRespectsAge(t *testing.T) {
	root := t.TempDir()

	fresh := filepath.Join(root, ".seb-tmp-inflight")
	old := filepath.Join(root, ".seb-tmp-orphan")
	for _, p := range []string{fresh, old} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	past := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	gateway.SweepTempFiles(root, time.Hour, testLogger())

	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("an in-flight scratch file was swept: %v", err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("orphaned scratch file survived: %v", err)
	}
}

// backdate sets the modification time of a directory and everything directly
// inside it, so a TTL can be exercised without waiting.
func backdate(t *testing.T, dir string, when time.Time) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if err := os.Chtimes(filepath.Join(dir, e.Name()), when, when); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	if err := os.Chtimes(dir, when, when); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

// base64Std renders a digest the way a Content-MD5 header carries it.
func base64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func TestWritePartContentSHA256(t *testing.T) {
	s, _ := testStore(t, Limits{})

	up, err := s.Create("bucket", "obj")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	payload := []byte("signed payload")
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])

	if _, err := s.WritePart(up.ID, 1, bytes.NewReader(payload), Checksums{ContentSHA256: good}); err != nil {
		t.Fatalf("matching sha256 rejected: %v", err)
	}

	// A request signed over one body must not be able to stage a different one.
	other := sha256.Sum256([]byte("swapped body"))
	if _, err := s.WritePart(up.ID, 2, bytes.NewReader(payload), Checksums{ContentSHA256: hex.EncodeToString(other[:])}); !errors.Is(err, ErrContentSHA256Mismatch) {
		t.Fatalf("error = %v, want ErrContentSHA256Mismatch", err)
	}

	// Markers that carry no verifiable digest are not treated as a checksum.
	for _, marker := range []string{"UNSIGNED-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", ""} {
		if _, err := s.WritePart(up.ID, 3, bytes.NewReader(payload), Checksums{ContentSHA256: marker}); err != nil {
			t.Fatalf("marker %q rejected: %v", marker, err)
		}
	}

	parts, _, _, err := s.ListParts(up.ID, 0, 100)
	if err != nil {
		t.Fatalf("list parts: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("staged parts = %+v, want parts 1 and 3 only", parts)
	}
}
