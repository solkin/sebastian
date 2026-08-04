// Package multipart implements the on-disk staging store behind the S3 multipart
// upload API.
//
// Every in-progress upload owns a directory under
// {rootDir}/.sebastian/multipart/{uploadID}: an "upload.json" descriptor plus one
// file per staged part, named "part-{NNNNN}-{md5hex}". Encoding the digest in the
// file name means a part and its ETag become visible in a single atomic rename —
// there is no window in which a part exists without a verified checksum, and no
// sidecar to keep in sync.
//
// All state lives on disk, so uploads survive a restart: a process that comes back
// up can accept parts for, complete, or abort an upload started by its predecessor.
// Crash-torn scratch files are named with the shared ".seb-tmp-" prefix and are
// swept by age.
package multipart

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
)

// Filesystem layout constants.
const (
	stagingDirName = "multipart"
	metaFileName   = "upload.json"
	partPrefix     = "part-"
	tempPrefix     = ".seb-tmp-"

	// uploadIDHexLen is the length of a hex-encoded 16-byte upload ID.
	uploadIDHexLen = 32
)

// S3 protocol limits, used as defaults so a stock configuration behaves like AWS.
const (
	// DefaultMinPartBytes is the smallest allowed size for any part but the last.
	DefaultMinPartBytes int64 = 5 * 1024 * 1024
	// DefaultMaxPartBytes is the largest allowed size for a single part.
	DefaultMaxPartBytes int64 = 5 * 1024 * 1024 * 1024
	// DefaultMaxParts is the highest allowed part number.
	DefaultMaxParts = 10000
	// DefaultMaxActiveUploads bounds how many uploads may be staged at once.
	DefaultMaxActiveUploads = 10000
	// DefaultUploadTTL is how long an untouched upload is kept before cleanup,
	// mirroring a conservative AbortIncompleteMultipartUpload lifecycle rule.
	DefaultUploadTTL = 7 * 24 * time.Hour
	// DefaultCleanupInterval is how often the janitor sweeps.
	DefaultCleanupInterval = time.Hour
	// DefaultTempFileMaxAge is how old an orphaned scratch file must be before a
	// running server removes it.
	DefaultTempFileMaxAge = 24 * time.Hour
)

// Errors returned by the store. Callers map these onto protocol-level codes.
var (
	// ErrNoSuchUpload means the upload ID is unknown, malformed, or already
	// completed or aborted.
	ErrNoSuchUpload = errors.New("multipart: no such upload")
	// ErrInvalidPartNumber means the part number is outside 1..MaxParts.
	ErrInvalidPartNumber = errors.New("multipart: invalid part number")
	// ErrInvalidPart means a requested part is missing or its ETag does not match
	// what was staged.
	ErrInvalidPart = errors.New("multipart: invalid part")
	// ErrInvalidPartOrder means the completion list is not strictly ascending.
	ErrInvalidPartOrder = errors.New("multipart: invalid part order")
	// ErrEmptyPartList means completion was requested with no parts.
	ErrEmptyPartList = errors.New("multipart: empty part list")
	// ErrPartTooSmall means a non-final part is below the minimum part size.
	ErrPartTooSmall = errors.New("multipart: part too small")
	// ErrPartTooLarge means a single part exceeds the maximum part size.
	ErrPartTooLarge = errors.New("multipart: part too large")
	// ErrObjectTooLarge means the assembled object exceeds the upload cap.
	ErrObjectTooLarge = errors.New("multipart: object too large")
	// ErrTooManyUploads means the active upload cap is reached.
	ErrTooManyUploads = errors.New("multipart: too many active uploads")
	// ErrBusy means the concurrent part upload cap is reached.
	ErrBusy = errors.New("multipart: too many concurrent part uploads")
	// ErrBadDigest means the body did not match the client-supplied Content-MD5.
	ErrBadDigest = errors.New("multipart: content-md5 mismatch")
	// ErrCorruptPart means a staged part no longer hashes to the digest recorded
	// when it was uploaded.
	ErrCorruptPart = errors.New("multipart: staged part failed integrity check")
)

// Limits bounds the resources a multipart upload may consume. A zero value in a
// field means "use the default"; caps documented as such treat 0 as unlimited.
type Limits struct {
	// MinPartBytes is the minimum size of every part but the last.
	MinPartBytes int64
	// MaxPartBytes is the maximum size of a single part.
	MaxPartBytes int64
	// MaxParts is the highest accepted part number.
	MaxParts int
	// MaxObjectBytes caps the assembled object; 0 means unlimited.
	MaxObjectBytes int64
	// MaxActiveUploads caps simultaneously staged uploads; 0 means unlimited.
	MaxActiveUploads int
	// MaxConcurrentParts caps in-flight part uploads; 0 means unlimited.
	MaxConcurrentParts int
	// UploadTTL is how long an untouched upload survives.
	UploadTTL time.Duration
	// CleanupInterval is how often the janitor runs.
	CleanupInterval time.Duration
	// TempFileMaxAge is how old an orphaned scratch file must be to be swept.
	TempFileMaxAge time.Duration
}

// withDefaults fills unset fields with the S3-compatible defaults.
func (l Limits) withDefaults() Limits {
	if l.MinPartBytes <= 0 {
		l.MinPartBytes = DefaultMinPartBytes
	}
	if l.MaxPartBytes <= 0 {
		l.MaxPartBytes = DefaultMaxPartBytes
	}
	if l.MaxParts <= 0 {
		l.MaxParts = DefaultMaxParts
	}
	if l.MaxActiveUploads < 0 {
		l.MaxActiveUploads = 0
	}
	if l.UploadTTL <= 0 {
		l.UploadTTL = DefaultUploadTTL
	}
	if l.CleanupInterval <= 0 {
		l.CleanupInterval = DefaultCleanupInterval
	}
	if l.TempFileMaxAge <= 0 {
		l.TempFileMaxAge = DefaultTempFileMaxAge
	}
	return l
}

// Upload describes an in-progress multipart upload.
type Upload struct {
	ID        string    `json:"upload_id"`
	Bucket    string    `json:"bucket"`
	Key       string    `json:"key"`
	Initiated time.Time `json:"initiated"`
}

// Part describes a staged part.
type Part struct {
	Number       int
	Size         int64
	ETag         string // hex MD5 of the part's bytes, without quotes
	LastModified time.Time
}

// CompletePart is one entry of a client-supplied completion list.
type CompletePart struct {
	Number int
	ETag   string
}

// CompleteResult reports the object produced by a completed upload.
type CompleteResult struct {
	Bucket string
	Key    string
	// ETag is the composite S3 multipart ETag: the MD5 of the concatenated binary
	// part digests, suffixed with "-{partCount}". It is returned unquoted.
	ETag  string
	Size  int64
	Parts int
}

// Store manages staged multipart uploads under a root directory.
type Store struct {
	rootDir    string
	stagingDir string
	limits     Limits
	logger     *slog.Logger

	// createMu serializes Create so the active-upload cap cannot be overshot by
	// concurrent initiations.
	createMu sync.Mutex

	// mu guards locks, the table of per-upload mutexes that serialize the
	// publish/complete/abort steps of one upload against each other. Part bodies
	// are streamed outside these locks so concurrent parts stay parallel.
	mu    sync.Mutex
	locks map[string]*uploadLock

	// sem bounds in-flight part uploads; nil when unlimited.
	sem chan struct{}
}

type uploadLock struct {
	mu   sync.Mutex
	refs int
}

// New creates the staging area under rootDir and returns a Store.
func New(rootDir string, limits Limits, logger *slog.Logger) (*Store, error) {
	staging := filepath.Join(rootDir, gateway.ReservedDirName, stagingDirName)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, fmt.Errorf("multipart: create staging dir: %w", err)
	}

	limits = limits.withDefaults()

	s := &Store{
		rootDir:    rootDir,
		stagingDir: staging,
		limits:     limits,
		logger:     logger.With("component", "multipart"),
		locks:      make(map[string]*uploadLock),
	}
	if limits.MaxConcurrentParts > 0 {
		s.sem = make(chan struct{}, limits.MaxConcurrentParts)
	}
	return s, nil
}

// Limits returns the effective limits, with defaults applied.
func (s *Store) Limits() Limits { return s.limits }

// --- locking ---

func (s *Store) lock(id string) *uploadLock {
	s.mu.Lock()
	l, ok := s.locks[id]
	if !ok {
		l = &uploadLock{}
		s.locks[id] = l
	}
	l.refs++
	s.mu.Unlock()

	l.mu.Lock()
	return l
}

func (s *Store) unlock(id string, l *uploadLock) {
	l.mu.Unlock()

	s.mu.Lock()
	l.refs--
	if l.refs == 0 {
		delete(s.locks, id)
	}
	s.mu.Unlock()
}

// --- ids and paths ---

// newUploadID returns a fresh random upload ID.
func newUploadID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("multipart: generate upload id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidUploadID reports whether id has the exact shape this store issues. IDs
// arrive from the network and are used as directory names, so anything else —
// including path separators, "..", or a different length — is rejected before it
// reaches the filesystem.
func ValidUploadID(id string) bool {
	if len(id) != uploadIDHexLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (s *Store) uploadDir(id string) string {
	return filepath.Join(s.stagingDir, id)
}

// partFileName renders the on-disk name that carries both the part number and its
// verified digest.
func partFileName(number int, md5hex string) string {
	return fmt.Sprintf("%s%05d-%s", partPrefix, number, md5hex)
}

// parsePartFileName splits a staged part's file name back into its number and
// digest. ok is false for any other entry (the descriptor, scratch files, junk).
func parsePartFileName(name string) (number int, md5hex string, ok bool) {
	if !strings.HasPrefix(name, partPrefix) {
		return 0, "", false
	}
	rest := name[len(partPrefix):]
	numStr, digest, found := strings.Cut(rest, "-")
	if !found || len(numStr) != 5 || !isHexMD5(digest) {
		return 0, "", false
	}
	n, err := strconv.Atoi(numStr)
	if err != nil || n < 1 {
		return 0, "", false
	}
	return n, digest, true
}

func isHexMD5(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// --- descriptor I/O ---

// readMeta loads an upload descriptor, mapping every "not there" condition onto
// ErrNoSuchUpload so callers cannot distinguish a never-created upload from a
// completed or aborted one — same as S3.
func (s *Store) readMeta(id string) (Upload, error) {
	if !ValidUploadID(id) {
		return Upload{}, ErrNoSuchUpload
	}
	data, err := os.ReadFile(filepath.Join(s.uploadDir(id), metaFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Upload{}, ErrNoSuchUpload
		}
		return Upload{}, fmt.Errorf("multipart: read upload metadata: %w", err)
	}
	var up Upload
	if err := json.Unmarshal(data, &up); err != nil {
		return Upload{}, fmt.Errorf("multipart: parse upload metadata: %w", err)
	}
	if up.ID != id {
		return Upload{}, ErrNoSuchUpload
	}
	return up, nil
}

// writeMeta writes the descriptor atomically and flushes it, so an upload that
// exists after a crash is always fully described.
func writeMeta(dir string, up Upload) error {
	data, err := json.Marshal(up)
	if err != nil {
		return fmt.Errorf("multipart: encode upload metadata: %w", err)
	}
	tmp, err := os.CreateTemp(dir, tempPrefix+"meta-*")
	if err != nil {
		return fmt.Errorf("multipart: create metadata temp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("multipart: write metadata: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("multipart: sync metadata: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("multipart: close metadata: %w", err)
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, metaFileName)); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("multipart: publish metadata: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a directory entry change so a rename survives a power loss.
// Failures are not fatal: some filesystems refuse to sync directories.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	d.Sync()
	d.Close()
}

// --- upload lifecycle ---

// Create registers a new upload for bucket/key and returns its descriptor.
func (s *Store) Create(bucket, key string) (Upload, error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()

	if s.limits.MaxActiveUploads > 0 {
		n, err := s.countUploads()
		if err != nil {
			return Upload{}, err
		}
		if n >= s.limits.MaxActiveUploads {
			return Upload{}, ErrTooManyUploads
		}
	}

	id, err := newUploadID()
	if err != nil {
		return Upload{}, err
	}

	dir := s.uploadDir(id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Upload{}, fmt.Errorf("multipart: create upload dir: %w", err)
	}

	up := Upload{
		ID:     id,
		Bucket: bucket,
		Key:    key,
		// Millisecond precision matches the S3 timestamp format the gateway emits,
		// so a listed Initiated value round-trips exactly.
		Initiated: time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := writeMeta(dir, up); err != nil {
		os.RemoveAll(dir)
		return Upload{}, err
	}
	syncDir(s.stagingDir)

	s.logger.Debug("multipart upload created", "upload_id", id, "bucket", bucket, "key", key)
	return up, nil
}

// Get returns an upload's descriptor.
func (s *Store) Get(id string) (Upload, error) {
	return s.readMeta(id)
}

// countUploads returns the number of staged upload directories.
func (s *Store) countUploads() (int, error) {
	entries, err := os.ReadDir(s.stagingDir)
	if err != nil {
		return 0, fmt.Errorf("multipart: read staging dir: %w", err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && ValidUploadID(e.Name()) {
			n++
		}
	}
	return n, nil
}

// WritePart stages one part of an upload.
//
// The body is streamed to a scratch file outside the per-upload lock — so parts of
// the same upload transfer in parallel — hashed as it goes, and only then published
// with a single rename. A client that disconnects mid-part leaves nothing behind
// but a scratch file, and re-uploading a part number simply replaces it, which is
// what makes a retry after a failed part safe.
//
// contentMD5, when non-empty, is the client's base64 Content-MD5 header and is
// enforced against the received bytes.
func (s *Store) WritePart(uploadID string, number int, body io.Reader, contentMD5 string) (Part, error) {
	if !ValidUploadID(uploadID) {
		return Part{}, ErrNoSuchUpload
	}
	if number < 1 || number > s.limits.MaxParts {
		return Part{}, ErrInvalidPartNumber
	}

	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			return Part{}, ErrBusy
		}
	}

	dir := s.uploadDir(uploadID)
	if _, err := s.readMeta(uploadID); err != nil {
		return Part{}, err
	}

	tmp, err := os.CreateTemp(dir, tempPrefix+"part-*")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Part{}, ErrNoSuchUpload
		}
		return Part{}, fmt.Errorf("multipart: create part temp: %w", err)
	}
	tmpPath := tmp.Name()

	hasher := md5.New()
	// Read one byte past the cap so an oversized part is detected without
	// buffering or trusting Content-Length.
	size, copyErr := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(body, s.limits.MaxPartBytes+1))
	if copyErr == nil && size > s.limits.MaxPartBytes {
		copyErr = ErrPartTooLarge
	}
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		os.Remove(tmpPath)
		if errors.Is(copyErr, ErrPartTooLarge) {
			return Part{}, ErrPartTooLarge
		}
		return Part{}, copyErr
	}

	digest := hex.EncodeToString(hasher.Sum(nil))
	if contentMD5 != "" {
		want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(contentMD5))
		if err != nil || hex.EncodeToString(want) != digest {
			os.Remove(tmpPath)
			return Part{}, ErrBadDigest
		}
	}

	l := s.lock(uploadID)
	defer s.unlock(uploadID, l)

	// The upload may have been aborted while the body was streaming; publishing
	// now would resurrect its directory.
	if _, err := s.readMeta(uploadID); err != nil {
		os.Remove(tmpPath)
		return Part{}, err
	}

	finalPath := filepath.Join(dir, partFileName(number, digest))
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return Part{}, fmt.Errorf("multipart: publish part: %w", err)
	}
	// A re-upload with different content lands under a different name; drop the
	// superseded copy so exactly one file per part number remains.
	s.removeSupersededParts(dir, number, digest)
	syncDir(dir)

	info, err := os.Stat(finalPath)
	modTime := time.Now().UTC()
	if err == nil {
		modTime = info.ModTime().UTC()
	}

	s.logger.Debug("multipart part staged", "upload_id", uploadID, "part", number, "size", size)
	return Part{Number: number, Size: size, ETag: digest, LastModified: modTime}, nil
}

// removeSupersededParts deletes any other staged file for this part number.
func (s *Store) removeSupersededParts(dir string, number int, keepDigest string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n, digest, ok := parsePartFileName(e.Name())
		if !ok || n != number || digest == keepDigest {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			s.logger.Warn("failed to remove superseded part", "dir", dir, "part", number, "error", err)
		}
	}
}

// stagedParts returns every part staged for an upload, ordered by part number.
func (s *Store) stagedParts(id string) ([]Part, error) {
	dir := s.uploadDir(id)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoSuchUpload
		}
		return nil, fmt.Errorf("multipart: read upload dir: %w", err)
	}

	var parts []Part
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		number, digest, ok := parsePartFileName(e.Name())
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		parts = append(parts, Part{
			Number:       number,
			Size:         info.Size(),
			ETag:         digest,
			LastModified: info.ModTime().UTC(),
		})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Number < parts[j].Number })
	return parts, nil
}

// ListParts returns staged parts above numberMarker, at most maxParts of them,
// together with the marker to resume from when the listing is truncated.
func (s *Store) ListParts(id string, numberMarker, maxParts int) (parts []Part, truncated bool, next int, err error) {
	if _, err := s.readMeta(id); err != nil {
		return nil, false, 0, err
	}
	all, err := s.stagedParts(id)
	if err != nil {
		return nil, false, 0, err
	}

	filtered := make([]Part, 0, len(all))
	for _, p := range all {
		if p.Number > numberMarker {
			filtered = append(filtered, p)
		}
	}
	if maxParts > 0 && len(filtered) > maxParts {
		filtered = filtered[:maxParts]
		truncated = true
		next = filtered[len(filtered)-1].Number
	}
	return filtered, truncated, next, nil
}

// List returns uploads for a bucket, ordered by (key, upload ID) as S3 orders
// them, starting after the given markers. maxUploads bounds the page.
func (s *Store) List(bucket, prefix, keyMarker, uploadIDMarker string, maxUploads int) (uploads []Upload, truncated bool, err error) {
	entries, err := os.ReadDir(s.stagingDir)
	if err != nil {
		return nil, false, fmt.Errorf("multipart: read staging dir: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() || !ValidUploadID(e.Name()) {
			continue
		}
		up, err := s.readMeta(e.Name())
		if err != nil {
			// A concurrent abort or a half-written descriptor: skip, do not fail the
			// whole listing.
			continue
		}
		if up.Bucket != bucket {
			continue
		}
		if prefix != "" && !strings.HasPrefix(up.Key, prefix) {
			continue
		}
		uploads = append(uploads, up)
	}

	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key != uploads[j].Key {
			return uploads[i].Key < uploads[j].Key
		}
		return uploads[i].ID < uploads[j].ID
	})

	if keyMarker != "" || uploadIDMarker != "" {
		idx := sort.Search(len(uploads), func(i int) bool {
			if uploads[i].Key != keyMarker {
				return uploads[i].Key > keyMarker
			}
			return uploads[i].ID > uploadIDMarker
		})
		uploads = uploads[idx:]
	}

	if maxUploads > 0 && len(uploads) > maxUploads {
		uploads = uploads[:maxUploads]
		truncated = true
	}
	return uploads, truncated, nil
}

// HasUploads reports whether any upload is staged for a bucket. A bucket with
// in-progress uploads is not empty and must not be deleted.
func (s *Store) HasUploads(bucket string) bool {
	ups, _, err := s.List(bucket, "", "", "", 1)
	return err == nil && len(ups) > 0
}

// Abort discards an upload and every part staged for it.
func (s *Store) Abort(id string) error {
	if !ValidUploadID(id) {
		return ErrNoSuchUpload
	}

	l := s.lock(id)
	defer s.unlock(id, l)

	if _, err := s.readMeta(id); err != nil {
		return err
	}
	if err := os.RemoveAll(s.uploadDir(id)); err != nil {
		return fmt.Errorf("multipart: abort upload: %w", err)
	}
	s.logger.Info("multipart upload aborted", "upload_id", id)
	return nil
}

// Complete validates the client's part list, assembles the object at dest, and
// discards the staging directory.
//
// Validation mirrors S3: the list must be non-empty and strictly ascending, every
// entry must match a staged part's ETag, and every part but the last must reach the
// minimum part size. Assembly re-hashes each part as it is copied, so a part that
// was corrupted on disk after upload fails the completion instead of silently
// producing a bad object; the byte count of the finished file is checked against
// the sum of the part sizes before it is published.
//
// dest must be an absolute path inside the store's root directory; the caller is
// responsible for having resolved it safely.
func (s *Store) Complete(id string, want []CompletePart, dest string) (CompleteResult, error) {
	if !ValidUploadID(id) {
		return CompleteResult{}, ErrNoSuchUpload
	}
	if len(want) == 0 {
		return CompleteResult{}, ErrEmptyPartList
	}
	if err := s.validateDest(dest); err != nil {
		return CompleteResult{}, err
	}

	l := s.lock(id)
	defer s.unlock(id, l)

	up, err := s.readMeta(id)
	if err != nil {
		return CompleteResult{}, err
	}

	staged, err := s.stagedParts(id)
	if err != nil {
		return CompleteResult{}, err
	}
	byNumber := make(map[int]Part, len(staged))
	for _, p := range staged {
		byNumber[p.Number] = p
	}

	// Validate the shape of the list before looking at what was staged, so a
	// misordered request is reported as such rather than as whatever the first
	// out-of-order entry happens to violate.
	prev := 0
	for _, w := range want {
		if w.Number < 1 || w.Number > s.limits.MaxParts {
			return CompleteResult{}, ErrInvalidPartNumber
		}
		if w.Number <= prev {
			return CompleteResult{}, ErrInvalidPartOrder
		}
		prev = w.Number
	}

	selected := make([]Part, 0, len(want))
	var total int64
	for i, w := range want {
		p, ok := byNumber[w.Number]
		if !ok || !etagMatches(w.ETag, p.ETag) {
			return CompleteResult{}, ErrInvalidPart
		}
		// Every part but the last must be at least MinPartBytes, so a client cannot
		// assemble a huge object out of tiny fragments.
		if i < len(want)-1 && p.Size < s.limits.MinPartBytes {
			return CompleteResult{}, ErrPartTooSmall
		}
		total += p.Size
		if s.limits.MaxObjectBytes > 0 && total > s.limits.MaxObjectBytes {
			return CompleteResult{}, ErrObjectTooLarge
		}
		selected = append(selected, p)
	}

	etag, size, err := s.assemble(id, selected, total, dest)
	if err != nil {
		return CompleteResult{}, err
	}

	if err := os.RemoveAll(s.uploadDir(id)); err != nil {
		// The object is already published; a leftover staging directory is garbage
		// the janitor will collect, not a reason to fail the request.
		s.logger.Warn("failed to remove staging dir after complete", "upload_id", id, "error", err)
	}

	s.logger.Info("multipart upload completed",
		"upload_id", id, "bucket", up.Bucket, "key", up.Key, "parts", len(selected), "size", size)

	return CompleteResult{
		Bucket: up.Bucket,
		Key:    up.Key,
		ETag:   etag,
		Size:   size,
		Parts:  len(selected),
	}, nil
}

// validateDest guards against a destination outside the served root or inside the
// staging area, whatever the caller passed in.
func (s *Store) validateDest(dest string) error {
	absRoot, err := filepath.Abs(s.rootDir)
	if err != nil {
		return fmt.Errorf("multipart: resolve root: %w", err)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("multipart: resolve destination: %w", err)
	}
	if !strings.HasPrefix(absDest, absRoot+string(filepath.Separator)) {
		return fmt.Errorf("multipart: destination outside root")
	}
	reserved := filepath.Join(absRoot, gateway.ReservedDirName)
	if absDest == reserved || strings.HasPrefix(absDest, reserved+string(filepath.Separator)) {
		return fmt.Errorf("multipart: destination inside reserved directory")
	}
	return nil
}

// assemble concatenates parts into dest and returns the composite multipart ETag
// and the number of bytes written. wantSize is the expected total; the finished
// file is checked against it before anything is published.
//
// The scratch file lives in the staging directory, so a crash mid-assembly leaves
// nothing in a user-visible bucket and the whole attempt is discarded with the
// upload. The final rename is atomic, so readers see either no object or the
// complete one.
func (s *Store) assemble(id string, parts []Part, wantSize int64, dest string) (string, int64, error) {
	dir := s.uploadDir(id)

	tmp, err := os.CreateTemp(dir, tempPrefix+"assemble-*")
	if err != nil {
		return "", 0, fmt.Errorf("multipart: create assembly temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}

	composite := md5.New()
	var written int64
	for _, p := range parts {
		partPath := filepath.Join(dir, partFileName(p.Number, p.ETag))
		f, err := os.Open(partPath)
		if err != nil {
			cleanup()
			if errors.Is(err, os.ErrNotExist) {
				return "", 0, ErrInvalidPart
			}
			return "", 0, fmt.Errorf("multipart: open part %d: %w", p.Number, err)
		}

		verifier := md5.New()
		n, err := io.Copy(io.MultiWriter(tmp, verifier), f)
		f.Close()
		if err != nil {
			cleanup()
			return "", 0, fmt.Errorf("multipart: copy part %d: %w", p.Number, err)
		}

		raw := verifier.Sum(nil)
		if hex.EncodeToString(raw) != p.ETag || n != p.Size {
			cleanup()
			s.logger.Error("staged part failed integrity check", "upload_id", id, "part", p.Number)
			return "", 0, ErrCorruptPart
		}
		composite.Write(raw)
		written += n
	}

	// Verify the finished file before it becomes visible: a mismatch here means the
	// staged bytes shifted underneath us, and half an object must never be
	// published under the object's name.
	if written != wantSize {
		cleanup()
		return "", 0, fmt.Errorf("multipart: assembled %d bytes, expected %d", written, wantSize)
	}
	if info, err := tmp.Stat(); err == nil && info.Size() != wantSize {
		cleanup()
		return "", 0, fmt.Errorf("multipart: assembled file is %d bytes, expected %d", info.Size(), wantSize)
	}

	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", 0, fmt.Errorf("multipart: sync assembled object: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", 0, fmt.Errorf("multipart: close assembled object: %w", err)
	}

	destDir := filepath.Dir(dest)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		os.Remove(tmpPath)
		return "", 0, fmt.Errorf("multipart: create destination dir: %w", err)
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return "", 0, fmt.Errorf("multipart: publish object: %w", err)
	}
	syncDir(destDir)

	etag := fmt.Sprintf("%s-%d", hex.EncodeToString(composite.Sum(nil)), len(parts))
	return etag, written, nil
}

// etagMatches compares a client-supplied ETag with a staged digest, tolerating the
// surrounding quotes and the weak-validator prefix that clients echo back.
func etagMatches(clientETag, digest string) bool {
	e := strings.TrimSpace(clientETag)
	e = strings.TrimPrefix(e, "W/")
	e = strings.Trim(e, `"`)
	return strings.EqualFold(e, digest)
}

// --- cleanup ---

// Cleanup removes uploads whose last activity is older than the TTL and reports
// how many were removed. An upload's activity is the newest timestamp among its
// directory and the files in it, so a long upload that keeps receiving parts is
// never collected out from under a client.
func (s *Store) Cleanup(now time.Time) int {
	entries, err := os.ReadDir(s.stagingDir)
	if err != nil {
		s.logger.Warn("multipart cleanup: read staging dir failed", "error", err)
		return 0
	}

	removed := 0
	for _, e := range entries {
		path := filepath.Join(s.stagingDir, e.Name())

		// Anything that is not a well-formed upload directory is junk from a crash
		// or a stray write; drop it once it is older than the TTL as well.
		if !e.IsDir() || !ValidUploadID(e.Name()) {
			if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > s.limits.UploadTTL {
				if err := os.RemoveAll(path); err != nil {
					s.logger.Warn("multipart cleanup: remove stray entry failed", "path", path, "error", err)
				}
			}
			continue
		}

		last, err := lastActivity(path)
		if err != nil {
			continue
		}
		if now.Sub(last) <= s.limits.UploadTTL {
			continue
		}

		// Take the upload's lock so cleanup cannot race a part that is being
		// published or an in-flight completion.
		l := s.lock(e.Name())
		if cur, err := lastActivity(path); err == nil && now.Sub(cur) > s.limits.UploadTTL {
			if err := os.RemoveAll(path); err != nil {
				s.logger.Warn("multipart cleanup: remove upload failed", "upload_id", e.Name(), "error", err)
			} else {
				removed++
				s.logger.Info("expired multipart upload removed", "upload_id", e.Name(), "idle", now.Sub(cur).String())
			}
		}
		s.unlock(e.Name(), l)
	}
	return removed
}

// lastActivity returns the newest modification time of an upload directory or any
// file inside it.
func lastActivity(dir string) (time.Time, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return time.Time{}, err
	}
	last := info.ModTime()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return last, nil
	}
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().After(last) {
			last = fi.ModTime()
		}
	}
	return last, nil
}
