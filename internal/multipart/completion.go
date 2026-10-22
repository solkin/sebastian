package multipart

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/solkin/sebastian/internal/fileops"
	"github.com/solkin/sebastian/internal/gateway"
)

// completedDirName holds one small record per completed upload, kept for the
// upload TTL so a retried CompleteMultipartUpload can be answered. It sits
// beside the staging directory, not in it: a record is not an upload, and must
// count neither against the active-upload cap nor in upload listings.
const completedDirName = "multipart-completed"

// completion is the durable record of a completed upload: what was asked for
// (the part list, as a digest) and what was produced (the object's size and
// timestamp, which is also what its ETag is made of).
type completion struct {
	UploadID string `json:"upload_id"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	// Dest is the object's path relative to the store root.
	Dest string `json:"dest"`
	// Parts is partListDigest of the completion list.
	Parts     string `json:"parts"`
	PartCount int    `json:"part_count"`
	// ETag is the composite multipart ETag the completion computed.
	ETag      string    `json:"etag"`
	Size      int64     `json:"size"`
	ModTime   int64     `json:"mod_time_ns"`
	Completed time.Time `json:"completed"`
}

func (s *Store) completedDir() string {
	return filepath.Join(s.rootDir, gateway.ReservedDirName, completedDirName)
}

func (s *Store) completionPath(id string) string {
	return filepath.Join(s.completedDir(), id+".json")
}

// partListDigest identifies a completion list by its part numbers and
// normalized ETags, in order, so a record need not keep up to 10,000 entries.
func partListDigest(parts []CompletePart) string {
	h := sha256.New()
	for _, p := range parts {
		etag := strings.ToLower(strings.Trim(strings.TrimPrefix(strings.TrimSpace(p.ETag), "W/"), `"`))
		h.Write([]byte(strconv.Itoa(p.Number) + ":" + etag + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// destName returns dest relative to the store root, the form a record keeps,
// so that a relocated root still recognizes its own records.
func (s *Store) destName(dest string) (string, error) {
	absRoot, err := filepath.Abs(s.rootDir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, dest)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// recordCompletion durably records that up was completed into dest with the
// given parts, producing the object info describes.
func (s *Store) recordCompletion(up Upload, parts []CompletePart, dest, etag string, info os.FileInfo) error {
	name, err := s.destName(dest)
	if err != nil {
		return err
	}
	data, err := json.Marshal(completion{
		UploadID:  up.ID,
		Bucket:    up.Bucket,
		Key:       up.Key,
		Dest:      name,
		Parts:     partListDigest(parts),
		PartCount: len(parts),
		ETag:      etag,
		Size:      info.Size(),
		ModTime:   info.ModTime().UnixNano(),
		Completed: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	dir := s.completedDir()
	return fileops.Do(s.rootDir, func() error {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		tmp, err := fileops.CreateTemp(dir, tempPrefix+"completion-*")
		if err != nil {
			return err
		}
		defer fileops.ReleaseTemp(tmp)
		_, err = tmp.Write(data)
		if err == nil {
			err = tmp.Sync()
		}
		if err = errors.Join(err, tmp.Close()); err == nil {
			err = os.Rename(tmp.Name(), s.completionPath(up.ID))
		}
		if err != nil {
			os.Remove(tmp.Name())
			return err
		}
		return fileops.SyncParents(dir, s.rootDir)
	})
}

// repeatCompletion answers a completion of an upload that no longer exists. If
// it was completed into dest with the same part list, and dest is still the
// object that completion produced, the retry gets that completion's result;
// anything else is ErrNoSuchUpload, as for an upload that was never there.
func (s *Store) repeatCompletion(id string, want []CompletePart, dest string) (CompleteResult, error) {
	data, err := os.ReadFile(s.completionPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CompleteResult{}, ErrNoSuchUpload
		}
		return CompleteResult{}, fmt.Errorf("multipart: read completion record: %w", err)
	}
	var rec completion
	if err := json.Unmarshal(data, &rec); err != nil {
		return CompleteResult{}, fmt.Errorf("multipart: parse completion record: %w", err)
	}
	name, err := s.destName(dest)
	if err != nil || rec.UploadID != id || rec.Dest != name || rec.Parts != partListDigest(want) {
		return CompleteResult{}, ErrNoSuchUpload
	}
	info, err := os.Stat(dest)
	if err != nil || !info.Mode().IsRegular() || info.Size() != rec.Size || info.ModTime().UnixNano() != rec.ModTime {
		// The object was replaced or deleted since: the completion is history,
		// and reporting it as current would describe an object that is gone.
		return CompleteResult{}, ErrNoSuchUpload
	}
	s.logger.Info("multipart completion repeated", "upload_id", id, "bucket", rec.Bucket, "key", rec.Key)
	return CompleteResult{
		Bucket:   rec.Bucket,
		Key:      rec.Key,
		ETag:     rec.ETag,
		Size:     rec.Size,
		Parts:    rec.PartCount,
		Info:     info,
		Repeated: true,
	}, nil
}

// cleanupCompletions removes completion records older than the upload TTL and
// reports how many it removed. Past the TTL a retry is no longer expected; the
// upload itself would have expired by then had it not been completed.
func (s *Store) cleanupCompletions(now time.Time) int {
	entries, err := os.ReadDir(s.completedDir())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Warn("multipart cleanup: read completion records failed", "error", err)
		}
		return 0
	}
	removed := 0
	for _, e := range entries {
		id, isRecord := strings.CutSuffix(e.Name(), ".json")
		if !isRecord || !ValidUploadID(id) {
			continue // scratch files are the temp sweep's
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) <= s.limits.UploadTTL {
			continue
		}
		// Under the upload's lock, so a retry in progress reads a whole record
		// or none.
		l := s.lock(id)
		err = fileops.Do(s.rootDir, func() error {
			if err := os.Remove(s.completionPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return fileops.SyncDir(s.completedDir())
		})
		s.unlock(id, l)
		if err != nil {
			s.logger.Warn("multipart cleanup: remove completion record failed", "upload_id", id, "error", err)
			continue
		}
		removed++
	}
	return removed
}
