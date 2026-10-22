package s3

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/solkin/sebastian/internal/fileops"
)

// A key ending in "/" is a folder marker: the empty object the AWS console's
// "Create folder", Cyberduck and rclone's directory markers write so that a
// folder exists before anything is put in it. Folders are directories here, so
// a marker is the directory itself: creating one makes the directory, and it
// holds no data. Listings are made of files, so a marker never shows up in one
// as an object, and an empty folder does not show up at all.

// emptyETag is the ETag S3 reports for an object with no bytes (the MD5 of
// nothing), which is what a folder marker is.
const emptyETag = `"d41d8cd98f00b204e9800998ecf8427e"`

var (
	errFolderHasNoData = &objectFailure{http.StatusBadRequest, "InvalidRequest",
		"A key ending in / is a folder, which cannot hold data."}
	errNotAFolderKey = &objectFailure{http.StatusBadRequest, "InvalidArgument",
		"A folder key must name a folder inside the bucket."}
)

// isFolderKey reports whether key names a folder marker.
func isFolderKey(key string) bool { return strings.HasSuffix(key, "/") }

// folderPath resolves a folder key to its directory. The directory is strictly
// inside the bucket: a key such as "./" would otherwise name the bucket itself.
func (g *Gateway) folderPath(bucket, key string) (string, *objectFailure) {
	if !validateBucketName(bucket) || !validateKey(key) {
		return "", &objectFailure{http.StatusBadRequest, "InvalidArgument", "Invalid argument"}
	}
	dir, ok := g.objectPath(bucket, key)
	bp, bucketOK := g.bucketPath(bucket)
	if !ok || !bucketOK || filepath.Clean(dir) == filepath.Clean(bp) {
		return "", errNotAFolderKey
	}
	return dir, nil
}

// requireEmptyBody checks that a request that may carry no data (a folder
// marker, CopyObject) carries none, reading at most one byte of it to find
// out. It returns the decoded body, whose verified checksum the response
// echoes. A body with data is refused with tooMuch.
func (g *Gateway) requireEmptyBody(r *http.Request, tooMuch *objectFailure) (*payload, *objectFailure) {
	if r.ContentLength > 0 && !streamingBody(r) {
		return nil, tooMuch
	}
	body, failure := g.newPayload(r)
	if failure != nil {
		return nil, failure
	}
	if body.length > 0 {
		return nil, tooMuch
	}
	var one [1]byte
	n, err := io.ReadFull(body, one[:])
	if n > 0 {
		return nil, tooMuch
	}
	if errors.As(err, &failure) {
		return nil, failure
	}
	if err != nil && err != io.EOF {
		return nil, errIncompleteBody
	}
	return body, nil
}

// handlePutFolder creates a folder (PUT /{bucket}/{prefix}/ with no body).
func (g *Gateway) handlePutFolder(w http.ResponseWriter, r *http.Request, bucket, key string) {
	dir, failure := g.folderPath(bucket, key)
	if failure == nil && !g.bucketExists(bucket) {
		failure = errNoSuchBucket
	}
	if failure != nil {
		writeObjectFailure(w, failure)
		return
	}
	body, failure := g.requireEmptyBody(r, errFolderHasNoData)
	if failure != nil {
		writeObjectFailure(w, failure)
		return
	}
	if err := g.makeFolder(dir); err != nil {
		if failure := writeFailure(err); failure != nil {
			writeObjectFailure(w, failure)
			return
		}
		g.logger.Error("put folder failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create folder")
		return
	}
	g.logger.Info("folder created", "bucket", bucket, "key", key)
	w.Header().Set("ETag", emptyETag)
	body.setChecksumHeader(w)
	w.WriteHeader(http.StatusOK)
}

// makeFolder creates dir and its parents durably. Creating a folder that is
// there already succeeds, as rewriting a marker does in S3.
func (g *Gateway) makeFolder(dir string) error {
	return fileops.Mkdir(g.rootDir, dir, 0o755, true)
}

// handleGetFolder answers GET and HEAD of a folder marker: an empty object
// when the folder exists.
func (g *Gateway) handleGetFolder(w http.ResponseWriter, r *http.Request, bucket, key string) {
	dir, failure := g.folderPath(bucket, key)
	if failure != nil {
		writeObjectFailure(w, failure)
		return
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		if err != nil && !readMissing(err) {
			g.logger.Error("stat folder failed", "bucket", bucket, "key", key, "error", err)
			writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
			return
		}
		writeObjectFailure(w, g.missingObject(bucket))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", "0")
	h.Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	h.Set("ETag", emptyETag)
	w.WriteHeader(http.StatusOK)
}

// handleDeleteFolder deletes a folder marker. As in S3, deleting a marker never
// deletes what is in the folder: only an empty folder is removed, and either
// way the answer is 204.
func (g *Gateway) handleDeleteFolder(w http.ResponseWriter, r *http.Request, bucket, key string) {
	dir, failure := g.folderPath(bucket, key)
	if failure == nil && !g.bucketExists(bucket) {
		failure = errNoSuchBucket
	}
	if failure != nil {
		writeObjectFailure(w, failure)
		return
	}
	if err := g.removeEmptyFolder(dir); err != nil {
		g.logger.Error("delete folder failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to delete folder")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// removeEmptyFolder removes dir if it is an empty directory and does nothing
// otherwise. Emptiness is checked by reading one entry before any commit, so a
// marker on a large folder costs one directory read, not a commit over the
// whole tree.
func (g *Gateway) removeEmptyFolder(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		if err != nil && !readMissing(err) {
			return err
		}
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(1)
	f.Close()
	if len(names) > 0 {
		return nil
	}
	if err != nil && err != io.EOF {
		return err
	}
	err = fileops.Remove(g.rootDir, dir, false)
	if err == nil || readMissing(err) || errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
		// Gone, or filled by a concurrent write since the check: either way the
		// marker's folder is as it should be.
		return nil
	}
	return err
}
