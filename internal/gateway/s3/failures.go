package s3

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"
)

// Objects are files and folders are directories, so a key can collide with the
// filesystem in ways S3 itself never reports. These are the answers for those
// collisions; each is the client's to resolve, so none of them is a 5xx that a
// client would retry.
var (
	errNoSuchKey    = &objectFailure{http.StatusNotFound, "NoSuchKey", "The specified key does not exist."}
	errNoSuchBucket = &objectFailure{http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist."}
	errKeyTooLong   = &objectFailure{http.StatusBadRequest, "KeyTooLongError", "Your key is too long"}
	errInvalidKey   = &objectFailure{http.StatusBadRequest, "InvalidArgument",
		"Object keys must be valid UTF-8 without NUL characters."}
	errParentIsObject = &objectFailure{http.StatusConflict, "ParentIsObject",
		"A prefix of this key is an existing object. An object cannot be stored below another object."}
	errObjectIsDirectory = &objectFailure{http.StatusConflict, "ObjectExistsAsDirectory",
		"This key is a prefix (folder) of existing objects. An object cannot have the name of a folder."}
	errPreconditionFailed = &objectFailure{http.StatusPreconditionFailed, "PreconditionFailed",
		"At least one of the pre-conditions you specified did not hold"}
	errIncompleteBody = &objectFailure{http.StatusBadRequest, "IncompleteBody",
		"The request body ended before the upload was complete."}
)

// maxSegmentLength is the longest path segment a key may have: one directory
// or file name, which every filesystem Sebastian runs on caps at 255 bytes.
const maxSegmentLength = 255

// keyShapeFailure refuses a key no node could store, before any filesystem
// call sees it: S3's 1024-byte key limit, an over-long path segment, and bytes
// that are not a name (NUL, or anything that is not UTF-8).
func keyShapeFailure(key string) *objectFailure {
	if len(key) > maxKeyLength {
		return errKeyTooLong
	}
	if !utf8.ValidString(key) || strings.IndexByte(key, 0) >= 0 {
		return errInvalidKey
	}
	for _, segment := range strings.Split(key, "/") {
		if len(segment) > maxSegmentLength {
			return errKeyTooLong
		}
	}
	return nil
}

// writeFailure classifies the error of a write (PUT, CopyObject, a folder
// marker, a multipart completion) into the S3 error the client should see. It
// returns nil for a fault of this server, which the caller logs and answers
// with InternalError.
func writeFailure(err error) *objectFailure {
	var failure *objectFailure
	switch {
	case errors.As(err, &failure):
		return failure
	case errors.Is(err, syscall.ENOTDIR):
		// mkdir or rename met a regular file where the key needs a folder.
		return errParentIsObject
	case errors.Is(err, syscall.EISDIR), errors.Is(err, syscall.ENOTEMPTY):
		// rename met a folder where the key needs an object.
		return errObjectIsDirectory
	case errors.Is(err, syscall.ENAMETOOLONG):
		return errKeyTooLong
	case errors.Is(err, syscall.EILSEQ):
		return errInvalidKey
	}
	return nil
}

// publishFailure is writeFailure for a write that failed to publish at dest. A
// rename refused because dest is a folder is the client's conflict, whatever
// the platform reported for it: EISDIR on Linux, EEXIST on macOS.
func publishFailure(err error, dest string) *objectFailure {
	if failure := writeFailure(err); failure != nil {
		return failure
	}
	var rename *os.LinkError
	if errors.As(err, &rename) {
		if info, statErr := os.Stat(dest); statErr == nil && info.IsDir() {
			return errObjectIsDirectory
		}
	}
	return nil
}

// readMissing reports whether a stat error of a read means there is no object
// at the key: nothing is there, or a prefix of the key is an object, so the
// key cannot exist below it.
func readMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// writeObjectFailure answers a request with failure, adding the Retry-After a
// SlowDown asks for.
func writeObjectFailure(w http.ResponseWriter, failure *objectFailure) {
	if failure.status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	writeS3Error(w, failure.status, failure.code, failure.message)
}

// trackedBody remembers the error reading a request body failed with, so a
// failed transfer can be told apart from a failed disk: a body that broke off
// is the client going away, which is routine for uploads from phones and
// flaky links and no fault of this server.
type trackedBody struct {
	r   io.Reader
	err error
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && err != io.EOF {
		b.err = err
	}
	return n, err
}

// clientAborted reports whether a request failed because its client went
// away rather than because of this server: the request was cancelled, or the
// body broke off (connection reset, unexpected EOF, a read deadline).
func clientAborted(r *http.Request, body *trackedBody) bool {
	if errors.Is(r.Context().Err(), context.Canceled) {
		return true
	}
	return body != nil && body.err != nil
}
