package s3

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/solkin/sebastian/internal/multipart"
)

// maxCompleteBodyBytes bounds the CompleteMultipartUpload request body. A
// 10000-part list is roughly 1 MB of XML, so 8 MiB leaves generous headroom while
// keeping an unbounded body from being buffered.
const maxCompleteBodyBytes = 8 << 20

// defaultMaxParts and defaultMaxUploads are the S3 page sizes for ListParts and
// ListMultipartUploads.
const (
	defaultMaxParts   = 1000
	defaultMaxUploads = 1000
)

// --- S3 XML types ---

// InitiateMultipartUploadResult is the response for CreateMultipartUpload.
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// CompleteMultipartUploadRequest is the client-supplied part list.
type CompleteMultipartUploadRequest struct {
	XMLName xml.Name            `xml:"CompleteMultipartUpload"`
	Parts   []CompletePartEntry `xml:"Part"`
}

// CompletePartEntry is one entry of a completion list.
type CompletePartEntry struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// CompleteMultipartUploadResult is the response for CompleteMultipartUpload.
type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// ListPartsResult is the response for ListParts.
type ListPartsResult struct {
	XMLName              xml.Name   `xml:"ListPartsResult"`
	Xmlns                string     `xml:"xmlns,attr"`
	Bucket               string     `xml:"Bucket"`
	Key                  string     `xml:"Key"`
	UploadID             string     `xml:"UploadId"`
	Initiator            Owner      `xml:"Initiator"`
	Owner                Owner      `xml:"Owner"`
	StorageClass         string     `xml:"StorageClass"`
	PartNumberMarker     int        `xml:"PartNumberMarker"`
	NextPartNumberMarker int        `xml:"NextPartNumberMarker,omitempty"`
	MaxParts             int        `xml:"MaxParts"`
	IsTruncated          bool       `xml:"IsTruncated"`
	Parts                []PartInfo `xml:"Part"`
}

// PartInfo describes one staged part in a ListParts response.
type PartInfo struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// ListMultipartUploadsResult is the response for ListMultipartUploads.
type ListMultipartUploadsResult struct {
	XMLName            xml.Name       `xml:"ListMultipartUploadsResult"`
	Xmlns              string         `xml:"xmlns,attr"`
	Bucket             string         `xml:"Bucket"`
	KeyMarker          string         `xml:"KeyMarker"`
	UploadIDMarker     string         `xml:"UploadIdMarker"`
	NextKeyMarker      string         `xml:"NextKeyMarker,omitempty"`
	NextUploadIDMarker string         `xml:"NextUploadIdMarker,omitempty"`
	Prefix             string         `xml:"Prefix,omitempty"`
	Delimiter          string         `xml:"Delimiter,omitempty"`
	MaxUploads         int            `xml:"MaxUploads"`
	IsTruncated        bool           `xml:"IsTruncated"`
	Uploads            []UploadInfo   `xml:"Upload"`
	CommonPrefixes     []CommonPrefix `xml:"CommonPrefixes,omitempty"`
}

// UploadInfo describes one in-progress upload in a ListMultipartUploads response.
type UploadInfo struct {
	Key          string `xml:"Key"`
	UploadID     string `xml:"UploadId"`
	Initiator    Owner  `xml:"Initiator"`
	Owner        Owner  `xml:"Owner"`
	StorageClass string `xml:"StorageClass"`
	Initiated    string `xml:"Initiated"`
}

// sebastianOwner is the single synthetic identity this server reports.
func sebastianOwner() Owner {
	return Owner{ID: "sebastian", DisplayName: "sebastian"}
}

// --- error mapping ---

// writeMultipartError translates a store error into the S3 error the client
// expects. Anything unrecognized becomes InternalError and is logged, so a new
// failure mode never leaks its Go text to the wire.
func (g *Gateway) writeMultipartError(w http.ResponseWriter, err error, op, bucket, key string) {
	switch {
	case errors.Is(err, multipart.ErrNoSuchUpload):
		writeS3Error(w, http.StatusNotFound, "NoSuchUpload",
			"The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.")
	case errors.Is(err, multipart.ErrInvalidPartNumber):
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument",
			"Part number must be an integer between 1 and 10000, inclusive.")
	case errors.Is(err, multipart.ErrInvalidPart):
		writeS3Error(w, http.StatusBadRequest, "InvalidPart",
			"One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not have matched the part's entity tag.")
	case errors.Is(err, multipart.ErrInvalidPartOrder):
		writeS3Error(w, http.StatusBadRequest, "InvalidPartOrder",
			"The list of parts was not in ascending order. Parts must be ordered by part number.")
	case errors.Is(err, multipart.ErrEmptyPartList):
		writeS3Error(w, http.StatusBadRequest, "InvalidRequest",
			"You must specify at least one part.")
	case errors.Is(err, multipart.ErrPartTooSmall):
		writeS3Error(w, http.StatusBadRequest, "EntityTooSmall",
			"Your proposed upload is smaller than the minimum allowed object size. Each part but the last must be at least the minimum part size.")
	case errors.Is(err, multipart.ErrPartTooLarge), errors.Is(err, multipart.ErrObjectTooLarge):
		writeS3Error(w, http.StatusRequestEntityTooLarge, "EntityTooLarge",
			"Your proposed upload exceeds the maximum allowed size")
	case errors.Is(err, multipart.ErrBadDigest):
		writeS3Error(w, http.StatusBadRequest, "BadDigest",
			"The Content-MD5 you specified did not match what we received.")
	case errors.Is(err, multipart.ErrContentSHA256Mismatch):
		writeS3Error(w, http.StatusBadRequest, "XAmzContentSHA256Mismatch",
			"The provided 'x-amz-content-sha256' header does not match what was computed.")
	case errors.Is(err, multipart.ErrCorruptPart):
		writeS3Error(w, http.StatusInternalServerError, "InternalError",
			"A previously uploaded part failed its integrity check.")
	case errors.Is(err, multipart.ErrBusy), errors.Is(err, multipart.ErrTooManyUploads):
		w.Header().Set("Retry-After", "1")
		writeS3Error(w, http.StatusServiceUnavailable, "SlowDown",
			"Please reduce your request rate.")
	default:
		g.logger.Error("multipart operation failed", "op", op, "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
	}
}

// multipartReady validates the common preconditions of every multipart request:
// the feature is configured, the names are well-formed, and the bucket exists. It
// returns the resolved object path.
func (g *Gateway) multipartReady(w http.ResponseWriter, bucket, key string) (string, bool) {
	if g.multipart == nil {
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented",
			"Multipart upload is not enabled on this server.")
		return "", false
	}
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return "", false
	}

	bp, ok := g.bucketPath(bucket)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return "", false
	}
	info, err := os.Stat(bp)
	if os.IsNotExist(err) || (err == nil && !info.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return "", false
	}
	if err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return "", false
	}

	op, ok := g.objectPath(bucket, key)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid key")
		return "", false
	}
	return op, true
}

// ownedUpload loads an upload and confirms it belongs to the bucket and key in the
// request URL, so an upload ID cannot be redirected at a different object.
func (g *Gateway) ownedUpload(w http.ResponseWriter, uploadID, bucket, key string) (multipart.Upload, bool) {
	up, err := g.multipart.Get(uploadID)
	if err != nil {
		g.writeMultipartError(w, err, "get-upload", bucket, key)
		return multipart.Upload{}, false
	}
	if up.Bucket != bucket || up.Key != key {
		g.writeMultipartError(w, multipart.ErrNoSuchUpload, "get-upload", bucket, key)
		return multipart.Upload{}, false
	}
	return up, true
}

// --- handlers ---

// handleCreateMultipartUpload starts a new multipart upload (POST /{bucket}/{key}?uploads).
func (g *Gateway) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if _, ok := g.multipartReady(w, bucket, key); !ok {
		return
	}

	up, err := g.multipart.Create(bucket, key)
	if err != nil {
		g.writeMultipartError(w, err, "create", bucket, key)
		return
	}

	g.logger.Info("multipart upload initiated", "bucket", bucket, "key", key, "upload_id", up.ID)
	writeXML(w, http.StatusOK, InitiateMultipartUploadResult{
		Xmlns:    s3Xmlns,
		Bucket:   bucket,
		Key:      key,
		UploadID: up.ID,
	})
}

// handleUploadPart stages one part (PUT /{bucket}/{key}?partNumber=N&uploadId=ID).
func (g *Gateway) handleUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	if _, ok := g.multipartReady(w, bucket, key); !ok {
		return
	}

	partNumber, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("partNumber")))
	if err != nil {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument",
			"Part number must be an integer between 1 and 10000, inclusive.")
		return
	}

	if _, ok := g.ownedUpload(w, uploadID, bucket, key); !ok {
		return
	}

	// The whole-object cap still applies per part: a part larger than the object
	// limit could never be completed anyway.
	body := r.Body
	if g.config.MaxUploadBytes > 0 {
		body = http.MaxBytesReader(w, body, g.config.MaxUploadBytes)
	}

	// Mirror PutObject: when the client declares a concrete payload SHA-256 — the
	// value its SigV4 signature covers — the part is re-hashed and a mismatch is
	// refused, so a captured signed request cannot be replayed with a swapped body.
	part, err := g.multipart.WritePart(uploadID, partNumber, body, multipart.Checksums{
		ContentMD5:    r.Header.Get("Content-MD5"),
		ContentSHA256: r.Header.Get("X-Amz-Content-Sha256"),
	})
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeS3Error(w, http.StatusRequestEntityTooLarge, "EntityTooLarge",
				"Your proposed upload exceeds the maximum allowed size")
			return
		}
		g.writeMultipartError(w, err, "upload-part", bucket, key)
		return
	}

	g.logger.Debug("part uploaded", "bucket", bucket, "key", key, "upload_id", uploadID,
		"part", partNumber, "size", part.Size)

	w.Header().Set("ETag", `"`+part.ETag+`"`)
	w.WriteHeader(http.StatusOK)
}

// handleCompleteMultipartUpload assembles the object (POST /{bucket}/{key}?uploadId=ID).
func (g *Gateway) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	objPath, ok := g.multipartReady(w, bucket, key)
	if !ok {
		return
	}
	if _, ok := g.ownedUpload(w, uploadID, bucket, key); !ok {
		return
	}

	data, err := io.ReadAll(io.LimitReader(r.Body, maxCompleteBodyBytes+1))
	if err != nil {
		writeS3Error(w, http.StatusBadRequest, "IncompleteBody", "Failed to read the request body.")
		return
	}
	if len(data) > maxCompleteBodyBytes {
		writeS3Error(w, http.StatusRequestEntityTooLarge, "MaxMessageLengthExceeded",
			"Your request was too large.")
		return
	}

	var req CompleteMultipartUploadRequest
	if err := xml.Unmarshal(data, &req); err != nil {
		writeS3Error(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.")
		return
	}

	parts := make([]multipart.CompletePart, 0, len(req.Parts))
	for _, p := range req.Parts {
		parts = append(parts, multipart.CompletePart{Number: p.PartNumber, ETag: p.ETag})
	}

	result, err := g.multipart.Complete(uploadID, parts, objPath)
	if err != nil {
		g.writeMultipartError(w, err, "complete", bucket, key)
		return
	}

	g.logger.Info("object created via multipart upload",
		"bucket", bucket, "key", key, "upload_id", uploadID, "parts", result.Parts, "size", result.Size)

	writeXML(w, http.StatusOK, CompleteMultipartUploadResult{
		Xmlns:    s3Xmlns,
		Location: "/" + bucket + "/" + escapeKeyPath(key),
		Bucket:   bucket,
		Key:      key,
		ETag:     `"` + result.ETag + `"`,
	})
}

// handleAbortMultipartUpload discards an upload (DELETE /{bucket}/{key}?uploadId=ID).
func (g *Gateway) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	if _, ok := g.multipartReady(w, bucket, key); !ok {
		return
	}
	if _, ok := g.ownedUpload(w, uploadID, bucket, key); !ok {
		return
	}

	if err := g.multipart.Abort(uploadID); err != nil {
		g.writeMultipartError(w, err, "abort", bucket, key)
		return
	}

	g.logger.Info("multipart upload aborted", "bucket", bucket, "key", key, "upload_id", uploadID)
	w.WriteHeader(http.StatusNoContent)
}

// handleListParts lists staged parts (GET /{bucket}/{key}?uploadId=ID).
func (g *Gateway) handleListParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	if _, ok := g.multipartReady(w, bucket, key); !ok {
		return
	}
	if _, ok := g.ownedUpload(w, uploadID, bucket, key); !ok {
		return
	}

	query := r.URL.Query()
	marker, ok := parseNonNegativeInt(query.Get("part-number-marker"), 0)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid part-number-marker value")
		return
	}
	maxParts, ok := parseNonNegativeInt(query.Get("max-parts"), defaultMaxParts)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid max-parts value")
		return
	}
	if maxParts == 0 || maxParts > defaultMaxParts {
		maxParts = defaultMaxParts
	}

	parts, truncated, next, err := g.multipart.ListParts(uploadID, marker, maxParts)
	if err != nil {
		g.writeMultipartError(w, err, "list-parts", bucket, key)
		return
	}

	infos := make([]PartInfo, 0, len(parts))
	for _, p := range parts {
		infos = append(infos, PartInfo{
			PartNumber:   p.Number,
			LastModified: p.LastModified.UTC().Format(s3TimeFormat),
			ETag:         `"` + p.ETag + `"`,
			Size:         p.Size,
		})
	}

	writeXML(w, http.StatusOK, ListPartsResult{
		Xmlns:                s3Xmlns,
		Bucket:               bucket,
		Key:                  key,
		UploadID:             uploadID,
		Initiator:            sebastianOwner(),
		Owner:                sebastianOwner(),
		StorageClass:         "STANDARD",
		PartNumberMarker:     marker,
		NextPartNumberMarker: next,
		MaxParts:             maxParts,
		IsTruncated:          truncated,
		Parts:                infos,
	})
}

// handleListMultipartUploads lists in-progress uploads (GET /{bucket}?uploads).
func (g *Gateway) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) {
	if g.multipart == nil {
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented",
			"Multipart upload is not enabled on this server.")
		return
	}
	if !validateBucketName(bucket) {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return
	}
	bp, ok := g.bucketPath(bucket)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return
	}
	info, err := os.Stat(bp)
	if os.IsNotExist(err) || (err == nil && !info.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return
	}

	query := r.URL.Query()
	prefix := query.Get("prefix")
	keyMarker := query.Get("key-marker")
	uploadIDMarker := query.Get("upload-id-marker")
	maxUploads, ok := parseNonNegativeInt(query.Get("max-uploads"), defaultMaxUploads)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid max-uploads value")
		return
	}
	if maxUploads == 0 || maxUploads > defaultMaxUploads {
		maxUploads = defaultMaxUploads
	}

	delimiter := query.Get("delimiter")

	// Fetch the whole matching set and page it here: with a delimiter, uploads and
	// the common prefixes they roll up into share one ordered key space, and
	// truncation has to apply to that merged view. The active-upload cap bounds
	// how much this can be.
	uploads, _, err := g.multipart.List(bucket, prefix, "", "", 0)
	if err != nil {
		g.writeMultipartError(w, err, "list-uploads", bucket, "")
		return
	}

	infos, prefixes, truncated, nextKey, nextUploadID :=
		pageUploads(uploads, prefix, delimiter, keyMarker, uploadIDMarker, maxUploads)

	result := ListMultipartUploadsResult{
		Xmlns:              s3Xmlns,
		Bucket:             bucket,
		KeyMarker:          keyMarker,
		UploadIDMarker:     uploadIDMarker,
		Prefix:             prefix,
		Delimiter:          delimiter,
		MaxUploads:         maxUploads,
		IsTruncated:        truncated,
		Uploads:            infos,
		CommonPrefixes:     prefixes,
		NextKeyMarker:      nextKey,
		NextUploadIDMarker: nextUploadID,
	}

	g.logger.Debug("list multipart uploads", "bucket", bucket, "count", len(infos))
	writeXML(w, http.StatusOK, result)
}

// pageUploads rolls uploads up by delimiter, resumes after the marker pair, and
// truncates to maxUploads, mirroring how S3 pages ListMultipartUploads.
//
// Uploads and common prefixes are ordered together by key; a prefix carries no
// upload ID, so it sorts ahead of any upload sharing its key.
func pageUploads(uploads []multipart.Upload, prefix, delimiter, keyMarker, uploadIDMarker string, maxUploads int) (
	infos []UploadInfo, prefixes []CommonPrefix, truncated bool, nextKey, nextUploadID string) {

	type item struct {
		key      string
		uploadID string
		upload   multipart.Upload
		isPrefix bool
	}

	var items []item
	seenPrefix := make(map[string]bool)
	for _, u := range uploads {
		if delimiter != "" {
			rest := strings.TrimPrefix(u.Key, prefix)
			if idx := strings.Index(rest, delimiter); idx >= 0 {
				cp := prefix + rest[:idx+len(delimiter)]
				if !seenPrefix[cp] {
					seenPrefix[cp] = true
					items = append(items, item{key: cp, isPrefix: true})
				}
				continue
			}
		}
		items = append(items, item{key: u.Key, uploadID: u.ID, upload: u})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].key != items[j].key {
			return items[i].key < items[j].key
		}
		return items[i].uploadID < items[j].uploadID
	})

	if keyMarker != "" || uploadIDMarker != "" {
		idx := sort.Search(len(items), func(i int) bool {
			if items[i].key != keyMarker {
				return items[i].key > keyMarker
			}
			return items[i].uploadID > uploadIDMarker
		})
		items = items[idx:]
	}

	if maxUploads > 0 && len(items) > maxUploads {
		items = items[:maxUploads]
		truncated = true
	}

	for _, it := range items {
		if it.isPrefix {
			prefixes = append(prefixes, CommonPrefix{Prefix: it.key})
			continue
		}
		infos = append(infos, UploadInfo{
			Key:          it.upload.Key,
			UploadID:     it.upload.ID,
			Initiator:    sebastianOwner(),
			Owner:        sebastianOwner(),
			StorageClass: "STANDARD",
			Initiated:    it.upload.Initiated.UTC().Format(s3TimeFormat),
		})
	}
	if truncated && len(items) > 0 {
		last := items[len(items)-1]
		nextKey = last.key
		nextUploadID = last.uploadID
	}
	return infos, prefixes, truncated, nextKey, nextUploadID
}

// parseNonNegativeInt parses an optional non-negative integer query parameter,
// returning def when it is absent and ok=false when it is not a valid number.
func parseNonNegativeInt(raw string, def int) (int, bool) {
	if strings.TrimSpace(raw) == "" {
		return def, true
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// escapeKeyPath percent-encodes a key for use in the Location header of a
// completion response, leaving the "/" separators intact.
func escapeKeyPath(key string) string {
	segments := strings.Split(key, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return strings.Join(segments, "/")
}
