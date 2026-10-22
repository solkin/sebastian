package s3

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/solkin/sebastian/internal/fileops"
	"github.com/solkin/sebastian/internal/gateway"
)

// --- S3 XML response types ---

// S3Error is the standard S3 error response.
type S3Error struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

// ListAllMyBucketsResult is the response for ListBuckets.
type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Xmlns   string   `xml:"xmlns,attr"`
	Owner   Owner    `xml:"Owner"`
	Buckets Buckets  `xml:"Buckets"`
}

// Owner represents the bucket owner.
type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// Buckets is a container for bucket list.
type Buckets struct {
	Bucket []BucketInfo `xml:"Bucket"`
}

// BucketInfo represents a single bucket.
type BucketInfo struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// ListBucketResultV1 is the response for ListObjects (V1).
type ListBucketResultV1 struct {
	XMLName        xml.Name       `xml:"ListBucketResult"`
	Xmlns          string         `xml:"xmlns,attr"`
	Name           string         `xml:"Name"`
	Prefix         string         `xml:"Prefix"`
	Marker         string         `xml:"Marker"`
	NextMarker     string         `xml:"NextMarker,omitempty"`
	Delimiter      string         `xml:"Delimiter,omitempty"`
	MaxKeys        int            `xml:"MaxKeys"`
	IsTruncated    bool           `xml:"IsTruncated"`
	Contents       []ObjectInfo   `xml:"Contents"`
	CommonPrefixes []CommonPrefix `xml:"CommonPrefixes,omitempty"`
}

// ListBucketResultV2 is the response for ListObjectsV2.
type ListBucketResultV2 struct {
	XMLName               xml.Name       `xml:"ListBucketResult"`
	Xmlns                 string         `xml:"xmlns,attr"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	MaxKeys               int            `xml:"MaxKeys"`
	IsTruncated           bool           `xml:"IsTruncated"`
	KeyCount              int            `xml:"KeyCount"`
	Contents              []ObjectInfo   `xml:"Contents"`
	CommonPrefixes        []CommonPrefix `xml:"CommonPrefixes,omitempty"`
	EncodingType          string         `xml:"EncodingType,omitempty"`
	StartAfter            string         `xml:"StartAfter,omitempty"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
}

// LocationConstraint is the response for GetBucketLocation.
type LocationConstraint struct {
	XMLName xml.Name `xml:"LocationConstraint"`
	Xmlns   string   `xml:"xmlns,attr"`
	Value   string   `xml:",chardata"`
}

// VersioningConfiguration is the response for GetBucketVersioning.
type VersioningConfiguration struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	Xmlns   string   `xml:"xmlns,attr"`
}

// DeleteObjectsRequest is the body of a DeleteObjects request.
type DeleteObjectsRequest struct {
	XMLName xml.Name              `xml:"Delete"`
	Quiet   bool                  `xml:"Quiet"`
	Objects []DeleteObjectsObject `xml:"Object"`
}

// DeleteObjectsObject names one object to delete; a VersionId is ignored, as
// buckets are not versioned.
type DeleteObjectsObject struct {
	Key string `xml:"Key"`
}

// DeleteObjectsResult is the response for DeleteObjects: the keys deleted
// (unless the request was quiet) and the keys that could not be.
type DeleteObjectsResult struct {
	XMLName xml.Name            `xml:"DeleteResult"`
	Xmlns   string              `xml:"xmlns,attr"`
	Deleted []DeletedObject     `xml:"Deleted"`
	Errors  []DeleteObjectError `xml:"Error"`
}

// DeletedObject is a key DeleteObjects deleted.
type DeletedObject struct {
	Key string `xml:"Key"`
}

// DeleteObjectError is a key DeleteObjects could not delete, and why.
type DeleteObjectError struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// ObjectInfo represents a single object in a listing.
type ObjectInfo struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

// CommonPrefix represents a common prefix (virtual directory) in a listing.
type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// s3TimeFormat is the time format used by S3 (ISO 8601 with milliseconds, always UTC).
const s3TimeFormat = "2006-01-02T15:04:05.000Z"

// s3Xmlns is the namespace every S3 response document carries.
const s3Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

// --- Helpers ---

// writeS3Error writes an S3-formatted XML error response.
func writeS3Error(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)
	data, _ := xml.MarshalIndent(S3Error{Code: code, Message: message}, "", "  ")
	w.Write([]byte(xml.Header))
	w.Write(data)
}

// writeXML writes an XML response with proper headers.
func writeXML(w http.ResponseWriter, statusCode int, v interface{}) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)
	data, _ := xml.MarshalIndent(v, "", "  ")
	w.Write([]byte(xml.Header))
	w.Write(data)
}

// bucketPath returns the absolute path for a bucket (first-level dir in rootDir).
// It routes through gateway.SafePath so a bucket directory that is a symlink
// escaping rootDir is rejected (ok=false), matching the other gateways.
func (g *Gateway) bucketPath(bucket string) (string, bool) {
	_, full, err := gateway.SafePath(g.rootDir, bucket)
	if err != nil {
		return "", false
	}
	return full, true
}

// objectPath returns the absolute path for an object within a bucket. It routes
// through gateway.SafePath (which resolves symlinks and rejects any escape from
// rootDir) and additionally confirms the result stays within the bucket dir.
func (g *Gateway) objectPath(bucket, key string) (string, bool) {
	_, full, err := gateway.SafePath(g.rootDir, bucket+"/"+key)
	if err != nil {
		return "", false
	}
	if !gateway.PathResolvesWithin(filepath.Join(g.rootDir, bucket), full) {
		return "", false
	}
	return full, true
}

// validateBucketName checks that a bucket name is safe.
func validateBucketName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	// The reserved state directory is not a bucket; refusing the name here keeps a
	// client from creating, listing, or deleting it through the bucket API.
	if gateway.IsReserved(name) {
		return false
	}
	return true
}

// validateKey checks that an object key is safe (no path traversal).
func validateKey(key string) bool {
	if key == "" {
		return false
	}
	// Reject any ".." path segment outright rather than letting filepath.Clean
	// collapse it: a key like "a/../b" must not be silently rewritten to "b"
	// (AWS treats keys literally), and the traversal intent is refused either way.
	for _, seg := range strings.Split(filepath.ToSlash(key), "/") {
		if seg == ".." {
			return false
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean(key))
	if strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") || cleaned == ".." {
		return false
	}
	return true
}

// isHexSHA256 reports whether s is a 64-character lowercase hex string, i.e. a
// concrete SHA-256 digest as opposed to UNSIGNED-PAYLOAD, a streaming marker, or
// an absent header.
func isHexSHA256(s string) bool {
	if len(s) != 64 {
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

// etagFor returns a deterministic, content-independent ETag derived from a file's
// size and modification time. It avoids reading file contents on list/get/head,
// stays stable while the file is unchanged, and is identical across LIST, GET,
// HEAD, and PUT. Note: it is intentionally NOT a hash of the object's content.
func etagFor(fi os.FileInfo) string {
	return fmt.Sprintf("\"%x-%x\"", fi.Size(), fi.ModTime().UnixNano())
}

// --- Bucket handlers ---

// handleListBuckets lists all first-level directories in rootDir as buckets.
func (g *Gateway) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(g.rootDir)
	if err != nil {
		g.logger.Error("list buckets: read rootDir failed", "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to list buckets")
		return
	}

	var buckets []BucketInfo
	for _, entry := range entries {
		if !entry.IsDir() || gateway.IsReserved(entry.Name()) || gateway.IsScratchFile(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		buckets = append(buckets, BucketInfo{
			Name:         entry.Name(),
			CreationDate: info.ModTime().UTC().Format(s3TimeFormat),
		})
	}

	result := ListAllMyBucketsResult{
		Xmlns: s3Xmlns,
		Owner: Owner{ID: "sebastian", DisplayName: "sebastian"},
		Buckets: Buckets{
			Bucket: buckets,
		},
	}

	g.logger.Debug("list buckets", "count", len(buckets))
	writeXML(w, http.StatusOK, result)
}

// handleHeadBucket checks if a bucket exists.
func (g *Gateway) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
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
	if err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	w.Header().Set("x-amz-bucket-region", "us-east-1")
	w.WriteHeader(http.StatusOK)
}

// handleCreateBucket creates a new bucket (first-level directory).
func (g *Gateway) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketName(bucket) {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return
	}

	bp, ok := g.bucketPath(bucket)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return
	}

	if err := g.createBucket(bucket, bp); err != nil {
		g.logger.Error("create bucket failed", "bucket", bucket, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create bucket")
		return
	}

	w.Header().Set("Location", "/"+bucket)
	w.WriteHeader(http.StatusOK)
}

// createBucket makes the directory of a bucket unless it exists already.
func (g *Gateway) createBucket(bucket, bp string) error {
	if info, err := os.Stat(bp); err == nil && info.IsDir() {
		return nil
	}
	if err := fileops.Mkdir(g.rootDir, bp, 0o755, false); err != nil {
		return err
	}
	g.logger.Info("bucket created", "bucket", bucket)
	return nil
}

// CreateBuckets makes the named buckets that do not exist yet, so that they are
// there before the first request. A name that cannot be a bucket is an error.
func (g *Gateway) CreateBuckets(buckets []string) error {
	for _, bucket := range buckets {
		bp, ok := g.bucketPath(bucket)
		if !validateBucketName(bucket) || !ok {
			return fmt.Errorf("invalid bucket name %q", bucket)
		}
		if err := g.createBucket(bucket, bp); err != nil {
			return fmt.Errorf("create bucket %q: %w", bucket, err)
		}
	}
	return nil
}

// handleDeleteBucket deletes an empty bucket.
func (g *Gateway) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
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

	entries, err := os.ReadDir(bp)
	if err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}
	if len(entries) > 0 {
		writeS3Error(w, http.StatusConflict, "BucketNotEmpty", "The bucket you tried to delete is not empty.")
		return
	}
	// Staged parts live outside the bucket directory, so an in-progress upload
	// leaves the bucket looking empty. Deleting it would strand those parts and
	// break the client's pending completion.
	if g.multipart != nil {
		hasUploads, uploadsErr := g.multipart.HasUploads(bucket)
		if uploadsErr != nil {
			g.logger.Error("delete bucket: check multipart uploads failed", "bucket", bucket, "error", uploadsErr)
			writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
			return
		}
		if hasUploads {
			writeS3Error(w, http.StatusConflict, "BucketNotEmpty",
				"The bucket you tried to delete has in-progress multipart uploads.")
			return
		}
	}

	if err := fileops.Remove(g.rootDir, bp, false); err != nil {
		g.logger.Error("delete bucket failed", "bucket", bucket, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to delete bucket")
		return
	}

	g.logger.Info("bucket deleted", "bucket", bucket)
	w.WriteHeader(http.StatusNoContent)
}

// --- Sub-resource handlers ---

// handleGetBucketLocation returns the bucket region.
func (g *Gateway) handleGetBucketLocation(w http.ResponseWriter, r *http.Request, bucket string) {
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
	result := LocationConstraint{
		Xmlns: s3Xmlns,
	}
	g.logger.Debug("get bucket location", "bucket", bucket)
	writeXML(w, http.StatusOK, result)
}

// handleGetBucketVersioning returns versioning status (always disabled).
func (g *Gateway) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
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
	result := VersioningConfiguration{
		Xmlns: s3Xmlns,
	}
	g.logger.Debug("get bucket versioning", "bucket", bucket)
	writeXML(w, http.StatusOK, result)
}

// handleGetBucketACL returns a canned ACL response (owner full control).
func (g *Gateway) handleGetBucketACL(w http.ResponseWriter, r *http.Request, bucket string) {
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
	acl := `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>sebastian</ID><DisplayName>sebastian</DisplayName></Owner>
  <AccessControlList>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>sebastian</ID><DisplayName>sebastian</DisplayName>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>`
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(acl))
}

// --- Object handlers ---

// paginate applies S3 list pagination over the merged, lexically ordered key
// space of objects and common prefixes: it drops everything up to and including
// startAfter, keeps at most maxKeys items, and reports whether the listing was
// truncated along with the token to resume from (the last key returned).
func paginate(objects []ObjectInfo, commonPrefixes []string, startAfter string, maxKeys int) (pageObjects []ObjectInfo, pagePrefixes []CommonPrefix, isTruncated bool, nextToken string) {
	type item struct {
		key      string
		obj      ObjectInfo
		isPrefix bool
	}

	items := make([]item, 0, len(objects)+len(commonPrefixes))
	for _, o := range objects {
		items = append(items, item{key: o.Key, obj: o})
	}
	for _, p := range commonPrefixes {
		items = append(items, item{key: p, isPrefix: true})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })

	if startAfter != "" {
		idx := sort.Search(len(items), func(i int) bool { return items[i].key > startAfter })
		items = items[idx:]
	}

	if len(items) > maxKeys {
		isTruncated = true
		items = items[:maxKeys]
	}

	for _, it := range items {
		if it.isPrefix {
			pagePrefixes = append(pagePrefixes, CommonPrefix{Prefix: it.key})
		} else {
			pageObjects = append(pageObjects, it.obj)
		}
	}
	if isTruncated && len(items) > 0 {
		nextToken = items[len(items)-1].key
	}
	return pageObjects, pagePrefixes, isTruncated, nextToken
}

// handleListObjects dispatches to V1 or V2 based on the list-type query parameter.
func (g *Gateway) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
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

	listType := r.URL.Query().Get("list-type")
	if listType == "2" {
		g.handleListObjectsV2(w, r, bucket, bp)
	} else {
		g.handleListObjectsV1(w, r, bucket, bp)
	}
}

// handleListObjectsV1 returns a V1 ListBucketResult (with Marker, no KeyCount).
func (g *Gateway) handleListObjectsV1(w http.ResponseWriter, r *http.Request, bucket, bp string) {
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	marker := r.URL.Query().Get("marker")
	maxKeys, ok := parseMaxKeys(r)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid max-keys value")
		return
	}

	pageObjects, pagePrefixes, isTruncated, nextToken, err := g.filesystemPage(r.Context(), bp, prefix, delimiter, marker, maxKeys)
	if err != nil {
		g.listFailed(w, r, bucket, err)
		return
	}

	result := ListBucketResultV1{
		Xmlns:          s3Xmlns,
		Name:           bucket,
		Prefix:         prefix,
		Marker:         marker,
		NextMarker:     nextToken,
		Delimiter:      delimiter,
		MaxKeys:        maxKeys,
		IsTruncated:    isTruncated,
		Contents:       pageObjects,
		CommonPrefixes: pagePrefixes,
	}

	g.logger.Debug("list objects v1", "bucket", bucket, "prefix", prefix, "count", len(pageObjects))
	writeXML(w, http.StatusOK, result)
}

// handleListObjectsV2 returns a V2 ListBucketResult (with KeyCount, ContinuationToken).
func (g *Gateway) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket, bp string) {
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	startAfter := r.URL.Query().Get("start-after")
	contToken := r.URL.Query().Get("continuation-token")
	maxKeys, ok := parseMaxKeys(r)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid max-keys value")
		return
	}

	// A continuation token, when present, takes precedence over start-after.
	skipAfter := startAfter
	if contToken != "" {
		skipAfter = contToken
	}

	pageObjects, pagePrefixes, isTruncated, nextToken, err := g.filesystemPage(r.Context(), bp, prefix, delimiter, skipAfter, maxKeys)
	if err != nil {
		g.listFailed(w, r, bucket, err)
		return
	}

	result := ListBucketResultV2{
		Xmlns:                 s3Xmlns,
		Name:                  bucket,
		Prefix:                prefix,
		Delimiter:             delimiter,
		MaxKeys:               maxKeys,
		IsTruncated:           isTruncated,
		KeyCount:              len(pageObjects) + len(pagePrefixes),
		Contents:              pageObjects,
		CommonPrefixes:        pagePrefixes,
		StartAfter:            startAfter,
		ContinuationToken:     contToken,
		NextContinuationToken: nextToken,
	}

	g.logger.Debug("list objects v2", "bucket", bucket, "prefix", prefix, "count", len(pageObjects))
	writeXML(w, http.StatusOK, result)
}

// listFailed answers a listing that could not be made. A client that went away
// mid-listing cancelled it, which is no fault of this server.
func (g *Gateway) listFailed(w http.ResponseWriter, r *http.Request, bucket string, err error) {
	if clientAborted(r, nil) {
		g.logger.Debug("list objects: client went away", "bucket", bucket, "error", err)
	} else {
		g.logger.Error("list objects failed", "bucket", bucket, "error", err)
	}
	writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
}

// parseMaxKeys extracts max-keys from the query, defaulting to 1000. It returns
// ok=false for a non-numeric value (e.g. "abc" or trailing garbage like "5x") so
// the caller can reject it with InvalidArgument instead of silently using a
// default or a partially-parsed number.
func parseMaxKeys(r *http.Request) (int, bool) {
	s := r.URL.Query().Get("max-keys")
	if s == "" {
		return 1000, true
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	if n <= 0 {
		n = 1000
	}
	if n > 10000 {
		n = 10000
	}
	return n, true
}

// bucketExists reports whether a bucket directory is there. A bucket that
// cannot be looked at is assumed to exist, so an unreadable volume is not
// reported as a missing bucket.
func (g *Gateway) bucketExists(bucket string) bool {
	bp, ok := g.bucketPath(bucket)
	if !ok {
		return false
	}
	info, err := os.Stat(bp)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return info.IsDir()
}

// missingObject is the answer for a key with nothing behind it: NoSuchBucket
// when its bucket is missing too, as S3 reports it, and NoSuchKey otherwise.
func (g *Gateway) missingObject(bucket string) *objectFailure {
	if !g.bucketExists(bucket) {
		return errNoSuchBucket
	}
	return errNoSuchKey
}

// statObject resolves the key of a read and stats the object behind it. A
// folder, a key below an object, and a missing bucket all read as no object.
func (g *Gateway) statObject(bucket, key string) (string, os.FileInfo, *objectFailure) {
	if !validateBucketName(bucket) || !validateKey(key) {
		return "", nil, &objectFailure{http.StatusBadRequest, "InvalidArgument", "Invalid argument"}
	}
	op, ok := g.objectPath(bucket, key)
	if !ok {
		return "", nil, &objectFailure{http.StatusBadRequest, "InvalidArgument", "Invalid key"}
	}
	info, err := os.Stat(op)
	switch {
	case err == nil && !info.IsDir():
		return op, info, nil
	case err == nil || readMissing(err):
		return "", nil, g.missingObject(bucket)
	case errors.Is(err, syscall.ENAMETOOLONG):
		return "", nil, errKeyTooLong
	}
	g.logger.Error("stat object failed", "bucket", bucket, "key", key, "error", err)
	return "", nil, &objectFailure{http.StatusInternalServerError, "InternalError", "Internal error"}
}

// setObjectHeaders sets the headers that describe an object on a GET or HEAD.
func setObjectHeaders(w http.ResponseWriter, key string, info os.FileInfo) {
	h := w.Header()
	h.Set("Content-Type", contentTypeFor(key))
	h.Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	h.Set("ETag", etagFor(info))
	h.Set("Accept-Ranges", "bytes")
}

// handleHeadObject returns metadata for an object.
func (g *Gateway) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	_, info, failure := g.statObject(bucket, key)
	if failure != nil {
		writeObjectFailure(w, failure)
		return
	}

	setObjectHeaders(w, key, info)
	switch evaluateConditions(r, readConditions, info) {
	case conditionFailed:
		writeObjectFailure(w, errPreconditionFailed)
		return
	case conditionNotModified:
		writeNotModified(w, info)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.WriteHeader(http.StatusOK)
}

// handleGetObject serves an object's content.
//
// Preconditions and ranges are decided here, so that every answer that is not
// the object itself is an S3 error with a body that matches its headers:
// net/http's ServeContent would answer a failed If-Match with an empty 412 under
// the object's Content-Length, and an unsatisfiable range with text/plain. What
// remains for ServeContent is serving the bytes, whole or ranged.
func (g *Gateway) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	op, _, failure := g.statObject(bucket, key)
	if failure != nil {
		writeObjectFailure(w, failure)
		return
	}

	f, err := os.Open(op)
	if err != nil {
		if readMissing(err) {
			// Deleted between the stat and the open.
			writeObjectFailure(w, g.missingObject(bucket))
			return
		}
		g.logger.Error("get object: open failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	setObjectHeaders(w, key, info)
	switch evaluateConditions(r, readConditions, info) {
	case conditionFailed:
		writeObjectFailure(w, errPreconditionFailed)
		return
	case conditionNotModified:
		writeNotModified(w, info)
		return
	}

	// ServeContent gets a request whose conditions are already settled.
	serve := r.Clone(r.Context())
	for _, h := range []string{"If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range"} {
		serve.Header.Del(h)
	}
	if !ifRangeHolds(r, info) {
		serve.Header.Del("Range")
	} else {
		switch classifyRange(r.Header.Get("Range"), info.Size()) {
		case rangeIgnore:
			serve.Header.Del("Range")
		case rangeUnsatisfiable:
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", info.Size()))
			writeS3Error(w, http.StatusRequestedRangeNotSatisfiable, "InvalidRange",
				"The requested range is not satisfiable")
			return
		}
	}

	g.logger.Debug("get object", "bucket", bucket, "key", key, "size", info.Size())
	http.ServeContent(w, serve, "", info.ModTime(), f)
}

// declaredTooLarge reports whether a request body declares, before it is read,
// more than limit bytes; limit <= 0 is no limit. A plain body declares its
// Content-Length; an aws-chunked one declares its decoded length instead, which
// newPayload holds to the upload cap itself. Refusing here is what keeps an
// oversized upload from being sent at all: a client that asked for
// 100-continue is answered before it is told to go ahead.
func declaredTooLarge(r *http.Request, limit int64) bool {
	return limit > 0 && !streamingBody(r) && r.ContentLength > limit
}

// handlePutObject writes an object to the bucket.
func (g *Gateway) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}

	op, ok := g.objectPath(bucket, key)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid key")
		return
	}

	// Verify bucket exists.
	bp, ok := g.bucketPath(bucket)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return
	}
	bInfo, err := os.Stat(bp)
	if os.IsNotExist(err) || (err == nil && !bInfo.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return
	}

	if declaredTooLarge(r, g.config.MaxUploadBytes) {
		writeS3Error(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
		return
	}
	conditions, failure := parseWriteConditions(r)
	if failure != nil {
		writeObjectFailure(w, failure)
		return
	}
	// Refuse what is bound to fail before the body is read: a key that is a
	// folder, or a condition that already does not hold. The condition is
	// decided for good only at publication, under the root lock.
	current, statErr := os.Stat(op)
	if statErr == nil && current.IsDir() {
		writeObjectFailure(w, errObjectIsDirectory)
		return
	}
	if err := conditions.check(current, statErr); err != nil {
		if failure := writeFailure(err); failure != nil {
			writeObjectFailure(w, failure)
			return
		}
		// A stat that fails here for another reason fails the write later too,
		// where it is reported; nothing is decided by it now.
	}

	// Decode an aws-chunked body and check its signatures, decoded length, and
	// flexible checksum as it is read.
	body, failure := g.newPayload(r)
	if failure != nil {
		writeS3Error(w, failure.status, failure.code, failure.message)
		return
	}
	// Cap the decoded upload size when configured, translating an overflow into 413.
	var src io.Reader = body
	if g.config.MaxUploadBytes > 0 {
		src = http.MaxBytesReader(w, body, g.config.MaxUploadBytes)
	}
	tracked := &trackedBody{r: src}

	// When the client declares a concrete payload SHA-256 (the value the SigV4
	// signature is computed over), verify the streamed body against it and reject a
	// mismatch. This closes the integrity gap where a captured signed request could
	// be replayed with a swapped body. UNSIGNED-PAYLOAD and the streaming markers
	// carry no whole-body digest; a signed stream is verified chunk by chunk.
	declaredHash := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Amz-Content-Sha256")))
	var hasher hash.Hash
	if isHexSHA256(declaredHash) {
		hasher = sha256.New()
	}
	declaredMD5 := strings.TrimSpace(r.Header.Get("Content-MD5"))
	var md5Hasher hash.Hash
	var wantMD5 []byte
	if declaredMD5 != "" {
		wantMD5, err = base64.StdEncoding.DecodeString(declaredMD5)
		if err != nil || len(wantMD5) != md5.Size {
			writeS3Error(w, http.StatusBadRequest, "BadDigest",
				"The Content-MD5 you specified did not match what we received.")
			return
		}
		md5Hasher = md5.New()
	}

	// Create parent directories if needed.
	dir := filepath.Dir(op)
	if err := fileops.Mkdir(g.rootDir, dir, 0o755, true); err != nil {
		if failure := writeFailure(err); failure != nil {
			writeObjectFailure(w, failure)
			return
		}
		g.logger.Error("put object: mkdir failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create directories")
		return
	}

	// Write to temp file, then rename (atomic write).
	tmpFile, err := fileops.CreateTemp(dir, ".seb-tmp-*")
	if err != nil {
		g.logger.Error("put object: create temp failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create temp file")
		return
	}
	defer fileops.ReleaseTemp(tmpFile)
	tmpPath := tmpFile.Name()

	writers := []io.Writer{tmpFile}
	if hasher != nil {
		writers = append(writers, hasher)
	}
	if md5Hasher != nil {
		writers = append(writers, md5Hasher)
	}
	size, err := io.Copy(io.MultiWriter(writers...), tracked)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeS3Error(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
			return
		}
		if errors.As(err, &failure) {
			g.logger.Warn("put object: payload rejected", "bucket", bucket, "key", key, "code", failure.code)
			writeS3Error(w, failure.status, failure.code, failure.message)
			return
		}
		if clientAborted(r, tracked) {
			g.logger.Info("put object: client aborted the upload", "bucket", bucket, "key", key,
				"received", size, "error", err)
			writeObjectFailure(w, errIncompleteBody)
			return
		}
		g.logger.Error("put object: write failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to write object")
		return
	}

	if hasher != nil {
		if actual := hex.EncodeToString(hasher.Sum(nil)); actual != declaredHash {
			os.Remove(tmpPath)
			g.logger.Warn("put object: content sha256 mismatch", "bucket", bucket, "key", key)
			writeS3Error(w, http.StatusBadRequest, "XAmzContentSHA256Mismatch",
				"The provided 'x-amz-content-sha256' header does not match what was computed.")
			return
		}
	}
	if md5Hasher != nil && !bytes.Equal(md5Hasher.Sum(nil), wantMD5) {
		os.Remove(tmpPath)
		g.logger.Warn("put object: content md5 mismatch", "bucket", bucket, "key", key)
		writeS3Error(w, http.StatusBadRequest, "BadDigest",
			"The Content-MD5 you specified did not match what we received.")
		return
	}

	// Rename the temp file over the object; a conditional write is decided here,
	// in the same root-lock hold as the rename.
	info, err := fileops.PublishIf(g.rootDir, tmpPath, op, conditions.precondition())
	if err != nil {
		os.Remove(tmpPath)
		if failure := publishFailure(err, op); failure != nil {
			g.logger.Info("put object: refused", "bucket", bucket, "key", key, "code", failure.code)
			writeObjectFailure(w, failure)
			return
		}
		g.logger.Error("put object: rename failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to finalize object")
		return
	}

	g.logger.Info("object created", "bucket", bucket, "key", key, "size", size)

	// The ETag of the generation this request published, which is what a HEAD
	// reports for it, whatever was written after it.
	w.Header().Set("ETag", etagFor(info))
	body.setChecksumHeader(w)
	w.WriteHeader(http.StatusOK)
}

// handleDeleteObject deletes an object from the bucket.
func (g *Gateway) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}
	// Deleting a missing key is a success, but only in a bucket that exists.
	if !g.bucketExists(bucket) {
		writeObjectFailure(w, errNoSuchBucket)
		return
	}
	if failure := g.deleteObject(bucket, key); failure != nil {
		writeS3Error(w, failure.status, failure.code, failure.message)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// objectFailure is why one object could not be deleted: the status and S3 error
// DeleteObject answers with, of which DeleteObjects reports the error.
type objectFailure struct {
	status        int
	code, message string
}

// deleteObject deletes one object of a bucket, for DeleteObject and
// DeleteObjects alike; nil means the key is gone.
func (g *Gateway) deleteObject(bucket, key string) *objectFailure {
	if !validateKey(key) {
		return &objectFailure{http.StatusBadRequest, "InvalidArgument", "Invalid argument"}
	}
	op, ok := g.objectPath(bucket, key)
	if !ok {
		return &objectFailure{http.StatusBadRequest, "InvalidArgument", "Invalid key"}
	}

	// Only a regular file is an object. Deleting a missing key is a success no-op
	// in S3, and a key that resolves to a directory must not be removed via the
	// object API (os.Remove on a non-empty directory would otherwise return 500).
	// A key that cannot even be looked at may still be there, so that is a failure.
	info, err := os.Stat(op)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENAMETOOLONG) {
			return nil
		}
		g.logger.Error("delete object: stat failed", "bucket", bucket, "key", key, "error", err)
		return &objectFailure{http.StatusInternalServerError, "InternalError", "Failed to delete object"}
	}
	if !info.IsDir() {
		if rmErr := fileops.Remove(g.rootDir, op, false); rmErr != nil && !os.IsNotExist(rmErr) {
			g.logger.Error("delete object failed", "bucket", bucket, "key", key, "error", rmErr)
			return &objectFailure{http.StatusInternalServerError, "InternalError", "Failed to delete object"}
		}
		g.logger.Info("object deleted", "bucket", bucket, "key", key)
	}
	return nil
}

// maxDeleteObjectsKeys is how many keys one DeleteObjects request may name, and
// maxKeyLength how long each may be, in bytes, as in S3. Resolving a key costs
// more the longer it is, so the limits bound the work of one request.
const (
	maxDeleteObjectsKeys = 1000
	maxKeyLength         = 1024
)

// maxDeleteObjectsBody bounds the body of a DeleteObjects request: a thousand
// keys of S3's longest, 1024 bytes each, fit even with every character escaped.
const maxDeleteObjectsBody = 8 << 20

// checkBodyDigests holds a buffered request body (DeleteObjects,
// CompleteMultipartUpload) to the digests its request declares: Content-MD5,
// and a concrete x-amz-content-sha256, which is what a SigV4 signature covers.
// A body that says what to do is as worth protecting as an object's bytes: a
// captured signed request must not be replayable with another body.
func checkBodyDigests(r *http.Request, body []byte) *objectFailure {
	if declared := strings.TrimSpace(r.Header.Get("Content-MD5")); declared != "" {
		want, err := base64.StdEncoding.DecodeString(declared)
		if sum := md5.Sum(body); err != nil || !bytes.Equal(sum[:], want) {
			return &objectFailure{http.StatusBadRequest, "BadDigest",
				"The Content-MD5 you specified did not match what we received."}
		}
	}
	if declared := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Amz-Content-Sha256"))); isHexSHA256(declared) {
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != declared {
			return &objectFailure{http.StatusBadRequest, "XAmzContentSHA256Mismatch",
				"The provided 'x-amz-content-sha256' header does not match what was computed."}
		}
	}
	return nil
}

// handleDeleteObjects deletes many objects of a bucket in one request, each as
// DeleteObject would: a missing key counts as deleted, and a key that cannot be
// deleted is reported in the result without failing the others.
func (g *Gateway) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketName(bucket) {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return
	}
	bp, ok := g.bucketPath(bucket)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return
	}
	if info, err := os.Stat(bp); os.IsNotExist(err) || (err == nil && !info.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return
	} else if err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDeleteObjectsBody))
	if err != nil {
		writeS3Error(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.")
		return
	}
	// The body names what to delete, so it is held to its declared digests just
	// as an object's body is: a captured signed request cannot be replayed with
	// other keys.
	if failure := checkBodyDigests(r, body); failure != nil {
		writeObjectFailure(w, failure)
		return
	}

	var request DeleteObjectsRequest
	if err := xml.Unmarshal(body, &request); err != nil || len(request.Objects) == 0 || len(request.Objects) > maxDeleteObjectsKeys {
		writeS3Error(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.")
		return
	}

	result := DeleteObjectsResult{Xmlns: s3Xmlns}
	for _, object := range request.Objects {
		// Each key of the body is held to the rules the route applies to the key
		// of a URL, so that it is deleted exactly as DeleteObject would be.
		failure := keyFailure(object.Key)
		if failure == nil {
			failure = g.deleteObject(bucket, object.Key)
		}
		if failure != nil {
			result.Errors = append(result.Errors, DeleteObjectError{Key: object.Key, Code: failure.code, Message: failure.message})
		} else if !request.Quiet {
			result.Deleted = append(result.Deleted, DeletedObject{Key: object.Key})
		}
	}
	writeXML(w, http.StatusOK, result)
}
