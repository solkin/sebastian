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
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/solkin/sebastian/internal/gateway"
)

// maxListWalkEntries bounds how many objects/prefixes a single ListObjects walk
// will materialize, so a bucket with a pathological number of files cannot
// exhaust memory or stall the server. A truncated walk is logged.
const maxListWalkEntries = 100000

// errWalkLimit aborts the bucket walk once maxListWalkEntries is reached.
var errWalkLimit = errors.New("list walk limit reached")

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

	info, err := os.Stat(bp)
	if err == nil && info.IsDir() {
		w.Header().Set("Location", "/"+bucket)
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := os.Mkdir(bp, 0o755); err != nil {
		g.logger.Error("create bucket failed", "bucket", bucket, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create bucket")
		return
	}

	g.logger.Info("bucket created", "bucket", bucket)
	w.Header().Set("Location", "/"+bucket)
	w.WriteHeader(http.StatusOK)
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

	if err := os.Remove(bp); err != nil {
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

// collectObjects walks a bucket directory and collects all matching objects and
// common prefixes, sorted lexicographically. It does not read file contents and
// does not paginate — pagination is applied separately by paginate.
func (g *Gateway) collectObjects(bp, prefix, delimiter string) ([]ObjectInfo, []string, error) {
	var objects []ObjectInfo
	commonPrefixes := make(map[string]bool)

	err := filepath.Walk(bp, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			// Skip an unreadable entry but log it: silently dropping it would make
			// objects beneath it vanish from the listing with no signal.
			g.logger.Warn("list objects: skipping unreadable entry", "path", path, "error", err)
			return nil
		}
		if path == bp {
			return nil
		}

		// Stop the walk once we have collected the cap; better to truncate (and log)
		// than to hold an unbounded result set in memory.
		if len(objects)+len(commonPrefixes) >= maxListWalkEntries {
			return errWalkLimit
		}

		relPath, _ := filepath.Rel(bp, path)
		key := filepath.ToSlash(relPath)

		// A backup can be an entire directory during WebDAV COPY/MOVE. Prune
		// scratch directories before walking children or collecting prefixes.
		if gateway.IsScratchFile(fi.Name()) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if fi.IsDir() {
			return nil
		}

		// Walk reports Lstat metadata for symlinks, while GET and HEAD follow a
		// safe in-root link. Resolve only link entries so LIST reports the same
		// size/mtime/ETag as those operations, and omit links that escape rootDir.
		if fi.Mode()&os.ModeSymlink != 0 {
			if !gateway.PathResolvesWithin(bp, path) {
				g.logger.Warn("list objects: skipping symlink outside bucket", "path", path)
				return nil
			}
			rootRel, relErr := filepath.Rel(g.rootDir, path)
			if relErr != nil {
				return nil
			}
			if _, _, safeErr := gateway.SafePath(g.rootDir, filepath.ToSlash(rootRel)); safeErr != nil {
				g.logger.Warn("list objects: skipping unsafe symlink", "path", path, "error", safeErr)
				return nil
			}
			resolvedInfo, statErr := os.Stat(path)
			if statErr != nil || resolvedInfo.IsDir() {
				return nil
			}
			fi = resolvedInfo
		}

		if prefix != "" && !strings.HasPrefix(key, prefix) {
			return nil
		}

		if delimiter != "" {
			rest := key
			if prefix != "" {
				rest = key[len(prefix):]
			}
			if idx := strings.Index(rest, delimiter); idx >= 0 {
				commonPrefixes[prefix+rest[:idx+len(delimiter)]] = true
				return nil
			}
		}

		objects = append(objects, ObjectInfo{
			Key:          key,
			LastModified: fi.ModTime().UTC().Format(s3TimeFormat),
			ETag:         etagFor(fi),
			Size:         fi.Size(),
			StorageClass: "STANDARD",
		})

		return nil
	})
	if err != nil && !errors.Is(err, errWalkLimit) {
		return nil, nil, err
	}
	if errors.Is(err, errWalkLimit) {
		g.logger.Warn("list objects: result truncated at limit", "limit", maxListWalkEntries)
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Key < objects[j].Key
	})

	cpList := make([]string, 0, len(commonPrefixes))
	for cp := range commonPrefixes {
		cpList = append(cpList, cp)
	}
	sort.Strings(cpList)

	return objects, cpList, nil
}

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

	objects, cpList, err := g.collectObjects(bp, prefix, delimiter)
	if err != nil {
		g.logger.Error("list objects walk failed", "bucket", bucket, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	pageObjects, pagePrefixes, isTruncated, nextToken := paginate(objects, cpList, marker, maxKeys)

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

	objects, cpList, err := g.collectObjects(bp, prefix, delimiter)
	if err != nil {
		g.logger.Error("list objects walk failed", "bucket", bucket, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	// A continuation token, when present, takes precedence over start-after.
	skipAfter := startAfter
	if contToken != "" {
		skipAfter = contToken
	}

	pageObjects, pagePrefixes, isTruncated, nextToken := paginate(objects, cpList, skipAfter, maxKeys)

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

// handleHeadObject returns metadata for an object.
func (g *Gateway) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}

	op, ok := g.objectPath(bucket, key)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid key")
		return
	}

	info, err := os.Stat(op)
	if os.IsNotExist(err) || (err == nil && info.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}
	if err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", etagFor(info))
	w.WriteHeader(http.StatusOK)
}

// handleGetObject serves an object's content.
func (g *Gateway) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}

	op, ok := g.objectPath(bucket, key)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid key")
		return
	}

	info, err := os.Stat(op)
	if os.IsNotExist(err) || (err == nil && info.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}
	if err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	f, err := os.Open(op)
	if err != nil {
		g.logger.Error("get object: open failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", etagFor(info))

	g.logger.Debug("get object", "bucket", bucket, "key", key, "size", info.Size())
	http.ServeContent(w, r, filepath.Base(op), info.ModTime(), f)
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

	// Cap the upload size when configured, translating an overflow into 413.
	if g.config.MaxUploadBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, g.config.MaxUploadBytes)
	}

	// When the client declares a concrete payload SHA-256 (the value the SigV4
	// signature is computed over), verify the streamed body against it and reject a
	// mismatch. This closes the integrity gap where a captured signed request could
	// be replayed with a swapped body. UNSIGNED-PAYLOAD and aws-chunked streaming
	// markers carry no verifiable digest, so they are not checked.
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		g.logger.Error("put object: mkdir failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create directories")
		return
	}

	// Write to temp file, then rename (atomic write).
	tmpFile, err := os.CreateTemp(dir, ".seb-tmp-*")
	if err != nil {
		g.logger.Error("put object: create temp failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create temp file")
		return
	}
	tmpPath := tmpFile.Name()

	writers := []io.Writer{tmpFile}
	if hasher != nil {
		writers = append(writers, hasher)
	}
	if md5Hasher != nil {
		writers = append(writers, md5Hasher)
	}
	size, err := io.Copy(io.MultiWriter(writers...), r.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeS3Error(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
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

	// Rename temp file to final path.
	if err := os.Rename(tmpPath, op); err != nil {
		os.Remove(tmpPath)
		g.logger.Error("put object: rename failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to finalize object")
		return
	}

	info, err := os.Stat(op)
	if err != nil {
		g.logger.Error("put object: stat failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to finalize object")
		return
	}

	g.logger.Info("object created", "bucket", bucket, "key", key, "size", size)

	w.Header().Set("ETag", etagFor(info))
	w.WriteHeader(http.StatusOK)
}

// handleDeleteObject deletes an object from the bucket.
func (g *Gateway) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}

	op, ok := g.objectPath(bucket, key)
	if !ok {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid key")
		return
	}

	// Only a regular file is an object. Deleting a missing key is a success no-op
	// in S3, and a key that resolves to a directory must not be removed via the
	// object API (os.Remove on a non-empty directory would otherwise return 500).
	if info, err := os.Stat(op); err == nil && !info.IsDir() {
		if rmErr := os.Remove(op); rmErr != nil && !os.IsNotExist(rmErr) {
			g.logger.Error("delete object failed", "bucket", bucket, "key", key, "error", rmErr)
			writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to delete object")
			return
		}
		g.logger.Info("object deleted", "bucket", bucket, "key", key)
	}

	w.WriteHeader(http.StatusNoContent)
}
