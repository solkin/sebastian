package s3

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
func (g *Gateway) bucketPath(bucket string) string {
	return filepath.Join(g.rootDir, bucket)
}

// objectPath returns the absolute path for an object within a bucket.
func (g *Gateway) objectPath(bucket, key string) string {
	return filepath.Join(g.rootDir, bucket, filepath.FromSlash(key))
}

// validateBucketName checks that a bucket name is safe.
func validateBucketName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	return true
}

// validateKey checks that an object key is safe (no path traversal).
func validateKey(key string) bool {
	if key == "" {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(key))
	if strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") || cleaned == ".." {
		return false
	}
	return true
}

// isUnderDir checks that resolved path is within the parent directory.
func isUnderDir(parent, child string) bool {
	absParent, _ := filepath.Abs(parent)
	absChild, _ := filepath.Abs(child)
	return strings.HasPrefix(absChild, absParent+string(filepath.Separator)) || absChild == absParent
}

// hashFile computes SHA256 hex digest of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
		if !entry.IsDir() {
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
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
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

	bp := g.bucketPath(bucket)
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

	bp := g.bucketPath(bucket)
	if !isUnderDir(g.rootDir, bp) {
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

	bp := g.bucketPath(bucket)
	if !isUnderDir(g.rootDir, bp) {
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
	bp := g.bucketPath(bucket)
	info, err := os.Stat(bp)
	if os.IsNotExist(err) || (err == nil && !info.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return
	}
	result := LocationConstraint{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
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
	bp := g.bucketPath(bucket)
	info, err := os.Stat(bp)
	if os.IsNotExist(err) || (err == nil && !info.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return
	}
	result := VersioningConfiguration{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
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
	bp := g.bucketPath(bucket)
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

// collectObjects walks a bucket directory and collects objects and common prefixes.
func (g *Gateway) collectObjects(bp, prefix, delimiter string, maxKeys int) ([]ObjectInfo, []CommonPrefix, bool, error) {
	var objects []ObjectInfo
	commonPrefixes := make(map[string]bool)

	err := filepath.Walk(bp, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if path == bp {
			return nil
		}

		relPath, _ := filepath.Rel(bp, path)
		key := filepath.ToSlash(relPath)

		if fi.IsDir() {
			return nil
		}

		if prefix != "" && !strings.HasPrefix(key, prefix) {
			return nil
		}

		if delimiter != "" {
			rest := key
			if prefix != "" {
				rest = key[len(prefix):]
			}
			idx := strings.Index(rest, delimiter)
			if idx >= 0 {
				cp := prefix + rest[:idx+len(delimiter)]
				commonPrefixes[cp] = true
				return nil
			}
		}

		hash, hashErr := hashFile(path)
		etag := ""
		if hashErr == nil {
			etag = hash
		}

		objects = append(objects, ObjectInfo{
			Key:          key,
			LastModified: fi.ModTime().UTC().Format(s3TimeFormat),
			ETag:         etag,
			Size:         fi.Size(),
			StorageClass: "STANDARD",
		})

		return nil
	})
	if err != nil {
		return nil, nil, false, err
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Key < objects[j].Key
	})

	var cpList []CommonPrefix
	cpKeys := make([]string, 0, len(commonPrefixes))
	for cp := range commonPrefixes {
		cpKeys = append(cpKeys, cp)
	}
	sort.Strings(cpKeys)
	for _, cp := range cpKeys {
		cpList = append(cpList, CommonPrefix{Prefix: cp})
	}

	isTruncated := false
	totalItems := len(objects) + len(cpList)
	if totalItems > maxKeys {
		isTruncated = true
		if len(objects) > maxKeys {
			objects = objects[:maxKeys]
		}
	}

	return objects, cpList, isTruncated, nil
}

// handleListObjects dispatches to V1 or V2 based on the list-type query parameter.
func (g *Gateway) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketName(bucket) {
		writeS3Error(w, http.StatusBadRequest, "InvalidBucketName", "Invalid bucket name")
		return
	}

	bp := g.bucketPath(bucket)
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
	maxKeys := parseMaxKeys(r)

	objects, cpList, isTruncated, err := g.collectObjects(bp, prefix, delimiter, maxKeys)
	if err != nil {
		g.logger.Error("list objects walk failed", "bucket", bucket, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	if marker != "" {
		filtered := objects[:0]
		for _, obj := range objects {
			if obj.Key > marker {
				filtered = append(filtered, obj)
			}
		}
		objects = filtered
	}

	nextMarker := ""
	if isTruncated && len(objects) > 0 {
		nextMarker = objects[len(objects)-1].Key
	}

	result := ListBucketResultV1{
		Xmlns:          "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:           bucket,
		Prefix:         prefix,
		Marker:         marker,
		NextMarker:     nextMarker,
		Delimiter:      delimiter,
		MaxKeys:        maxKeys,
		IsTruncated:    isTruncated,
		Contents:       objects,
		CommonPrefixes: cpList,
	}

	g.logger.Debug("list objects v1", "bucket", bucket, "prefix", prefix, "count", len(objects))
	writeXML(w, http.StatusOK, result)
}

// handleListObjectsV2 returns a V2 ListBucketResult (with KeyCount, ContinuationToken).
func (g *Gateway) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket, bp string) {
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	startAfter := r.URL.Query().Get("start-after")
	contToken := r.URL.Query().Get("continuation-token")
	maxKeys := parseMaxKeys(r)

	objects, cpList, isTruncated, err := g.collectObjects(bp, prefix, delimiter, maxKeys)
	if err != nil {
		g.logger.Error("list objects walk failed", "bucket", bucket, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Internal error")
		return
	}

	skipAfter := startAfter
	if contToken != "" {
		skipAfter = contToken
	}
	if skipAfter != "" {
		filtered := objects[:0]
		for _, obj := range objects {
			if obj.Key > skipAfter {
				filtered = append(filtered, obj)
			}
		}
		objects = filtered
	}

	nextContToken := ""
	if isTruncated && len(objects) > 0 {
		nextContToken = objects[len(objects)-1].Key
	}

	result := ListBucketResultV2{
		Xmlns:                 "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:                  bucket,
		Prefix:                prefix,
		Delimiter:             delimiter,
		MaxKeys:               maxKeys,
		IsTruncated:           isTruncated,
		KeyCount:              len(objects),
		Contents:              objects,
		CommonPrefixes:        cpList,
		StartAfter:            startAfter,
		ContinuationToken:     contToken,
		NextContinuationToken: nextContToken,
	}

	g.logger.Debug("list objects v2", "bucket", bucket, "prefix", prefix, "count", len(objects))
	writeXML(w, http.StatusOK, result)
}

// parseMaxKeys extracts max-keys from query, defaulting to 1000.
func parseMaxKeys(r *http.Request) int {
	maxKeys := 1000
	if s := r.URL.Query().Get("max-keys"); s != "" {
		fmt.Sscanf(s, "%d", &maxKeys)
		if maxKeys <= 0 {
			maxKeys = 1000
		}
		if maxKeys > 10000 {
			maxKeys = 10000
		}
	}
	return maxKeys
}

// handleHeadObject returns metadata for an object.
func (g *Gateway) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}

	op := g.objectPath(bucket, key)
	if !isUnderDir(g.bucketPath(bucket), op) {
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

	hash, _ := hashFile(op)

	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", "application/octet-stream")
	if hash != "" {
		w.Header().Set("ETag", fmt.Sprintf("\"%s\"", hash))
	}
	w.WriteHeader(http.StatusOK)
}

// handleGetObject serves an object's content.
func (g *Gateway) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}

	op := g.objectPath(bucket, key)
	if !isUnderDir(g.bucketPath(bucket), op) {
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

	hash, _ := hashFile(op)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	if hash != "" {
		w.Header().Set("ETag", fmt.Sprintf("\"%s\"", hash))
	}

	g.logger.Debug("get object", "bucket", bucket, "key", key, "size", info.Size())
	http.ServeFile(w, r, op)
}

// handlePutObject writes an object to the bucket.
func (g *Gateway) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}

	op := g.objectPath(bucket, key)
	if !isUnderDir(g.bucketPath(bucket), op) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid key")
		return
	}

	bp := g.bucketPath(bucket)
	bInfo, err := os.Stat(bp)
	if os.IsNotExist(err) || (err == nil && !bInfo.IsDir()) {
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return
	}

	dir := filepath.Dir(op)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		g.logger.Error("put object: mkdir failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create directories")
		return
	}

	tmpFile, err := os.CreateTemp(dir, ".seb-tmp-*")
	if err != nil {
		g.logger.Error("put object: create temp failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to create temp file")
		return
	}
	tmpPath := tmpFile.Name()

	h := sha256.New()
	tee := io.TeeReader(r.Body, h)

	size, err := io.Copy(tmpFile, tee)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		g.logger.Error("put object: write failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to write object")
		return
	}

	if err := os.Rename(tmpPath, op); err != nil {
		os.Remove(tmpPath)
		g.logger.Error("put object: rename failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to finalize object")
		return
	}

	etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(h.Sum(nil)))

	g.logger.Info("object created", "bucket", bucket, "key", key, "size", size)

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

// handleDeleteObject deletes an object from the bucket.
func (g *Gateway) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketName(bucket) || !validateKey(key) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid argument")
		return
	}

	op := g.objectPath(bucket, key)
	if !isUnderDir(g.bucketPath(bucket), op) {
		writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "Invalid key")
		return
	}

	if err := os.Remove(op); err != nil && !os.IsNotExist(err) {
		g.logger.Error("delete object failed", "bucket", bucket, "key", key, "error", err)
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "Failed to delete object")
		return
	}

	g.logger.Info("object deleted", "bucket", bucket, "key", key)
	w.WriteHeader(http.StatusNoContent)
}
