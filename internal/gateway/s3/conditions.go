package s3

import (
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// --- read preconditions (GET, HEAD, and the source of CopyObject) ---

// condition is the outcome of a request's preconditions.
type condition int

const (
	conditionMet         condition = iota // serve the request
	conditionFailed                       // 412 Precondition Failed
	conditionNotModified                  // 304 Not Modified (GET/HEAD only)
)

// conditionalHeaders names the four validators of a request: the plain HTTP
// ones for GET and HEAD, the x-amz-copy-source- ones for a CopyObject source.
type conditionalHeaders struct {
	ifMatch, ifUnmodifiedSince, ifNoneMatch, ifModifiedSince string
}

var (
	readConditions = conditionalHeaders{"If-Match", "If-Unmodified-Since", "If-None-Match", "If-Modified-Since"}
	copyConditions = conditionalHeaders{
		"X-Amz-Copy-Source-If-Match", "X-Amz-Copy-Source-If-Unmodified-Since",
		"X-Amz-Copy-Source-If-None-Match", "X-Amz-Copy-Source-If-Modified-Since",
	}
)

// evaluateConditions applies the validators of r to the object info describes
// in the order of RFC 9110 section 13.2.2, as S3 does: If-Match, or failing
// that If-Unmodified-Since, decides 412; then If-None-Match, or failing that
// If-Modified-Since, decides 304. An unparsable date is ignored, as the RFC
// requires. Dates compare at the one-second resolution HTTP dates have.
func evaluateConditions(r *http.Request, names conditionalHeaders, info os.FileInfo) condition {
	etag := etagFor(info)
	modified := info.ModTime().Truncate(time.Second)

	if raw := r.Header.Get(names.ifMatch); raw != "" {
		if !etagListMatches(raw, etag) {
			return conditionFailed
		}
	} else if since, ok := parseHTTPDate(r.Header.Get(names.ifUnmodifiedSince)); ok && modified.After(since) {
		return conditionFailed
	}

	if raw := r.Header.Get(names.ifNoneMatch); raw != "" {
		if etagListMatches(raw, etag) {
			return conditionNotModified
		}
	} else if since, ok := parseHTTPDate(r.Header.Get(names.ifModifiedSince)); ok && !modified.After(since) {
		return conditionNotModified
	}
	return conditionMet
}

// parseHTTPDate parses an HTTP date header; ok is false when it is absent or
// unparsable.
func parseHTTPDate(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	t, err := http.ParseTime(raw)
	return t, err == nil
}

// etagListMatches reports whether a comma-separated validator list (or "*")
// names etag. Quotes and a weak prefix are not significant: clients echo the
// ETag they were given, sometimes unquoted, and this server only issues one
// kind of tag.
func etagListMatches(list, etag string) bool {
	want := normalizeETag(etag)
	for _, candidate := range strings.Split(list, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || (candidate != "" && normalizeETag(candidate) == want) {
			return true
		}
	}
	return false
}

func normalizeETag(etag string) string {
	return strings.Trim(strings.TrimPrefix(strings.TrimSpace(etag), "W/"), `"`)
}

// writeNotModified answers 304: the validators of the representation and no
// body, so no Content-Length that would promise one.
func writeNotModified(w http.ResponseWriter, info os.FileInfo) {
	h := w.Header()
	h.Del("Content-Type")
	h.Del("Content-Length")
	h.Set("ETag", etagFor(info))
	h.Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusNotModified)
}

// --- write preconditions (PutObject, CompleteMultipartUpload) ---

// writeConditions are the conditional-write headers of a PUT: If-None-Match: *
// creates the object only if the key is free, If-Match replaces it only if it
// is still the generation the client saw.
type writeConditions struct {
	ifNoneMatch bool
	ifMatch     string
}

// parseWriteConditions reads the conditional-write headers. S3 accepts only *
// in If-None-Match on a write; any other value is refused as unsupported.
func parseWriteConditions(r *http.Request) (writeConditions, *objectFailure) {
	var c writeConditions
	if raw := strings.TrimSpace(r.Header.Get("If-None-Match")); raw != "" {
		if raw != "*" {
			return c, &objectFailure{http.StatusNotImplemented, "NotImplemented",
				"If-None-Match on a write supports only the value *."}
		}
		c.ifNoneMatch = true
	}
	c.ifMatch = strings.TrimSpace(r.Header.Get("If-Match"))
	return c, nil
}

func (c writeConditions) empty() bool { return !c.ifNoneMatch && c.ifMatch == "" }

// check decides the write against the destination as it is now. It is run
// once before the body is read, to refuse early, and once more under the
// root lock at publication, where the answer is final. An unexpected stat
// error is returned as is.
func (c writeConditions) check(current os.FileInfo, statErr error) error {
	if statErr != nil && !readMissing(statErr) {
		return statErr
	}
	exists := statErr == nil && current.Mode().IsRegular()
	if c.ifNoneMatch && exists {
		return errPreconditionFailed
	}
	if c.ifMatch != "" {
		if !exists {
			return errNoSuchKey
		}
		if !etagListMatches(c.ifMatch, etagFor(current)) {
			return errPreconditionFailed
		}
	}
	return nil
}

// precondition returns check for fileops.PublishIf, or nil when the write is
// unconditional.
func (c writeConditions) precondition() func(os.FileInfo, error) error {
	if c.empty() {
		return nil
	}
	return c.check
}

// --- ranges ---

// rangeOutcome is what a GET's Range header asks of an object of a given size.
type rangeOutcome int

const (
	rangeNone          rangeOutcome = iota // no Range: the whole object
	rangeServe                             // a satisfiable range: 206
	rangeIgnore                            // malformed: ignored, the whole object
	rangeUnsatisfiable                     // 416 InvalidRange
)

// classifyRange decides a Range header the way net/http's ServeContent will
// parse it, so that the cases it would answer with a text/plain 416 are
// answered here instead: an unsatisfiable range with S3's XML InvalidRange, and
// a malformed one (which RFC 9110 lets a server ignore) with the whole object.
func classifyRange(header string, size int64) rangeOutcome {
	if header == "" {
		return rangeNone
	}
	const unit = "bytes="
	if !strings.HasPrefix(header, unit) {
		return rangeIgnore
	}
	satisfiable, named := false, false
	for _, spec := range strings.Split(header[len(unit):], ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		named = true
		first, last, ok := strings.Cut(spec, "-")
		if !ok {
			return rangeIgnore
		}
		first, last = strings.TrimSpace(first), strings.TrimSpace(last)
		if first == "" {
			// A suffix: the last N bytes. Any valid suffix overlaps a
			// non-empty object; "-0" selects nothing.
			n, err := strconv.ParseInt(last, 10, 64)
			if last == "" || last[0] == '-' || err != nil || n < 0 {
				return rangeIgnore
			}
			if n > 0 && size > 0 {
				satisfiable = true
			}
			continue
		}
		start, err := strconv.ParseInt(first, 10, 64)
		if err != nil || start < 0 {
			return rangeIgnore
		}
		if last != "" {
			end, err := strconv.ParseInt(last, 10, 64)
			if err != nil || start > end {
				return rangeIgnore
			}
		}
		if start < size {
			satisfiable = true
		}
	}
	switch {
	case !named:
		return rangeIgnore
	case satisfiable:
		return rangeServe
	case size == 0:
		// ServeContent serves an empty object whole rather than 416, since some
		// clients send a Range with every request; keep that.
		return rangeIgnore
	}
	return rangeUnsatisfiable
}

// ifRangeHolds reports whether an If-Range validator still names the object,
// so a Range applies; without If-Range it always does. It mirrors net/http,
// which serves the whole object when the validator is stale.
func ifRangeHolds(r *http.Request, info os.FileInfo) bool {
	raw := strings.TrimSpace(r.Header.Get("If-Range"))
	if raw == "" {
		return true
	}
	if strings.HasPrefix(raw, `"`) || strings.HasPrefix(raw, "W/") {
		// If-Range requires a strong match, and a weak tag never is one.
		return !strings.HasPrefix(raw, "W/") && raw == etagFor(info)
	}
	t, ok := parseHTTPDate(raw)
	return ok && info.ModTime().Truncate(time.Second).Equal(t)
}

// --- content types ---

// safeContentTypes is the allowlist of extensions served with their own media
// type. Content-Type is not stored, so it is derived from the name, and only
// for types a browser renders inertly: an uploaded page, SVG, XML or script
// stays application/octet-stream, so a link to an object can never run code
// in the origin it is served from.
var safeContentTypes = map[string]string{
	".apk":  "application/vnd.android.package-archive",
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
	".ico":  "image/x-icon",
	".json": "application/json",
	".txt":  "text/plain; charset=utf-8",
	".pdf":  "application/pdf",
	".zip":  "application/zip",
}

// contentTypeFor returns the media type served for an object key.
func contentTypeFor(key string) string {
	if t, ok := safeContentTypes[strings.ToLower(path.Ext(key))]; ok {
		return t
	}
	return "application/octet-stream"
}
