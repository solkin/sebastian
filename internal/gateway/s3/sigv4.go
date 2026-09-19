package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file implements real AWS Signature Version 4 verification for the S3
// gateway, for both the Authorization header form and the presigned query-string
// form. Legacy SigV2 is intentionally not supported and is rejected by the caller.
//
// Limitation: the request body is not re-hashed here. The canonical request uses
// the client-supplied x-amz-content-sha256 value (or UNSIGNED-PAYLOAD) verbatim,
// as the signing spec requires. This authenticates the requester without buffering
// the body; payload integrity (when the client declares a concrete digest) is
// enforced separately in handlePutObject. aws-chunked / streaming-signed bodies
// are not decoded.

const (
	sigV4Algorithm   = "AWS4-HMAC-SHA256"
	unsignedPayload  = "UNSIGNED-PAYLOAD"
	amzDateFormat    = "20060102T150405Z"
	presignSkewGrace = 15 * time.Minute
)

// nowUTC returns the current time in UTC. It is a variable so tests can pin the
// clock when validating fixed-date example signatures.
var nowUTC = func() time.Time { return time.Now().UTC() }

// credential holds the parsed components of an AWS credential scope.
type credential struct {
	accessKey string
	date      string // yyyymmdd
	region    string
	service   string
	scope     string // date/region/service/aws4_request
}

// parseCredential parses "AKID/yyyymmdd/region/service/aws4_request".
func parseCredential(cred string) (credential, bool) {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return credential{}, false
	}
	for _, p := range parts {
		if p == "" {
			return credential{}, false
		}
	}
	return credential{
		accessKey: parts[0],
		date:      parts[1],
		region:    parts[2],
		service:   parts[3],
		scope:     strings.Join(parts[1:], "/"),
	}, true
}

// verifyHeaderV4 verifies an Authorization-header SigV4 signature.
func verifyHeaderV4(r *http.Request, accessKey, secretKey string) bool {
	params := parseAuthHeader(r.Header.Get("Authorization"))
	cred, ok := parseCredential(params["Credential"])
	if !ok || cred.accessKey != accessKey {
		return false
	}

	signedHeadersRaw := params["SignedHeaders"]
	providedSig := params["Signature"]
	amzDate := r.Header.Get("X-Amz-Date")
	if signedHeadersRaw == "" || providedSig == "" || amzDate == "" {
		return false
	}

	// A header-form signature carries no explicit expiry, so without a clock-skew
	// window a captured Authorization header would replay forever. Bound it.
	if !withinSkew(amzDate) {
		return false
	}

	signedHeaders := splitSignedHeaders(signedHeadersRaw)
	// host must be signed, otherwise the signature is not bound to the target host
	// (and thus, with virtual-hosted addressing, not bound to a bucket).
	if !containsHeader(signedHeaders, "host") {
		return false
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = unsignedPayload
	}

	expected := computeSignature(r, secretKey, cred, amzDate,
		signedHeaders,
		canonicalQueryString(r.URL.Query(), ""), payloadHash)

	return hmac.Equal([]byte(expected), []byte(providedSig))
}

// verifyPresignedV4 verifies a presigned (query-string) SigV4 signature.
func verifyPresignedV4(r *http.Request, accessKey, secretKey string) bool {
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") != sigV4Algorithm {
		return false
	}
	cred, ok := parseCredential(q.Get("X-Amz-Credential"))
	if !ok || cred.accessKey != accessKey {
		return false
	}

	providedSig := q.Get("X-Amz-Signature")
	signedHeadersRaw := q.Get("X-Amz-SignedHeaders")
	amzDate := q.Get("X-Amz-Date")
	if providedSig == "" || signedHeadersRaw == "" || amzDate == "" {
		return false
	}

	if !presignedNotExpired(amzDate, q.Get("X-Amz-Expires")) {
		return false
	}

	signedHeaders := splitSignedHeaders(signedHeadersRaw)
	// host must be signed so the presigned URL is bound to the target host/bucket.
	if !containsHeader(signedHeaders, "host") {
		return false
	}

	expected := computeSignature(r, secretKey, cred, amzDate,
		signedHeaders,
		canonicalQueryString(q, "X-Amz-Signature"), unsignedPayload)

	return hmac.Equal([]byte(expected), []byte(providedSig))
}

// computeSignature builds the canonical request and string-to-sign, derives the
// signing key from secretKey, and returns the hex-encoded expected signature.
func computeSignature(r *http.Request, secretKey string, cred credential, amzDate string, signedHeaders []string, canonicalQuery, payloadHash string) string {
	canonicalURI := r.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders(r, signedHeaders),
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		cred.scope,
		sha256Hex(canonicalRequest),
	}, "\n")

	key := deriveSigningKey(secretKey, cred.date, cred.region, cred.service)
	return hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))
}

// parseAuthHeader parses the comma-separated key=value parameters of a SigV4
// Authorization header into a map (Credential, SignedHeaders, Signature).
func parseAuthHeader(h string) map[string]string {
	out := make(map[string]string, 3)
	h = strings.TrimSpace(strings.TrimPrefix(h, sigV4Algorithm))
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out
}

// splitSignedHeaders splits a ";"-separated signed-headers list, lowercases and
// sorts it (canonical order required by the signing spec).
func splitSignedHeaders(raw string) []string {
	hs := strings.Split(raw, ";")
	for i := range hs {
		hs[i] = strings.ToLower(strings.TrimSpace(hs[i]))
	}
	sort.Strings(hs)
	return hs
}

// canonicalHeaders builds the canonical headers block. Each signed header is
// emitted as "name:trimmed-value\n" in the (already sorted) order given.
func canonicalHeaders(r *http.Request, signedHeaders []string) string {
	var b strings.Builder
	for _, h := range signedHeaders {
		b.WriteString(h)
		b.WriteByte(':')
		switch {
		case h == "host":
			b.WriteString(trimAll(r.Host))
		case h == "content-length" && r.ContentLength >= 0:
			// net/http hoists Content-Length out of r.Header into r.ContentLength,
			// so r.Header.Values would be empty and break a signature that signed
			// content-length. Reconstruct it from the parsed value.
			b.WriteString(strconv.FormatInt(r.ContentLength, 10))
		default:
			b.WriteString(trimAll(strings.Join(r.Header.Values(http.CanonicalHeaderKey(h)), ",")))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// canonicalQueryString builds the canonical query string: parameters (optionally
// excluding one key) URI-encoded per RFC 3986 and sorted by key then value.
func canonicalQueryString(query url.Values, exclude string) string {
	keys := make([]string, 0, len(query))
	for k := range query {
		if k == exclude {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), query[k]...)
		sort.Strings(vals)
		ek := awsURIEncode(k, true)
		for _, v := range vals {
			parts = append(parts, ek+"="+awsURIEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// awsURIEncode percent-encodes s per RFC 3986 as required by SigV4. Unreserved
// characters are passed through; '/' is preserved only when encodeSlash is false
// (used for the canonical URI path).
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// trimAll trims leading/trailing whitespace and collapses internal runs of
// whitespace to a single space, per the SigV4 "Trimall" rule.
func trimAll(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// presignedNotExpired reports whether a presigned request is currently within its
// validity window (X-Amz-Date .. X-Amz-Date + X-Amz-Expires), allowing a small
// clock-skew grace for not-yet-valid requests.
func presignedNotExpired(amzDate, expiresStr string) bool {
	t, err := time.Parse(amzDateFormat, amzDate)
	if err != nil {
		return false
	}
	expires, err := strconv.Atoi(expiresStr)
	if err != nil || expires <= 0 {
		return false
	}
	now := nowUTC()
	if now.Before(t.Add(-presignSkewGrace)) {
		return false
	}
	return !now.After(t.Add(time.Duration(expires) * time.Second))
}

// withinSkew reports whether amzDate (an X-Amz-Date stamp) is within
// presignSkewGrace of the current time, in either direction. This bounds replay
// of header-form signatures, which carry no explicit expiry of their own.
func withinSkew(amzDate string) bool {
	t, err := time.Parse(amzDateFormat, amzDate)
	if err != nil {
		return false
	}
	delta := nowUTC().Sub(t)
	if delta < 0 {
		delta = -delta
	}
	return delta <= presignSkewGrace
}

// containsHeader reports whether name appears in the (lowercased) signed-headers list.
func containsHeader(signed []string, name string) bool {
	for _, h := range signed {
		if h == name {
			return true
		}
	}
	return false
}

// deriveSigningKey computes the SigV4 signing key from the secret access key.
func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// sha256Hex returns the hex-encoded SHA256 of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hmacSHA256 computes HMAC-SHA256 of data with key.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
