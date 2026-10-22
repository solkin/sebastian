package s3

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSigV4_KnownAnswer reproduces the AWS-published Signature Version 4 example
// (GET examplebucket/test.txt with a Range header). Matching the documented
// signature validates our canonicalization independently of our own signer.
func TestSigV4_KnownAnswer(t *testing.T) {
	const (
		accessKey = "AKIAIOSFODNN7EXAMPLE"
		secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		wantSig   = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	)

	// The example carries a fixed 2013 date; pin the clock so the skew check in
	// verifyHeaderV4 accepts it.
	restore := nowUTC
	nowUTC = func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }
	defer func() { nowUTC = restore }()

	req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Host = "examplebucket.s3.amazonaws.com"
	req.Header.Set("Range", "bytes=0-9")
	req.Header.Set("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	req.Header.Set("x-amz-date", "20130524T000000Z")
	req.Header.Set("Authorization", sigV4Algorithm+
		" Credential="+accessKey+"/20130524/us-east-1/s3/aws4_request"+
		", SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"+
		", Signature="+wantSig)

	if !verifyHeaderV4(req, accessKey, secretKey) {
		t.Fatal("verifyHeaderV4 rejected the AWS documented example — canonicalization is wrong")
	}
	if verifyHeaderV4(req, accessKey, "wrong-secret") {
		t.Fatal("verifyHeaderV4 accepted a request signed with the wrong secret")
	}
}

// TestCanonicalHeaders_ContentLength verifies that a signed content-length header
// is reconstructed from r.ContentLength (which net/http hoists out of r.Header),
// so SDKs that sign content-length still canonicalize correctly.
func TestCanonicalHeaders_ContentLength(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "https://b.example.com/key", strings.NewReader("12345"))
	req.Host = "b.example.com"
	if req.Header.Get("Content-Length") != "" {
		t.Fatal("precondition: net/http should not expose Content-Length via Header")
	}

	got := canonicalHeaders(req, []string{"content-length", "host"})
	want := "content-length:5\nhost:b.example.com\n"
	if got != want {
		t.Fatalf("canonicalHeaders content-length:\n got %q\nwant %q", got, want)
	}
}

// --- Signing helpers shared by the auth tests ---

// signV4Header signs req in place with a valid SigV4 Authorization header over
// host;x-amz-content-sha256;x-amz-date. req.Host must already be set. It signs
// with the current time so the signature falls within the enforced skew window,
// and reuses the production signer, so a passing TestSigV4_KnownAnswer anchors
// correctness.
func signV4Header(req *http.Request, accessKey, secretKey string) {
	signV4HeaderScoped(req, accessKey, secretKey, "")
}

// signV4HeaderScoped is signV4Header with the credential scope dated scopeDate
// (yyyymmdd) instead of today, for the tests that must be refused for it.
func signV4HeaderScoped(req *http.Request, accessKey, secretKey, scopeDate string) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	if scopeDate != "" {
		date = scopeDate
	}
	scope := date + "/us-east-1/s3/aws4_request"

	req.Header.Set("X-Amz-Date", amzDate)
	if req.Header.Get("X-Amz-Content-Sha256") == "" {
		req.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	}
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signed)

	cred := credential{accessKey: accessKey, date: date, region: "us-east-1", service: "s3", scope: scope}
	sig := computeSignature(req, secretKey, cred, amzDate, signed,
		canonicalQueryString(req.URL.Query(), ""), req.Header.Get("X-Amz-Content-Sha256"))

	req.Header.Set("Authorization", sigV4Algorithm+
		" Credential="+accessKey+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+
		", Signature="+sig)
}

// presignV4 returns a presigned request path ("path?query") with a valid SigV4
// query signature over the host header, valid for expires seconds. It signs with
// the current time so the request falls within its enforced validity window.
func presignV4(method, rawPath, host, accessKey, secretKey string, expires int) string {
	return presignV4Scoped(method, rawPath, host, accessKey, secretKey, expires, "")
}

// presignV4Scoped is presignV4 with the credential scope dated scopeDate
// (yyyymmdd) instead of today.
func presignV4Scoped(method, rawPath, host, accessKey, secretKey string, expires int, scopeDate string) string {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	if scopeDate != "" {
		date = scopeDate
	}
	scope := date + "/us-east-1/s3/aws4_request"

	u, _ := url.Parse(rawPath)
	q := u.Query()
	q.Set("X-Amz-Algorithm", sigV4Algorithm)
	q.Set("X-Amz-Credential", accessKey+"/"+scope)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", strconv.Itoa(expires))
	q.Set("X-Amz-SignedHeaders", "host")

	req := httptest.NewRequest(method, rawPath, nil)
	req.Host = host

	cred := credential{accessKey: accessKey, date: date, region: "us-east-1", service: "s3", scope: scope}
	sig := computeSignature(req, secretKey, cred, amzDate, []string{"host"},
		canonicalQueryString(q, "X-Amz-Signature"), unsignedPayload)
	q.Set("X-Amz-Signature", sig)

	return u.Path + "?" + q.Encode()
}

// TestAuth_PresignedExpiresBounds refuses a presigned URL that claims a
// validity outside 1 second to 7 days, as S3 does: a URL signed with a huge
// X-Amz-Expires would otherwise be a credential that never expires.
func TestAuth_PresignedExpiresBounds(t *testing.T) {
	g, root := testGateway(t, Config{AccessKey: "admin", SecretKey: "secret"})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	for expires, want := range map[int]int{
		1:       http.StatusNotFound, // authenticated; the object is missing
		604800:  http.StatusNotFound,
		604801:  http.StatusForbidden,
		0:       http.StatusForbidden,
		-1:      http.StatusForbidden,
		1 << 30: http.StatusForbidden,
	} {
		path := presignV4(http.MethodGet, "/bucket/file.txt", "example.com", "admin", "secret", expires)
		if w := serveRequest(g, http.MethodGet, path, nil, map[string]string{"Host": "example.com"}); w.Code != want {
			t.Fatalf("X-Amz-Expires=%d: status %d, want %d", expires, w.Code, want)
		}
	}
}

// TestAuth_ScopeDateMustMatchRequestDate refuses a signature whose credential
// scope is dated another day than X-Amz-Date, in both signature forms. The key
// is derived from the scope date, so a key leaked for one day would otherwise
// sign fresh requests on any day.
func TestAuth_ScopeDateMustMatchRequestDate(t *testing.T) {
	g, root := testGateway(t, Config{AccessKey: "admin", SecretKey: "secret"})
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0o755); err != nil {
		t.Fatal(err)
	}
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("20060102")

	for scope, want := range map[string]int{"": http.StatusOK, yesterday: http.StatusForbidden} {
		req := httptest.NewRequest(http.MethodGet, "/bucket", nil)
		req.Host = "example.com"
		signV4HeaderScoped(req, "admin", "secret", scope)
		w := httptest.NewRecorder()
		g.route(w, req)
		if w.Code != want {
			t.Fatalf("header form, scope %q: status %d, want %d", scope, w.Code, want)
		}

		path := presignV4Scoped(http.MethodGet, "/bucket", "example.com", "admin", "secret", 900, scope)
		if w := serveRequest(g, http.MethodGet, path, nil, map[string]string{"Host": "example.com"}); w.Code != want {
			t.Fatalf("presigned, scope %q: status %d, want %d", scope, w.Code, want)
		}
	}
}
