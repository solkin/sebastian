package s3

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/solkin/sebastian/internal/multipart"
)

const (
	streamAccess = "access"
	streamSecret = "secret"
)

// --- aws-chunked bodies, encoded the way clients produce them ---

// streamOptions describes one aws-chunked request body.
type streamOptions struct {
	mode       string // x-amz-content-sha256 payload marker
	chunk      int    // data bytes per chunk; 0 means 64 KiB
	trailer    string // trailing checksum name; "" sends none
	value      string // trailer value; "" sends the correct checksum
	undeclared bool   // send the trailer without announcing it in x-amz-trailer
	minio      bool   // minio-go trailer layout: LF after the header, extra blank lines
	length     string // x-amz-decoded-content-length; "" is the real length, "-" omits it
}

func (o streamOptions) signed() bool { return o.mode != streamingUnsignedPayloadTrailer }

// streamingPut builds a PUT of data to path as an aws-chunked body, signed for
// streamAccess/streamSecret. It returns the request and the encoded body, which
// a test may tamper with before serving it.
func streamingPut(path string, data []byte, o streamOptions) (*http.Request, []byte) {
	req := httptest.NewRequest(http.MethodPut, path, nil)
	req.Header.Set("X-Amz-Content-Sha256", o.mode)
	req.Header.Set("Content-Encoding", "aws-chunked")
	switch o.length {
	case "":
		req.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(data)))
	case "-":
	default:
		req.Header.Set("X-Amz-Decoded-Content-Length", o.length)
	}
	if o.trailer != "" && !o.undeclared {
		req.Header.Set("X-Amz-Trailer", o.trailer)
	}
	key, amzDate, scope, prev := signStreaming(req, streamAccess, streamSecret)

	chunk := o.chunk
	if chunk == 0 {
		chunk = 64 << 10
	}
	var b bytes.Buffer
	frame := func(piece []byte) {
		if o.signed() {
			prev = testChunkSignature(key, amzDate, scope, prev, piece)
			fmt.Fprintf(&b, "%x;chunk-signature=%s\r\n", len(piece), prev)
		} else {
			fmt.Fprintf(&b, "%x\r\n", len(piece))
		}
		b.Write(piece)
	}
	for off := 0; off < len(data); off += chunk {
		frame(data[off:min(off+chunk, len(data))])
		b.WriteString("\r\n")
	}
	frame(nil)
	if o.trailer == "" {
		b.WriteString("\r\n")
		return req, b.Bytes()
	}

	value := o.value
	if value == "" {
		value = testChecksum(o.trailer, data)
	}
	line := o.trailer + ":" + value
	var signature string
	if o.signed() {
		signature = "x-amz-trailer-signature:" + testTrailerSignature(key, amzDate, scope, prev, line+"\n") + "\r\n"
	}
	if o.minio {
		b.WriteString(line + "\n\r\n" + signature + "\r\n")
	} else {
		b.WriteString(line + "\r\n" + signature + "\r\n")
	}
	return req, b.Bytes()
}

// signStreaming signs req as an SDK starting a streaming upload does, over the
// host, the payload marker, the date, and the decoded length when present. It
// returns what the chunk signatures are chained from.
func signStreaming(req *http.Request, accessKey, secretKey string) (key []byte, amzDate, scope, seed string) {
	now := time.Now().UTC()
	amzDate = now.Format(amzDateFormat)
	date := now.Format("20060102")
	scope = date + "/us-east-1/s3/aws4_request"
	req.Header.Set("X-Amz-Date", amzDate)

	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if req.Header.Get("X-Amz-Decoded-Content-Length") != "" {
		signed = append(signed, "x-amz-decoded-content-length")
	}
	sort.Strings(signed)
	cred := credential{accessKey: accessKey, date: date, region: "us-east-1", service: "s3", scope: scope}
	seed = computeSignature(req, secretKey, cred, amzDate, signed,
		canonicalQueryString(req.URL.Query(), ""), req.Header.Get("X-Amz-Content-Sha256"))
	req.Header.Set("Authorization", sigV4Algorithm+" Credential="+accessKey+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+seed)
	return deriveSigningKey(secretKey, date, "us-east-1", "s3"), amzDate, scope, seed
}

// testChunkSignature and testTrailerSignature follow the AWS streaming SigV4
// specification independently of the decoder under test.
func testChunkSignature(key []byte, amzDate, scope, prev string, data []byte) string {
	sum := sha256.Sum256(data)
	return testHMAC(key, "AWS4-HMAC-SHA256-PAYLOAD\n"+amzDate+"\n"+scope+"\n"+prev+"\n"+
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"+hex.EncodeToString(sum[:]))
}

func testTrailerSignature(key []byte, amzDate, scope, prev, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return testHMAC(key, "AWS4-HMAC-SHA256-TRAILER\n"+amzDate+"\n"+scope+"\n"+prev+"\n"+hex.EncodeToString(sum[:]))
}

func testHMAC(key []byte, data string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// testChecksum returns the base64 flexible checksum name of data.
func testChecksum(name string, data []byte) string {
	var h hash.Hash
	switch name {
	case "x-amz-checksum-crc32":
		h = crc32.NewIEEE()
	case "x-amz-checksum-crc32c":
		h = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "x-amz-checksum-crc64nvme":
		h = crc64.New(crc64.MakeTable(0x9a6c9329ac4bc9b5))
	case "x-amz-checksum-sha1":
		h = sha1.New()
	case "x-amz-checksum-sha256":
		h = sha256.New()
	default:
		panic("unknown checksum " + name)
	}
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// serveBody serves req with body as its payload.
func serveBody(g *Gateway, req *http.Request, body []byte) *httptest.ResponseRecorder {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	g.route(w, req)
	return w
}

func testPayload(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}
	return data
}

// --- a bucket with an object and a staged part to preserve ---

type streamingFixture struct {
	g     *Gateway
	root  string
	store *multipart.Store
	id    string
	etag  string
}

const previousObject = "previous object"

// newStreamingFixture creates bucket/object and an upload of it with part 1
// staged, then turns on authentication when cfg asks for it.
func newStreamingFixture(t *testing.T, cfg Config) *streamingFixture {
	t.Helper()
	g, root, store := multipartGateway(t, Config{MaxUploadBytes: cfg.MaxUploadBytes}, multipart.Limits{MinPartBytes: 1})
	if err := os.WriteFile(filepath.Join(root, "bucket", "object"), []byte(previousObject), 0o600); err != nil {
		t.Fatal(err)
	}
	id := initiateUpload(t, g, "bucket", "object")
	etag := uploadPart(t, g, "bucket", "object", id, 1, []byte("previous part"))
	g.config.AccessKey, g.config.SecretKey = cfg.AccessKey, cfg.SecretKey
	return &streamingFixture{g: g, root: root, store: store, id: id, etag: etag}
}

// targets are the two requests that take an object body: PutObject of
// bucket/object, and UploadPart of part 1 of the fixture's upload.
func (f *streamingFixture) targets() map[string]string {
	return map[string]string{
		"put_object":  "/bucket/object",
		"upload_part": "/bucket/object?partNumber=1&uploadId=" + f.id,
	}
}

// assertPreserved checks that a rejected request changed neither the object
// nor the staged part, and left no scratch file behind.
func (f *streamingFixture) assertPreserved(t *testing.T) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(f.root, "bucket", "object"))
	if err != nil || string(got) != previousObject {
		t.Fatalf("object replaced: %q %v", got, err)
	}
	parts, _, _, err := f.store.ListParts(f.id, 0, 1000)
	if err != nil || len(parts) != 1 || `"`+parts[0].ETag+`"` != f.etag {
		t.Fatalf("staged part replaced: %+v %v", parts, err)
	}
	for _, dir := range []string{
		filepath.Join(f.root, "bucket"),
		filepath.Join(f.root, ".sebastian", "multipart", f.id),
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".seb-tmp-") {
				t.Fatalf("scratch file left behind in %s: %s", dir, e.Name())
			}
		}
	}
}

// stored returns what a successful request to target stored.
func (f *streamingFixture) stored(t *testing.T, target string) ([]byte, string) {
	t.Helper()
	if target == "put_object" {
		got, err := os.ReadFile(filepath.Join(f.root, "bucket", "object"))
		if err != nil {
			t.Fatal(err)
		}
		return got, ""
	}
	parts, _, _, err := f.store.ListParts(f.id, 0, 1000)
	if err != nil || len(parts) != 1 {
		t.Fatalf("staged parts: %+v %v", parts, err)
	}
	return nil, parts[0].ETag
}

func checkStored(t *testing.T, f *streamingFixture, target string, w *httptest.ResponseRecorder, data []byte) {
	t.Helper()
	got, etag := f.stored(t, target)
	if target == "put_object" {
		if !bytes.Equal(got, data) {
			t.Fatalf("stored %d bytes, want %d (equal=%v)", len(got), len(data), bytes.Equal(got, data))
		}
		return
	}
	if want := md5HexOf(data); etag != want || w.Header().Get("ETag") != `"`+want+`"` {
		t.Fatalf("part etag %s (response %s), want %s", etag, w.Header().Get("ETag"), want)
	}
}

// --- tests ---

// TestStreamingSignedPayloadKnownAnswer decodes the AWS-published example of a
// STREAMING-AWS4-HMAC-SHA256-PAYLOAD upload (66560 bytes in 64 KiB chunks) with
// its documented seed and chunk signatures, anchoring the signature chain to the
// specification rather than to our own encoder.
func TestStreamingSignedPayloadKnownAnswer(t *testing.T) {
	const (
		accessKey = "AKIAIOSFODNN7EXAMPLE"
		secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		seed      = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
	)
	chunkSigs := []string{
		"ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
		"0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
		"b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
	}

	restore := nowUTC
	nowUTC = func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }
	defer func() { nowUTC = restore }()

	g, root := testGateway(t, Config{AccessKey: accessKey, SecretKey: secretKey})
	if err := os.Mkdir(filepath.Join(root, "examplebucket"), 0o755); err != nil {
		t.Fatal(err)
	}

	data := bytes.Repeat([]byte("a"), 66560)
	var body bytes.Buffer
	fmt.Fprintf(&body, "10000;chunk-signature=%s\r\n", chunkSigs[0])
	body.Write(data[:65536])
	fmt.Fprintf(&body, "\r\n400;chunk-signature=%s\r\n", chunkSigs[1])
	body.Write(data[65536:])
	fmt.Fprintf(&body, "\r\n0;chunk-signature=%s\r\n\r\n", chunkSigs[2])
	if body.Len() != 66824 {
		t.Fatalf("encoded body is %d bytes, the example's Content-Length is 66824", body.Len())
	}

	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/examplebucket/chunkObject.txt", nil)
		req.Host = "s3.amazonaws.com"
		req.Header.Set("X-Amz-Date", "20130524T000000Z")
		req.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
		req.Header.Set("X-Amz-Content-Sha256", streamingSignedPayload)
		req.Header.Set("Content-Encoding", "aws-chunked")
		req.Header.Set("X-Amz-Decoded-Content-Length", "66560")
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/20130524/us-east-1/s3/aws4_request,"+
			"SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,"+
			"Signature="+seed)
		return req
	}

	object := filepath.Join(root, "examplebucket", "chunkObject.txt")
	tampered := bytes.Clone(body.Bytes())
	tampered[len(tampered)-200] ^= 1 // a data byte of the second chunk
	if w := serveBody(g, request(), tampered); w.Code != http.StatusForbidden || errorCode(t, w) != "SignatureDoesNotMatch" {
		t.Fatalf("tampered example: status %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(object); !os.IsNotExist(err) {
		t.Fatalf("tampered example published an object: %v", err)
	}

	if w := serveBody(g, request(), body.Bytes()); w.Code != http.StatusOK {
		t.Fatalf("documented example: status %d: %s", w.Code, w.Body.String())
	}
	got, err := os.ReadFile(object)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stored %d bytes, %v", len(got), err)
	}
}

// TestFlexibleChecksumKnownAnswers anchors the checksum algorithms to their
// published check values, including the CRC-64/NVME table.
func TestFlexibleChecksumKnownAnswers(t *testing.T) {
	if got := crc64.Checksum([]byte("123456789"), nvmeTable); got != 0xae8b14860a799888 {
		t.Fatalf("CRC-64/NVME check value = %#x", got)
	}
	if got := crc32.Checksum([]byte("123456789"), castagnoliTable); got != 0xe3069283 {
		t.Fatalf("CRC-32C check value = %#x", got)
	}
	// The AWS trailing-checksum example: 66560 bytes of 'a'.
	if got := testChecksum("x-amz-checksum-crc32c", bytes.Repeat([]byte("a"), 66560)); got != "sOO8/Q==" {
		t.Fatalf("crc32c of the AWS example = %s", got)
	}
	for name, newHash := range checksumAlgorithms {
		h := newHash()
		h.Write([]byte("birak"))
		if got, want := base64.StdEncoding.EncodeToString(h.Sum(nil)), testChecksum(name, []byte("birak")); got != want {
			t.Fatalf("%s = %s, want %s", name, got, want)
		}
	}
}

var streamingVariants = []struct {
	name string
	o    streamOptions
}{
	{"signed", streamOptions{mode: streamingSignedPayload}},
	{"signed_trailer", streamOptions{mode: streamingSignedPayloadTrailer, trailer: "x-amz-checksum-crc32c"}},
	{"signed_trailer_minio", streamOptions{mode: streamingSignedPayloadTrailer, trailer: "x-amz-checksum-crc32c", minio: true}},
	{"unsigned_trailer_crc32", streamOptions{mode: streamingUnsignedPayloadTrailer, trailer: "x-amz-checksum-crc32"}},
	{"unsigned_trailer_crc32c_minio", streamOptions{mode: streamingUnsignedPayloadTrailer, trailer: "x-amz-checksum-crc32c", minio: true}},
	{"unsigned_trailer_crc64nvme", streamOptions{mode: streamingUnsignedPayloadTrailer, trailer: "x-amz-checksum-crc64nvme"}},
	{"unsigned_trailer_sha1", streamOptions{mode: streamingUnsignedPayloadTrailer, trailer: "x-amz-checksum-sha1"}},
	{"unsigned_trailer_sha256", streamOptions{mode: streamingUnsignedPayloadTrailer, trailer: "x-amz-checksum-sha256"}},
	{"unsigned_without_trailer", streamOptions{mode: streamingUnsignedPayloadTrailer}},
	{"unsigned_unknown_length", streamOptions{mode: streamingUnsignedPayloadTrailer, trailer: "x-amz-checksum-crc32", length: "-"}},
}

// TestStreamingUploadsStoreDecodedBytes uploads every variant through PutObject
// and UploadPart, with and without authentication, at sizes around the chunk
// boundaries, and reading the body one byte at a time so framing split across
// reads is exercised.
func TestStreamingUploadsStoreDecodedBytes(t *testing.T) {
	sizes := []int{0, 1, 63, 64, 65, 64*3 + 5}
	for _, auth := range []bool{true, false} {
		for _, v := range streamingVariants {
			t.Run(fmt.Sprintf("auth=%v/%s", auth, v.name), func(t *testing.T) {
				cfg := Config{}
				if auth {
					cfg.AccessKey, cfg.SecretKey = streamAccess, streamSecret
				}
				f := newStreamingFixture(t, cfg)
				o := v.o
				o.chunk = 64
				for target, path := range f.targets() {
					for _, size := range sizes {
						data := testPayload(size)
						req, body := streamingPut(path, data, o)
						req.Body = io.NopCloser(iotest.OneByteReader(bytes.NewReader(body)))
						req.ContentLength = int64(len(body))
						w := httptest.NewRecorder()
						f.g.route(w, req)
						if w.Code != http.StatusOK {
							t.Fatalf("%s size %d: status %d: %s", target, size, w.Code, w.Body.String())
						}
						checkStored(t, f, target, w, data)
						if o.trailer != "" {
							if got, want := w.Header().Get(o.trailer), testChecksum(o.trailer, data); got != want {
								t.Fatalf("%s size %d: response %s = %q, want %q", target, size, o.trailer, got, want)
							}
						}
					}
				}
			})
		}
	}
}

// TestStreamingMultipartUploadCompletes uploads every part of an object with a
// streaming body and completes it into the exact bytes.
func TestStreamingMultipartUploadCompletes(t *testing.T) {
	for _, v := range streamingVariants {
		t.Run(v.name, func(t *testing.T) {
			g, root, _ := multipartGateway(t, Config{}, multipart.Limits{})
			id := initiateUpload(t, g, "bucket", "big.apk")
			g.config.AccessKey, g.config.SecretKey = streamAccess, streamSecret

			parts := [][]byte{testPayload(200 << 10), testPayload(70 << 10)}
			var entries []CompletePartEntry
			for i, data := range parts {
				req, body := streamingPut(fmt.Sprintf("/bucket/big.apk?partNumber=%d&uploadId=%s", i+1, id), data, v.o)
				w := serveBody(g, req, body)
				if w.Code != http.StatusOK {
					t.Fatalf("part %d: status %d: %s", i+1, w.Code, w.Body.String())
				}
				entries = append(entries, CompletePartEntry{PartNumber: i + 1, ETag: w.Header().Get("ETag")})
			}

			req := httptest.NewRequest(http.MethodPost, "/bucket/big.apk?uploadId="+id, strings.NewReader(completeBody(entries)))
			signV4Header(req, streamAccess, streamSecret)
			w := httptest.NewRecorder()
			g.route(w, req)
			var result CompleteMultipartUploadResult
			if w.Code != http.StatusOK || xml.Unmarshal(w.Body.Bytes(), &result) != nil || result.ETag != compositeETagOf(parts) {
				t.Fatalf("complete: status %d: %s", w.Code, w.Body.String())
			}
			got, err := os.ReadFile(filepath.Join(root, "bucket", "big.apk"))
			if err != nil || !bytes.Equal(got, bytes.Join(parts, nil)) {
				t.Fatalf("assembled %d bytes, %v", len(got), err)
			}
		})
	}
}

// TestStreamingRejectionsPreserveState sends malformed, forged, and
// inconsistent streaming bodies to PutObject and UploadPart. Each is refused
// with the S3 error a client expects, and neither the existing object nor the
// staged part changes.
func TestStreamingRejectionsPreserveState(t *testing.T) {
	data := testPayload(300)
	signed := streamOptions{mode: streamingSignedPayload, chunk: 100}
	signedTrailer := streamOptions{mode: streamingSignedPayloadTrailer, chunk: 100, trailer: "x-amz-checksum-crc32c"}
	unsigned := streamOptions{mode: streamingUnsignedPayloadTrailer, chunk: 100, trailer: "x-amz-checksum-crc32"}

	with := func(o streamOptions, edit func(*streamOptions)) streamOptions { edit(&o); return o }
	encode := func(o streamOptions) func(string) (*http.Request, []byte) {
		return func(path string) (*http.Request, []byte) { return streamingPut(path, data, o) }
	}
	edited := func(o streamOptions, edit func([]byte) []byte) func(string) (*http.Request, []byte) {
		return func(path string) (*http.Request, []byte) {
			req, body := streamingPut(path, data, o)
			return req, edit(body)
		}
	}
	plain := func(headers map[string]string) func(string) (*http.Request, []byte) {
		return func(path string) (*http.Request, []byte) {
			req := httptest.NewRequest(http.MethodPut, path, nil)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			signV4Header(req, streamAccess, streamSecret)
			return req, data
		}
	}
	// frame returns the offset of the n-th (0-based) chunk header.
	frame := func(body []byte, n int) int {
		off := 0
		for i := 0; i < n; i++ {
			line := bytes.IndexByte(body[off:], '\n')
			size, _, _ := strings.Cut(string(body[off:off+line]), ";")
			length, _ := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
			off += line + 1 + int(length) + 2
		}
		return off
	}
	wrongCRC32 := testChecksum("x-amz-checksum-crc32", []byte("other bytes"))
	wrongCRC32C := testChecksum("x-amz-checksum-crc32c", []byte("other bytes"))

	cases := []struct {
		name   string
		build  func(path string) (*http.Request, []byte)
		status int
		code   string
	}{
		{"bad_chunk_signature", edited(signed, func(b []byte) []byte {
			b[frame(b, 1)-10] ^= 1 // a data byte of the first chunk
			return b
		}), http.StatusForbidden, "SignatureDoesNotMatch"},
		{"bad_last_chunk_signature", edited(signed, func(b []byte) []byte {
			off := frame(b, 3) + len("0;chunk-signature=")
			b[off] = map[bool]byte{true: '1', false: '0'}[b[off] == '0']
			return b
		}), http.StatusForbidden, "SignatureDoesNotMatch"},
		{"dropped_chunk", edited(signed, func(b []byte) []byte {
			return append(b[:frame(b, 1):frame(b, 1)], b[frame(b, 2):]...)
		}), http.StatusForbidden, "SignatureDoesNotMatch"},
		{"missing_chunk_signature", edited(signed, func(b []byte) []byte {
			return bytes.Replace(b, []byte(";chunk-signature="), []byte(";chunk-signaturx="), 1)
		}), http.StatusForbidden, "SignatureDoesNotMatch"},
		{"bad_trailer_signature", edited(signedTrailer, func(b []byte) []byte {
			off := bytes.Index(b, []byte("x-amz-trailer-signature:")) + len("x-amz-trailer-signature:")
			b[off] = map[bool]byte{true: '1', false: '0'}[b[off] == '0']
			return b
		}), http.StatusForbidden, "SignatureDoesNotMatch"},
		{"missing_trailer_signature", edited(signedTrailer, func(b []byte) []byte {
			off := bytes.Index(b, []byte("x-amz-trailer-signature:"))
			return append(b[:off:off], []byte("\r\n")...)
		}), http.StatusBadRequest, "MalformedTrailerError"},
		{"bad_trailer_checksum", encode(with(unsigned, func(o *streamOptions) { o.value = wrongCRC32 })),
			http.StatusBadRequest, "BadDigest"},
		{"bad_signed_trailer_checksum", encode(with(signedTrailer, func(o *streamOptions) { o.value = wrongCRC32C })),
			http.StatusBadRequest, "BadDigest"},
		{"invalid_trailer_checksum", encode(with(unsigned, func(o *streamOptions) { o.value = "not base64!" })),
			http.StatusBadRequest, "InvalidRequest"},
		{"truncated_chunk", edited(signed, func(b []byte) []byte { return b[:frame(b, 1)-50] }),
			http.StatusBadRequest, "IncompleteBody"},
		{"truncated_before_last_chunk", edited(signed, func(b []byte) []byte { return b[:frame(b, 3)] }),
			http.StatusBadRequest, "IncompleteBody"},
		{"truncated_unsigned_chunk", edited(unsigned, func(b []byte) []byte { return b[:frame(b, 2)-1] }),
			http.StatusBadRequest, "IncompleteBody"},
		{"decoded_length_short", encode(with(signed, func(o *streamOptions) { o.length = "301" })),
			http.StatusBadRequest, "IncompleteBody"},
		{"decoded_length_long", encode(with(unsigned, func(o *streamOptions) { o.length = "299" })),
			http.StatusBadRequest, "IncompleteBody"},
		{"invalid_decoded_length", encode(with(signed, func(o *streamOptions) { o.length = "-1" })),
			http.StatusBadRequest, "InvalidArgument"},
		{"missing_trailer", edited(unsigned, func(b []byte) []byte {
			return append(b[:frame(b, 3)+len("0\r\n"):frame(b, 3)+len("0\r\n")], []byte("\r\n")...)
		}), http.StatusBadRequest, "MalformedTrailerError"},
		{"undeclared_trailer", encode(with(unsigned, func(o *streamOptions) { o.undeclared = true })),
			http.StatusBadRequest, "MalformedTrailerError"},
		{"trailer_without_trailer_mode", edited(signed, func(b []byte) []byte {
			return append(b[:len(b)-2:len(b)-2], []byte("x-amz-checksum-crc32:AAAAAA==\r\n\r\n")...)
		}), http.StatusBadRequest, "MalformedTrailerError"},
		{"content_after_trailers", edited(unsigned, func(b []byte) []byte { return append(b, []byte("junk\r\n")...) }),
			http.StatusBadRequest, "MalformedTrailerError"},
		{"malformed_chunk_size", edited(unsigned, func(b []byte) []byte { return append([]byte("zz"), b[2:]...) }),
			http.StatusBadRequest, "InvalidRequest"},
		{"negative_chunk_size", edited(unsigned, func(b []byte) []byte { return append([]byte("-64"), b[2:]...) }),
			http.StatusBadRequest, "InvalidRequest"},
		{"missing_chunk_crlf", edited(unsigned, func(b []byte) []byte {
			copy(b[frame(b, 1)-2:], "XX")
			return b
		}), http.StatusBadRequest, "InvalidRequest"},
		{"oversized_chunk_line", edited(unsigned, func(b []byte) []byte {
			return append([]byte("64;"+strings.Repeat("x", 2*chunkLineLimit)), b[2:]...)
		}), http.StatusBadRequest, "InvalidRequest"},
		{"header_checksum_mismatch", func(path string) (*http.Request, []byte) {
			req, body := streamingPut(path, data, signed)
			req.Header.Set("X-Amz-Checksum-Crc32c", wrongCRC32C)
			return req, body
		}, http.StatusBadRequest, "BadDigest"},
		{"two_checksums", func(path string) (*http.Request, []byte) {
			req, body := streamingPut(path, data, unsigned)
			req.Header.Set("X-Amz-Checksum-Crc32c", testChecksum("x-amz-checksum-crc32c", data))
			return req, body
		}, http.StatusBadRequest, "InvalidRequest"},
		{"unsupported_trailer", encode(with(unsigned, func(o *streamOptions) { o.trailer, o.value = "x-amz-checksum-xxhash64", "AAAAAAAAAAA=" })),
			http.StatusBadRequest, "InvalidRequest"},
		{"x_amz_trailer_without_trailer_mode", func(path string) (*http.Request, []byte) {
			req, body := streamingPut(path, data, signed)
			req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
			return req, body
		}, http.StatusBadRequest, "InvalidRequest"},
		{"unsupported_variant", func(path string) (*http.Request, []byte) {
			req, body := streamingPut(path, data, unsigned)
			req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD")
			signV4Header(req, streamAccess, streamSecret)
			return req, body
		}, http.StatusNotImplemented, "NotImplemented"},
		{"aws_chunked_without_marker", plain(map[string]string{"Content-Encoding": "gzip, aws-chunked"}),
			http.StatusNotImplemented, "NotImplemented"},
		{"plain_checksum_mismatch", plain(map[string]string{"X-Amz-Checksum-Sha256": testChecksum("x-amz-checksum-sha256", []byte("x"))}),
			http.StatusBadRequest, "BadDigest"},
		{"plain_invalid_checksum", plain(map[string]string{"X-Amz-Checksum-Crc32": "AAAA"}),
			http.StatusBadRequest, "InvalidRequest"},
		{"plain_unsupported_checksum", plain(map[string]string{"X-Amz-Checksum-Xxhash3": "AAAAAAAAAAA="}),
			http.StatusBadRequest, "InvalidRequest"},
		{"signed_stream_with_presigned_auth", func(path string) (*http.Request, []byte) {
			req, body := streamingPut(path, data, signed)
			presigned := httptest.NewRequest(http.MethodPut, presignV4(http.MethodPut, path, "example.com", streamAccess, streamSecret, 300), nil)
			presigned.Host = "example.com"
			presigned.Header = req.Header.Clone()
			presigned.Header.Del("Authorization")
			return presigned, body
		}, http.StatusBadRequest, "InvalidRequest"},
		{"empty_body_without_signed_length", func(path string) (*http.Request, []byte) {
			req := httptest.NewRequest(http.MethodPut, path, nil)
			req.Header.Set("X-Amz-Content-Sha256", streamingSignedPayload)
			signStreaming(req, streamAccess, streamSecret)
			req.Header.Set("X-Amz-Decoded-Content-Length", "0") // not covered by the signature
			return req, nil
		}, http.StatusBadRequest, "IncompleteBody"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStreamingFixture(t, Config{AccessKey: streamAccess, SecretKey: streamSecret})
			for target, path := range f.targets() {
				req, body := tc.build(path)
				w := serveBody(f.g, req, body)
				if w.Code != tc.status || errorCode(t, w) != tc.code {
					t.Fatalf("%s: status %d, want %d %s: %s", target, w.Code, tc.status, tc.code, w.Body.String())
				}
				f.assertPreserved(t)
			}
		})
	}
}

// TestStreamingUploadLimitAppliesToDecodedBytes holds max_upload_bytes against
// the decoded payload: framing overhead does not count, a larger payload is
// refused while streaming, and a declared larger payload before any byte is read.
func TestStreamingUploadLimitAppliesToDecodedBytes(t *testing.T) {
	const limit = 1000
	f := newStreamingFixture(t, Config{AccessKey: streamAccess, SecretKey: streamSecret, MaxUploadBytes: limit})
	for target, path := range f.targets() {
		for _, mode := range []string{streamingSignedPayload, streamingUnsignedPayloadTrailer} {
			over := streamOptions{mode: mode, chunk: 100, length: "-"}
			req, body := streamingPut(path, testPayload(limit+1), over)
			if w := serveBody(f.g, req, body); w.Code != http.StatusRequestEntityTooLarge || errorCode(t, w) != "EntityTooLarge" {
				t.Fatalf("%s %s over the limit: status %d: %s", target, mode, w.Code, w.Body.String())
			}
			f.assertPreserved(t)

			declared := streamOptions{mode: mode, chunk: 100}
			req, _ = streamingPut(path, testPayload(limit+1), declared)
			unread := &observedBody{}
			req.Body = unread
			w := httptest.NewRecorder()
			f.g.route(w, req)
			if w.Code != http.StatusRequestEntityTooLarge || unread.reads != 0 {
				t.Fatalf("%s %s declared over the limit: status %d after %d reads", target, mode, w.Code, unread.reads)
			}
			f.assertPreserved(t)
		}
	}
	for target, path := range f.targets() {
		data := testPayload(limit)
		req, body := streamingPut(path, data, streamOptions{mode: streamingSignedPayload, chunk: 100})
		if len(body) <= limit {
			t.Fatal("precondition: the encoded body should exceed the limit")
		}
		w := serveBody(f.g, req, body)
		if w.Code != http.StatusOK {
			t.Fatalf("%s at the limit: status %d: %s", target, w.Code, w.Body.String())
		}
		checkStored(t, f, target, w, data)
	}
}

// TestStreamingEmptyBodyFromMinioGo accepts the empty body minio-go sends for a
// zero-byte object: no chunks at all, with a signed zero decoded length.
func TestStreamingEmptyBodyFromMinioGo(t *testing.T) {
	f := newStreamingFixture(t, Config{AccessKey: streamAccess, SecretKey: streamSecret})
	for target, path := range f.targets() {
		req := httptest.NewRequest(http.MethodPut, path, nil)
		req.Header.Set("X-Amz-Content-Sha256", streamingSignedPayload)
		req.Header.Set("X-Amz-Decoded-Content-Length", "0")
		signStreaming(req, streamAccess, streamSecret)
		w := serveBody(f.g, req, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", target, w.Code, w.Body.String())
		}
		checkStored(t, f, target, w, nil)
	}
}

// TestPlainUploadsVerifyChecksumHeaders verifies a flexible checksum sent as a
// header with an unencoded body, as SDKs do over plain HTTP, and echoes it.
func TestPlainUploadsVerifyChecksumHeaders(t *testing.T) {
	data := testPayload(5000)
	for name := range checksumAlgorithms {
		t.Run(name, func(t *testing.T) {
			f := newStreamingFixture(t, Config{AccessKey: streamAccess, SecretKey: streamSecret})
			for target, path := range f.targets() {
				req := httptest.NewRequest(http.MethodPut, path, nil)
				req.Header.Set(name, testChecksum(name, data))
				req.Header.Set("X-Amz-Sdk-Checksum-Algorithm", strings.ToUpper(strings.TrimPrefix(name, "x-amz-checksum-")))
				req.Header.Set("X-Amz-Checksum-Algorithm", "ignored")
				signV4Header(req, streamAccess, streamSecret)
				w := serveBody(f.g, req, data)
				if w.Code != http.StatusOK {
					t.Fatalf("%s: status %d: %s", target, w.Code, w.Body.String())
				}
				if got := w.Header().Get(name); got != testChecksum(name, data) {
					t.Fatalf("%s: response %s = %q", target, name, got)
				}
				checkStored(t, f, target, w, data)
			}
		})
	}
}

type observedBody struct{ reads int }

func (b *observedBody) Read(p []byte) (int, error) {
	b.reads++
	return 0, io.EOF
}

func (b *observedBody) Close() error { return nil }

// TestStreamingBodiesRejectedOutsideObjectPuts keeps refusing aws-chunked bodies
// for every request but PutObject and UploadPart, before reading them.
func TestStreamingBodiesRejectedOutsideObjectPuts(t *testing.T) {
	headers := []http.Header{
		{"Content-Encoding": {"aws-chunked"}},
		{"Content-Encoding": {"gzip", "aws-chunked"}},
		{"X-Amz-Content-Sha256": {streamingSignedPayload}},
		{"X-Amz-Content-Sha256": {streamingUnsignedPayloadTrailer}},
	}
	f := newStreamingFixture(t, Config{AccessKey: streamAccess, SecretKey: streamSecret})
	requests := []struct{ method, path string }{
		{http.MethodPost, "/bucket/object?uploadId=" + f.id}, // CompleteMultipartUpload
		{http.MethodPost, "/bucket?delete"},                  // DeleteObjects
		{http.MethodPut, "/newbucket"},                       // CreateBucket
		{http.MethodPost, "/bucket/object?uploads"},          // CreateMultipartUpload
	}
	for _, h := range headers {
		for _, rq := range requests {
			body := &observedBody{}
			req := httptest.NewRequest(rq.method, rq.path, body)
			req.Header = h.Clone()
			signV4Header(req, streamAccess, streamSecret)
			w := httptest.NewRecorder()
			f.g.route(w, req)
			if w.Code != http.StatusNotImplemented || errorCode(t, w) != "NotImplemented" || body.reads != 0 {
				t.Fatalf("%s %s %v: status %d after %d reads: %s", rq.method, rq.path, h, w.Code, body.reads, w.Body.String())
			}
		}
	}
	if _, err := os.Stat(filepath.Join(f.root, "newbucket")); !os.IsNotExist(err) {
		t.Fatalf("bucket created: %v", err)
	}
	f.assertPreserved(t)
}

// TestStreamingContentMD5CoversDecodedBytes checks Content-MD5 against the
// decoded bytes of a streaming body, not its framing.
func TestStreamingContentMD5CoversDecodedBytes(t *testing.T) {
	data := testPayload(500)
	f := newStreamingFixture(t, Config{AccessKey: streamAccess, SecretKey: streamSecret})
	for target, path := range f.targets() {
		wrong := md5.Sum([]byte("other bytes"))
		req, body := streamingPut(path, data, streamOptions{mode: streamingSignedPayload, chunk: 128})
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(wrong[:]))
		if w := serveBody(f.g, req, body); w.Code != http.StatusBadRequest || errorCode(t, w) != "BadDigest" {
			t.Fatalf("%s wrong MD5: status %d: %s", target, w.Code, w.Body.String())
		}
		f.assertPreserved(t)
	}
	for target, path := range f.targets() {
		sum := md5.Sum(data)
		req, body := streamingPut(path, data, streamOptions{mode: streamingSignedPayload, chunk: 128})
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
		w := serveBody(f.g, req, body)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", target, w.Code, w.Body.String())
		}
		checkStored(t, f, target, w, data)
	}
}
