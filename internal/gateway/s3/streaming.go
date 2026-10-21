package s3

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// The body of a PutObject or UploadPart request comes in one of the shapes that
// x-amz-content-sha256 names:
//
//   - a plain body (UNSIGNED-PAYLOAD, a concrete SHA-256, or no header);
//   - STREAMING-AWS4-HMAC-SHA256-PAYLOAD: aws-chunked frames, each signed with a
//     signature chained from the request's own (minio-go and mc over HTTP, the
//     AWS Java SDK v1);
//   - STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER: the same, ending in signed
//     trailing headers;
//   - STREAMING-UNSIGNED-PAYLOAD-TRAILER: unsigned aws-chunked frames ending in
//     trailing headers (current AWS SDKs and the AWS CLI over HTTPS).
//
// A flexible checksum (x-amz-checksum-*) is verified over the decoded bytes,
// whether it arrives as a header or, as these SDKs send it, as a trailer.
const (
	streamingSignedPayload          = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingSignedPayloadTrailer   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	streamingUnsignedPayloadTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"

	chunkSignatureAlgorithm   = "AWS4-HMAC-SHA256-PAYLOAD"
	trailerSignatureAlgorithm = "AWS4-HMAC-SHA256-TRAILER"
	trailerSignatureHeader    = "x-amz-trailer-signature"
	emptySHA256               = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// chunkLineLimit bounds a chunk header or trailer line, and maxTrailerLines the
// trailer section, so framing cannot make the decoder buffer without bound.
const (
	chunkLineLimit  = 4096
	maxTrailerLines = 32
)

// streamingBody reports whether r carries an aws-chunked or streaming payload.
// Only PutObject and UploadPart decode one; every other request refuses it.
func streamingBody(r *http.Request) bool {
	for _, value := range r.Header.Values("Content-Encoding") {
		for _, encoding := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(encoding), "aws-chunked") {
				return true
			}
		}
	}
	for _, value := range r.Header.Values("X-Amz-Content-Sha256") {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(value)), "STREAMING-") {
			return true
		}
	}
	return false
}

// writeStreamingNotImplemented refuses an aws-chunked body sent to a request
// other than PutObject and UploadPart.
func writeStreamingNotImplemented(w http.ResponseWriter) {
	writeS3Error(w, http.StatusNotImplemented, "NotImplemented",
		"aws-chunked and streaming payloads are supported only by PutObject and UploadPart.")
}

// Error lets a payload check fail a body read with the response it calls for.
func (f *objectFailure) Error() string { return f.code + ": " + f.message }

var (
	errStreamingVariant = &objectFailure{http.StatusNotImplemented, "NotImplemented",
		"This aws-chunked or streaming payload variant is not supported; use STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER], STREAMING-UNSIGNED-PAYLOAD-TRAILER, or an unencoded body."}
	errChunkSignature = &objectFailure{http.StatusForbidden, "SignatureDoesNotMatch",
		"The request signature we calculated does not match the signature you provided."}
	errChunkEncoding = &objectFailure{http.StatusBadRequest, "InvalidRequest",
		"The request body is not valid aws-chunked encoding."}
	errChunkTruncated = &objectFailure{http.StatusBadRequest, "IncompleteBody",
		"The request body ended before its aws-chunked encoding was complete."}
	errDecodedLength = &objectFailure{http.StatusBadRequest, "IncompleteBody",
		"The decoded request body does not match x-amz-decoded-content-length."}
	errMalformedTrailer = &objectFailure{http.StatusBadRequest, "MalformedTrailerError",
		"The request contained trailing data that was not well-formed or did not conform to our published schema."}
)

// checksumAlgorithms are the flexible checksums verified over a body, keyed by
// the header (or trailer) that carries their base64 value.
var checksumAlgorithms = map[string]func() hash.Hash{
	"x-amz-checksum-crc32":     func() hash.Hash { return crc32.NewIEEE() },
	"x-amz-checksum-crc32c":    func() hash.Hash { return crc32.New(castagnoliTable) },
	"x-amz-checksum-crc64nvme": func() hash.Hash { return crc64.New(nvmeTable) },
	"x-amz-checksum-sha1":      sha1.New,
	"x-amz-checksum-sha256":    sha256.New,
}

// checksumParameters are headers of the x-amz-checksum- family that describe a
// checksum rather than carry one.
var checksumParameters = map[string]bool{
	"x-amz-checksum-algorithm": true,
	"x-amz-checksum-type":      true,
	"x-amz-checksum-mode":      true,
}

var (
	castagnoliTable = crc32.MakeTable(crc32.Castagnoli)
	// nvmeTable is CRC-64/NVME, in the reversed form hash/crc64 expects.
	nvmeTable = crc64.MakeTable(0x9a6c9329ac4bc9b5)
)

// checksum is the flexible checksum a request declared for its body.
type checksum struct {
	name     string // header or trailer name, e.g. x-amz-checksum-crc32
	hash     hash.Hash
	want     []byte // declared digest; for a trailer, known only at the end
	trailing bool
}

// decode parses a base64 checksum value of the size its algorithm produces.
func (c *checksum) decode(value string) ([]byte, bool) {
	want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	return want, err == nil && len(want) == c.hash.Size()
}

// payload is the body of a PutObject or UploadPart request as the handler
// stores it: decoded when it is aws-chunked, and checked against what the
// request declared about it. A failed check is returned from Read in place of
// io.EOF, as an *objectFailure, so a handler that streams the body to a scratch
// file discards it exactly as it would after any other read error. Nothing is
// buffered beyond one framing line.
type payload struct {
	body   io.ReadCloser
	src    io.Reader    // body, or chunks
	chunks *chunkReader // nil for a plain body
	length int64        // x-amz-decoded-content-length, or -1
	n      int64        // decoded bytes read so far
	sum    *checksum    // nil when no flexible checksum was declared
	err    error
}

// newPayload prepares the body of r for PutObject or UploadPart. Before any of
// it is read, it refuses an encoding or checksum the gateway cannot verify.
func (g *Gateway) newPayload(r *http.Request) (*payload, *objectFailure) {
	p := &payload{body: r.Body, src: r.Body, length: -1}

	mode := strings.TrimSpace(r.Header.Get("X-Amz-Content-Sha256"))
	trailing := false
	switch mode {
	case streamingSignedPayload, streamingSignedPayloadTrailer:
		trailing = mode == streamingSignedPayloadTrailer
		p.chunks = &chunkReader{signed: true, trailing: trailing}
		if g.config.AccessKey != "" || g.config.SecretKey != "" {
			// The request was authenticated by its header signature, which seeds
			// the chain; a presigned URL carries no seed for the chunks.
			signer, ok := streamingSigner(r, g.config.SecretKey)
			if !ok {
				return nil, &objectFailure{http.StatusBadRequest, "InvalidRequest",
					"A signed streaming payload requires an Authorization header signature."}
			}
			p.chunks.signer = signer
		}
	case streamingUnsignedPayloadTrailer:
		trailing = true
		p.chunks = &chunkReader{trailing: true}
	default:
		if streamingBody(r) {
			return nil, errStreamingVariant
		}
	}

	if p.chunks != nil {
		p.chunks.src = bufio.NewReaderSize(r.Body, chunkLineLimit)
		p.src = p.chunks
		if raw := r.Header.Get("X-Amz-Decoded-Content-Length"); raw != "" {
			n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err != nil || n < 0 {
				return nil, &objectFailure{http.StatusBadRequest, "InvalidArgument",
					"x-amz-decoded-content-length must be a non-negative integer."}
			}
			if g.config.MaxUploadBytes > 0 && n > g.config.MaxUploadBytes {
				return nil, &objectFailure{http.StatusRequestEntityTooLarge, "EntityTooLarge",
					"Your proposed upload exceeds the maximum allowed size"}
			}
			p.length = n
			// minio-go sends an empty object as an empty body, without even the
			// last chunk. Accept that only when the zero length cannot have been
			// altered: a replayed signed request must not truncate an object.
			p.chunks.emptyOK = n == 0 && (p.chunks.signer == nil ||
				containsHeader(splitSignedHeaders(parseAuthHeader(r.Header.Get("Authorization"))["SignedHeaders"]), "x-amz-decoded-content-length"))
		}
	}

	sum, failure := declaredChecksum(r, trailing)
	if failure != nil {
		return nil, failure
	}
	p.sum = sum
	if sum != nil && sum.trailing {
		p.chunks.declared = sum.name
	}
	return p, nil
}

// declaredChecksum returns the one flexible checksum r declares, in a header or
// (when the payload has trailers) named by x-amz-trailer.
func declaredChecksum(r *http.Request, trailing bool) (*checksum, *objectFailure) {
	var names []string
	var sum *checksum
	for key, values := range r.Header {
		name := strings.ToLower(key)
		if !strings.HasPrefix(name, "x-amz-checksum-") || checksumParameters[name] {
			continue
		}
		newHash, ok := checksumAlgorithms[name]
		if !ok {
			return nil, &objectFailure{http.StatusBadRequest, "InvalidRequest",
				"The checksum algorithm of " + name + " is not supported."}
		}
		sum = &checksum{name: name, hash: newHash()}
		want, ok := sum.decode(strings.Join(values, ","))
		if !ok {
			return nil, &objectFailure{http.StatusBadRequest, "InvalidRequest",
				"Value for " + name + " header is invalid."}
		}
		sum.want = want
		names = append(names, name)
	}
	for _, value := range r.Header.Values("X-Amz-Trailer") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.ToLower(strings.TrimSpace(name)); name == "" {
				continue
			}
			if !trailing {
				return nil, &objectFailure{http.StatusBadRequest, "InvalidRequest",
					"x-amz-trailer requires a STREAMING-*-TRAILER payload."}
			}
			newHash, ok := checksumAlgorithms[name]
			if !ok {
				return nil, &objectFailure{http.StatusBadRequest, "InvalidRequest",
					"The trailing header " + name + " is not supported."}
			}
			sum = &checksum{name: name, hash: newHash(), trailing: true}
			names = append(names, name)
		}
	}
	if len(names) > 1 {
		return nil, &objectFailure{http.StatusBadRequest, "InvalidRequest",
			"Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed."}
	}
	return sum, nil
}

// Read returns decoded bytes. Once the body is exhausted it checks the decoded
// length and checksum, and only then reports io.EOF.
func (p *payload) Read(b []byte) (int, error) {
	if p.err != nil {
		return 0, p.err
	}
	n, err := p.src.Read(b)
	p.n += int64(n)
	if p.length >= 0 && p.n > p.length {
		p.err = errDecodedLength
		return 0, p.err
	}
	if p.sum != nil {
		p.sum.hash.Write(b[:n])
	}
	if err == io.EOF {
		err = p.finish()
	}
	if err != nil {
		p.err = err
	}
	return n, err
}

// finish verifies a completely read body and returns io.EOF when it is intact.
func (p *payload) finish() error {
	if p.length >= 0 && p.n != p.length {
		return errDecodedLength
	}
	if p.sum == nil {
		return io.EOF
	}
	if p.sum.trailing {
		value, ok := p.chunks.trailers[p.sum.name]
		if !ok {
			return errMalformedTrailer
		}
		want, ok := p.sum.decode(value)
		if !ok {
			return &objectFailure{http.StatusBadRequest, "InvalidRequest",
				"Value for " + p.sum.name + " trailing header is invalid."}
		}
		p.sum.want = want
	}
	if !bytes.Equal(p.sum.hash.Sum(nil), p.sum.want) {
		return &objectFailure{http.StatusBadRequest, "BadDigest",
			"The " + p.sum.name + " you specified did not match the calculated checksum."}
	}
	return io.EOF
}

// Close closes the request body.
func (p *payload) Close() error { return p.body.Close() }

// setChecksumHeader echoes a verified flexible checksum on the response, as S3
// does for PutObject and UploadPart.
func (p *payload) setChecksumHeader(w http.ResponseWriter) {
	if p.sum != nil && p.sum.want != nil {
		w.Header().Set(p.sum.name, base64.StdEncoding.EncodeToString(p.sum.want))
	}
}

// chunkReader decodes an aws-chunked body. Each chunk is
//
//	hex-size [";chunk-signature=" signature] CRLF data CRLF
//
// and a chunk of size zero ends the data; trailing headers and a blank line
// follow it. Chunk data is passed on as it arrives. A chunk's signature is
// checked when its data is complete, before the next chunk is opened, and the
// last chunk and the trailers before io.EOF is returned.
type chunkReader struct {
	src      *bufio.Reader
	signed   bool         // chunk headers carry a chunk-signature
	signer   *chunkSigner // verifies the signatures; nil when auth is disabled
	trailing bool         // trailing headers may follow the last chunk
	declared string       // the trailer x-amz-trailer announced, if any
	emptyOK  bool         // an empty body stands for an empty payload

	started  bool   // a chunk header has been read
	left     int64  // data bytes left in the open chunk
	open     bool   // a chunk's data is being read
	sig      string // signature declared for the open chunk
	trailers map[string]string
	err      error
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.left == 0 {
		if err := c.next(); err != nil {
			c.err = err
			return 0, err
		}
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.src.Read(p)
	c.left -= int64(n)
	if c.signer != nil {
		c.signer.hash.Write(p[:n])
	}
	if err != nil {
		c.err = truncation(err)
		return n, c.err
	}
	return n, nil
}

// next closes the chunk just read and opens the following one. After the last
// chunk it reads the trailers and returns io.EOF.
func (c *chunkReader) next() error {
	if c.open {
		var crlf [2]byte
		if _, err := io.ReadFull(c.src, crlf[:]); err != nil {
			return truncation(err)
		}
		if crlf != [2]byte{'\r', '\n'} {
			return errChunkEncoding
		}
		if c.signer != nil && !c.signer.verifyChunk(c.sig) {
			return errChunkSignature
		}
		c.open = false
	}

	line, err := c.src.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return errChunkEncoding
		}
		if !c.started && len(line) == 0 && errors.Is(err, io.EOF) && c.emptyOK {
			c.trailers = map[string]string{}
			return io.EOF
		}
		return truncation(err)
	}
	c.started = true
	size, ext, _ := strings.Cut(strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), ";")
	if len(size) == 0 || len(size) > 16 || strings.TrimLeft(size, "0123456789abcdefABCDEF") != "" {
		return errChunkEncoding
	}
	n, err := strconv.ParseUint(size, 16, 63)
	if err != nil {
		return errChunkEncoding
	}
	if c.signed {
		name, sig, _ := strings.Cut(ext, "=")
		if name != "chunk-signature" || !isHexSHA256(sig) {
			return errChunkSignature
		}
		c.sig = sig
	}
	if n == 0 {
		if c.signer != nil && !c.signer.verifyChunk(c.sig) {
			return errChunkSignature
		}
		return c.readTrailers()
	}
	c.left = int64(n)
	c.open = true
	return nil
}

// readTrailers reads what follows the last chunk up to the end of the body:
// trailing headers, the trailer signature of a signed payload, and blank lines.
// Clients differ in their line endings and in how many blank lines they put
// around the signature, so those are tolerated; content is not.
func (c *chunkReader) readTrailers() error {
	c.trailers = make(map[string]string)
	var canonical strings.Builder
	signed := false
	for i := 0; ; i++ {
		if i == maxTrailerLines {
			return errMalformedTrailer
		}
		line, err := c.src.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			if errors.Is(err, bufio.ErrBufferFull) {
				return errMalformedTrailer
			}
			return truncation(err)
		}
		if text := strings.TrimSpace(string(line)); text != "" {
			name, value, ok := strings.Cut(text, ":")
			name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
			switch {
			case !ok || name == "" || signed:
				return errMalformedTrailer
			case name == trailerSignatureHeader:
				if !c.signed || !c.trailing {
					return errMalformedTrailer
				}
				if !isHexSHA256(value) || (c.signer != nil && !c.signer.verifyTrailer(canonical.String(), value)) {
					return errChunkSignature
				}
				signed = true
			case name != c.declared:
				return errMalformedTrailer
			default:
				if _, dup := c.trailers[name]; dup {
					return errMalformedTrailer
				}
				c.trailers[name] = value
				canonical.WriteString(name + ":" + value + "\n")
			}
		}
		if err != nil {
			break
		}
	}
	if c.signed && c.trailing && !signed {
		return errMalformedTrailer
	}
	return io.EOF
}

// truncation maps the end of the request body inside the framing to
// IncompleteBody; other read errors pass through.
func truncation(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errChunkTruncated
	}
	return err
}

// chunkSigner verifies the signature chain of a signed streaming payload. Each
// chunk is signed over the previous signature and the SHA-256 of its data, and
// the trailers over the last chunk's signature and their canonical form, so
// chunks cannot be altered, dropped, reordered, or appended.
type chunkSigner struct {
	key     []byte
	amzDate string
	scope   string
	prev    string    // seed signature, then the last verified one
	hash    hash.Hash // SHA-256 of the open chunk's data
}

// streamingSigner seeds a chunk signature chain from r's Authorization header,
// which authenticate has already verified.
func streamingSigner(r *http.Request, secretKey string) (*chunkSigner, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, sigV4Algorithm) {
		return nil, false
	}
	params := parseAuthHeader(auth)
	cred, ok := parseCredential(params["Credential"])
	seed, amzDate := params["Signature"], r.Header.Get("X-Amz-Date")
	if !ok || seed == "" || amzDate == "" {
		return nil, false
	}
	return &chunkSigner{
		key:     deriveSigningKey(secretKey, cred.date, cred.region, cred.service),
		amzDate: amzDate,
		scope:   cred.scope,
		prev:    seed,
		hash:    sha256.New(),
	}, true
}

// verifyChunk checks the signature of the chunk whose data was just hashed.
func (s *chunkSigner) verifyChunk(sig string) bool {
	return s.verify(sig, chunkSignatureAlgorithm, emptySHA256+"\n"+hex.EncodeToString(s.hash.Sum(nil)))
}

// verifyTrailer checks the trailer signature over the canonical trailers, each
// "name:value\n".
func (s *chunkSigner) verifyTrailer(canonical, sig string) bool {
	return s.verify(sig, trailerSignatureAlgorithm, sha256Hex(canonical))
}

func (s *chunkSigner) verify(sig, algorithm, digest string) bool {
	stringToSign := algorithm + "\n" + s.amzDate + "\n" + s.scope + "\n" + s.prev + "\n" + digest
	want := hex.EncodeToString(hmacSHA256(s.key, []byte(stringToSign)))
	s.hash.Reset()
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return false
	}
	s.prev = sig
	return true
}
