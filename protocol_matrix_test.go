package sebastian_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solkin/sebastian/internal/gateway"
	"github.com/solkin/sebastian/internal/gateway/httpui"
	"github.com/solkin/sebastian/internal/gateway/s3"
	"github.com/solkin/sebastian/internal/gateway/sftp"
	"github.com/solkin/sebastian/internal/gateway/webdav"
	uploadstore "github.com/solkin/sebastian/internal/multipart"
	"golang.org/x/crypto/ssh"
)

// A real network client exercises the gateway lifecycle and wire formats, not
// package-private handlers. Every writer must be visible to every reader.
func TestProtocolMatrix(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bucket"), 0755); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := uploadstore.New(root, uploadstore.Limits{}, logger)
	if err != nil {
		t.Fatal(err)
	}
	reserve := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		return addr
	}
	s3Addr, davAddr, httpAddr, sshAddr := reserve(), reserve(), reserve(), reserve()
	s3gw := s3.New(root, s3.Config{ListenAddr: s3Addr, Multipart: store}, logger)
	davgw := webdav.New(root, webdav.Config{ListenAddr: davAddr}, logger)
	httpgw := httpui.New(root, httpui.Config{ListenAddr: httpAddr}, logger)
	sftpgw, err := sftp.New(root, sftp.Config{ListenAddr: sshAddr, Username: "user", Password: "pass", HostKeyPath: filepath.Join(t.TempDir(), "host_key")}, logger)
	if err != nil {
		t.Fatal(err)
	}
	gateways := []gateway.Gateway{s3gw, davgw, httpgw, sftpgw}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, len(gateways))
	for _, gw := range gateways {
		go func() { done <- gw.Start(ctx) }()
	}
	t.Cleanup(func() {
		cancel()
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, gw := range gateways {
			if err := gw.Stop(shutdown); err != nil {
				t.Errorf("stop %s: %v", gw.Name(), err)
			}
		}
		for range gateways {
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-shutdown.Done():
				t.Error("gateways did not stop")
				return
			}
		}
	})
	for _, addr := range []string{s3Addr, davAddr, httpAddr, sshAddr} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("gateway %s did not start", addr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	request := func(method, url, body, contentType string) (int, []byte, http.Header) {
		t.Helper()
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, data, resp.Header
	}
	checkStatus := func(status, want int, body []byte) {
		t.Helper()
		if status != want {
			t.Fatalf("status=%d want=%d body=%s", status, want, body)
		}
	}
	sc := newMatrixSFTP(t, sshAddr)
	objectURL := "/bucket/shared.txt"
	readers := map[string]func() string{
		"disk": func() string {
			data, err := os.ReadFile(filepath.Join(root, "bucket", "shared.txt"))
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		},
		"s3": func() string {
			status, data, _ := request("GET", "http://"+s3Addr+objectURL, "", "")
			checkStatus(status, 200, data)
			return string(data)
		},
		"webdav": func() string {
			status, data, _ := request("GET", "http://"+davAddr+objectURL, "", "")
			checkStatus(status, 200, data)
			return string(data)
		},
		"http": func() string {
			status, data, _ := request("GET", "http://"+httpAddr+"/_api/dl"+objectURL, "", "")
			checkStatus(status, 200, data)
			return string(data)
		},
		"sftp": func() string { return sc.read(objectURL) },
	}
	verify := func(want string) {
		t.Helper()
		for name, read := range readers {
			if got := read(); got != want {
				t.Fatalf("%s read=%q want=%q", name, got, want)
			}
		}
	}
	writers := []struct {
		name  string
		write func(string)
	}{
		{"disk", func(body string) {
			if err := os.WriteFile(filepath.Join(root, "bucket", "shared.txt"), []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"s3", func(body string) {
			status, data, _ := request("PUT", "http://"+s3Addr+objectURL, body, "")
			checkStatus(status, 200, data)
		}},
		{"webdav", func(body string) {
			status, data, _ := request("PUT", "http://"+davAddr+objectURL, body, "")
			checkStatus(status, 204, data)
		}},
		{"http", func(body string) {
			var buf bytes.Buffer
			writer := multipart.NewWriter(&buf)
			if err := writer.WriteField("path", "bucket"); err != nil {
				t.Fatal(err)
			}
			file, err := writer.CreateFormFile("files", "shared.txt")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(file, body); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			status, data, _ := request("POST", "http://"+httpAddr+"/_api/upload", buf.String(), writer.FormDataContentType())
			checkStatus(status, 200, data)
		}},
		{"sftp", func(body string) { sc.write(objectURL, body) }},
	}
	for _, writer := range writers {
		body := "written through " + writer.name
		writer.write(body)
		verify(body)
	}
	// Staging a multipart replacement leaves the previous object readable through
	// every gateway until completion publishes the new contents atomically.
	status, data, _ := request("POST", "http://"+s3Addr+objectURL+"?uploads", "", "")
	checkStatus(status, 200, data)
	var initiated struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(data, &initiated); err != nil || initiated.UploadID == "" {
		t.Fatalf("initiate: %s %v", data, err)
	}
	status, data, headers := request("PUT", "http://"+s3Addr+objectURL+"?partNumber=1&uploadId="+initiated.UploadID, "multipart replacement", "")
	checkStatus(status, 200, data)
	verify("written through sftp")
	body := "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" + headers.Get("ETag") + "</ETag></Part></CompleteMultipartUpload>"
	status, data, _ = request("POST", "http://"+s3Addr+objectURL+"?uploadId="+initiated.UploadID, body, "application/xml")
	checkStatus(status, 200, data)
	verify("multipart replacement")
	// Mutations must also remain visible across protocol boundaries.
	rename := `{"from":"bucket/shared.txt","to":"bucket/renamed.txt"}`
	status, data, _ = request("POST", "http://"+httpAddr+"/_api/rename", rename, "application/json")
	checkStatus(status, 200, data)
	objectURL = "/bucket/renamed.txt"
	if got := sc.read(objectURL); got != "multipart replacement" {
		t.Fatalf("renamed SFTP read: %q", got)
	}
	status, data, _ = request("GET", "http://"+s3Addr+objectURL, "", "")
	checkStatus(status, 200, data)
	if string(data) != "multipart replacement" {
		t.Fatalf("renamed S3 read: %q", data)
	}
	sc.remove(objectURL)
	for _, url := range []string{"http://" + s3Addr + objectURL, "http://" + davAddr + objectURL, "http://" + httpAddr + "/_api/dl" + objectURL} {
		status, data, _ = request("GET", url, "", "")
		checkStatus(status, 404, data)
	}
	if _, err := os.Stat(filepath.Join(root, "bucket", "renamed.txt")); !os.IsNotExist(err) {
		t.Fatalf("file remains after SFTP delete: %v", err)
	}
}

// Minimal SFTP v3 client for the cross-protocol contract. Packet types and status
// codes are intentionally independent of the server's private implementation.
type matrixSFTP struct {
	t      *testing.T
	reader io.Reader
	writer io.Writer
	id     uint32
}

func matrixString(value string) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(out, uint32(len(value)))
	copy(out[4:], value)
	return out
}
func newMatrixSFTP(t *testing.T, addr string) *matrixSFTP {
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "user", Auth: []ssh.AuthMethod{ssh.Password("pass")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	sess, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	c := &matrixSFTP{t: t, reader: out, writer: in}
	typ, payload := c.packet(1, []byte{0, 0, 0, 3})
	if typ != 2 || len(payload) < 4 || binary.BigEndian.Uint32(payload) != 3 {
		t.Fatalf("bad SFTP version: %d %x", typ, payload)
	}
	return c
}
func (c *matrixSFTP) packet(typ byte, payload []byte) (byte, []byte) {
	c.t.Helper()
	packet := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(packet, uint32(len(payload)+1))
	packet[4] = typ
	copy(packet[5:], payload)
	if _, err := c.writer.Write(packet); err != nil {
		c.t.Fatal(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		c.t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(header)
	if size < 1 || size > 1<<20 {
		c.t.Fatalf("bad SFTP packet size: %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(c.reader, data); err != nil {
		c.t.Fatal(err)
	}
	return data[0], data[1:]
}
func (c *matrixSFTP) call(typ byte, payload []byte) (byte, []byte) {
	c.id++
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, c.id)
	reply, body := c.packet(typ, append(prefix, payload...))
	if len(body) < 4 || binary.BigEndian.Uint32(body) != c.id {
		c.t.Fatal("SFTP response ID mismatch")
	}
	return reply, body[4:]
}
func (c *matrixSFTP) status(typ byte, body []byte) {
	c.t.Helper()
	if typ != 101 || len(body) < 4 || binary.BigEndian.Uint32(body) != 0 {
		c.t.Fatalf("SFTP request failed: %d %x", typ, body)
	}
}
func (c *matrixSFTP) open(path string, flags uint32) []byte {
	attrs := make([]byte, 8)
	binary.BigEndian.PutUint32(attrs, flags)
	typ, body := c.call(3, append(matrixString(path), attrs...))
	if typ != 102 || len(body) < 4 || int(binary.BigEndian.Uint32(body)) != len(body)-4 {
		c.t.Fatalf("SFTP open failed: %d %x", typ, body)
	}
	return body
}
func (c *matrixSFTP) write(path, body string) {
	handle := c.open(path, 2|8|16)
	payload := append(append(append([]byte{}, handle...), make([]byte, 8)...), matrixString(body)...)
	c.status(c.call(6, payload))
	c.status(c.call(4, handle))
}
func (c *matrixSFTP) read(path string) string {
	handle := c.open(path, 1)
	offsetAndLength := make([]byte, 12)
	binary.BigEndian.PutUint32(offsetAndLength[8:], 4096)
	typ, body := c.call(5, append(append([]byte{}, handle...), offsetAndLength...))
	if typ != 103 || len(body) < 4 || int(binary.BigEndian.Uint32(body)) != len(body)-4 {
		c.t.Fatalf("SFTP read failed: %d %x", typ, body)
	}
	c.status(c.call(4, handle))
	return string(body[4:])
}
func (c *matrixSFTP) remove(path string) { c.status(c.call(13, matrixString(path))) }
