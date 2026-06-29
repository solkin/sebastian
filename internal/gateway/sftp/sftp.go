// Package sftp implements an SFTP gateway that exposes rootDir over SSH/SFTP.
// Compatible with OpenSSH sftp, FileZilla, WinSCP, Cyberduck, and other SFTP clients.
package sftp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/solkin/sebastian/internal/gateway"
)

const (
	// maxSFTPConnections bounds concurrently served connections so a flood of TCP
	// connections cannot spawn unbounded goroutines and SSH state.
	maxSFTPConnections = 256
	// sftpHandshakeTimeout bounds the SSH handshake so a client cannot hold a
	// connection open indefinitely before authenticating.
	sftpHandshakeTimeout = 30 * time.Second
	// sftpIdleTimeout closes a connection that sends no SFTP packet within the
	// window, reclaiming idle/slow-loris connections.
	sftpIdleTimeout = 5 * time.Minute
)

// Config holds SFTP gateway configuration.
type Config struct {
	ListenAddr  string `yaml:"listen_addr"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	HostKeyPath string `yaml:"host_key_path"`
	// MaxUploadBytes caps the highest offset+length a single WRITE may reach,
	// bounding the size of any one uploaded file. 0 = unlimited.
	MaxUploadBytes int64
}

// Gateway implements the SFTP protocol over SSH.
type Gateway struct {
	rootDir   string
	config    Config
	logger    *slog.Logger
	listener  net.Listener
	sshConfig *ssh.ServerConfig
	wg        sync.WaitGroup
	closed    chan struct{}
	connSem   chan struct{}
}

// New creates a new SFTP Gateway. cfg.HostKeyPath must be set.
func New(rootDir string, cfg Config, logger *slog.Logger) (*Gateway, error) {
	g := &Gateway{
		rootDir: rootDir,
		config:  cfg,
		logger:  logger.With("gateway", "sftp"),
		closed:  make(chan struct{}),
		connSem: make(chan struct{}, maxSFTPConnections),
	}

	sshCfg := &ssh.ServerConfig{
		// Pin the per-connection password-attempt cap rather than relying on the
		// library default, to blunt online guessing.
		MaxAuthTries: 6,
	}

	// Authentication is required whenever a username OR password is configured.
	// Using "||" (not "&&") keeps a half-filled config fail-closed: a config that
	// sets only one field must still match it, instead of silently accepting every
	// client. Only an entirely empty credential disables auth (the documented
	// no-auth mode, consistent with the HTTP/WebDAV gateways).
	if cfg.Username != "" || cfg.Password != "" {
		sshCfg.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			userOK := subtle.ConstantTimeCompare([]byte(conn.User()), []byte(cfg.Username))
			passOK := subtle.ConstantTimeCompare(password, []byte(cfg.Password))
			if userOK&passOK == 1 {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication failed for %s", conn.User())
		}
	} else {
		sshCfg.NoClientAuth = true
	}

	hostKey, generated, err := loadOrGenerateHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	if generated {
		// A freshly generated host key means clients pinning the previous identity
		// will see a host-key-changed warning. Surface it loudly so an ephemeral or
		// misconfigured key path (e.g. a non-persistent container layer) is noticed
		// rather than silently defeating host-key verification.
		g.logger.Warn("generated a new SFTP host key; clients will see a new host identity",
			"path", cfg.HostKeyPath)
	}
	sshCfg.AddHostKey(hostKey)

	g.sshConfig = sshCfg
	return g, nil
}

// Name returns the protocol name.
func (g *Gateway) Name() string { return "sftp" }

// Start begins serving SFTP connections.
func (g *Gateway) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", g.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("sftp listen: %w", err)
	}
	g.listener = ln
	g.logger.Info("sftp gateway started", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-g.closed:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			g.logger.Error("accept failed", "error", err)
			continue
		}
		select {
		case g.connSem <- struct{}{}:
			g.wg.Add(1)
			go g.handleConnection(conn)
		default:
			g.logger.Warn("connection limit reached, rejecting", "remote", conn.RemoteAddr())
			conn.Close()
		}
	}
}

// Stop gracefully shuts down the SFTP gateway.
func (g *Gateway) Stop(ctx context.Context) error {
	close(g.closed)
	if g.listener != nil {
		g.listener.Close()
	}
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	g.logger.Info("sftp gateway stopped")
	return nil
}

func (g *Gateway) handleConnection(conn net.Conn) {
	defer g.wg.Done()
	defer func() { <-g.connSem }()
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			g.logger.Error("sftp connection panic recovered", "remote", conn.RemoteAddr(), "panic", r)
		}
	}()

	// Bound the handshake so an unauthenticated client cannot hold the connection
	// open; cleared once the SFTP loop installs its own per-packet idle deadline.
	conn.SetDeadline(time.Now().Add(sftpHandshakeTimeout))

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, g.sshConfig)
	if err != nil {
		g.logger.Debug("ssh handshake failed", "remote", conn.RemoteAddr(), "error", err)
		return
	}
	defer sshConn.Close()
	conn.SetDeadline(time.Time{})

	g.logger.Info("ssh connection", "remote", sshConn.RemoteAddr(), "user", sshConn.User())

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			g.logger.Error("channel accept failed", "error", err)
			continue
		}

		go g.handleSession(conn, ch, requests)
	}
}

func (g *Gateway) handleSession(conn net.Conn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	defer func() {
		if r := recover(); r != nil {
			g.logger.Error("sftp session panic recovered", "panic", r)
		}
	}()

	for req := range reqs {
		// The subsystem name is an SSH string (4-byte length prefix + bytes).
		// Parse it safely; a malformed or short payload must not panic the server.
		name, _, err := unmarshalString(req.Payload)
		if req.Type != "subsystem" || err != nil || name != "sftp" {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		req.Reply(true, nil)
		g.serveSFTP(conn, ch)
		return
	}
}

// resolvePath validates a request path and returns the full filesystem path.
func (g *Gateway) resolvePath(reqPath string) (string, error) {
	_, fullPath, err := gateway.SafePath(g.rootDir, reqPath)
	return fullPath, err
}

// loadOrGenerateHostKey loads the host key at path, or generates and persists a
// new one if the file does not exist. The second return value reports whether a
// new key was generated (so the caller can warn about the changed host identity).
func loadOrGenerateHostKey(path string) (ssh.Signer, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, perr := ssh.ParsePrivateKey(data)
		return signer, false, perr
	}

	if !os.IsNotExist(err) {
		return nil, false, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate key: %w", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, false, fmt.Errorf("marshal key: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, pemBlock, 0o600); err != nil {
		return nil, false, fmt.Errorf("write host key: %w", err)
	}

	signer, perr := ssh.ParsePrivateKey(pemBlock)
	return signer, true, perr
}
