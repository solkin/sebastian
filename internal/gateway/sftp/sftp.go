// Package sftp implements an SFTP gateway that exposes rootDir over SSH/SFTP.
// Compatible with OpenSSH sftp, FileZilla, WinSCP, Cyberduck, and other SFTP clients.
package sftp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/solkin/sebastian/internal/gateway"
)

// Config holds SFTP gateway configuration.
type Config struct {
	ListenAddr  string `yaml:"listen_addr"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	HostKeyPath string `yaml:"host_key_path"`
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
}

// New creates a new SFTP Gateway. cfg.HostKeyPath must be set.
func New(rootDir string, cfg Config, logger *slog.Logger) (*Gateway, error) {
	g := &Gateway{
		rootDir: rootDir,
		config:  cfg,
		logger:  logger.With("gateway", "sftp"),
		closed:  make(chan struct{}),
	}

	sshCfg := &ssh.ServerConfig{}

	if cfg.Username != "" && cfg.Password != "" {
		sshCfg.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == cfg.Username && string(password) == cfg.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication failed for %s", conn.User())
		}
	} else {
		sshCfg.NoClientAuth = true
	}

	hostKey, err := loadOrGenerateHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
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
		g.wg.Add(1)
		go g.handleConnection(conn)
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
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, g.sshConfig)
	if err != nil {
		g.logger.Debug("ssh handshake failed", "remote", conn.RemoteAddr(), "error", err)
		return
	}
	defer sshConn.Close()

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

		go g.handleSession(ch, requests)
	}
}

func (g *Gateway) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()

	for req := range reqs {
		if req.Type != "subsystem" || string(req.Payload[4:]) != "sftp" {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		req.Reply(true, nil)
		g.serveSFTP(ch)
		return
	}
}

// resolvePath validates a request path and returns the full filesystem path.
func (g *Gateway) resolvePath(reqPath string) (string, error) {
	_, fullPath, err := gateway.SafePath(g.rootDir, reqPath)
	return fullPath, err
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pemBlock, 0o600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}

	return ssh.ParsePrivateKey(pemBlock)
}
