package sshtunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// forwardedTCPPayload mirrors the unexported RFC 4254 §7.2 payload the SSH
// client expects on a "forwarded-tcpip" channel. ssh.Marshal relies on field
// order, so this must match the field order used by golang.org/x/crypto/ssh.
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func TestLoadKnownHosts(t *testing.T) {
	hostSigner := mustLoadSigner(t, writeTestKey(t, nil))
	addr := "203.0.113.7:22"

	t.Run("pinned host returns algorithms", func(t *testing.T) {
		path := writeKnownHosts(t, addr, hostSigner.PublicKey())
		callback, algorithms, err := loadKnownHosts(path, addr)
		if err != nil {
			t.Fatalf("loadKnownHosts: %v", err)
		}
		if callback == nil {
			t.Fatal("expected non-nil host key callback")
		}
		if len(algorithms) == 0 {
			t.Fatal("expected at least one host key algorithm")
		}
	})

	t.Run("unknown host rejected", func(t *testing.T) {
		path := writeKnownHosts(t, "198.51.100.1:22", hostSigner.PublicKey())
		if _, _, err := loadKnownHosts(path, addr); err == nil {
			t.Fatal("expected error for host absent from known_hosts")
		}
	})
}

// TestTunnelForwardsAndCloses drives Open against an in-memory SSH server,
// confirms a forwarded connection is delivered through the tunnel listener, and
// that Close is idempotent.
func TestTunnelForwardsAndCloses(t *testing.T) {
	srv := startTestSSHServer(t)

	tunnel, err := Open(Config{
		User:              "tester",
		Server:            srv.addr,
		PrivateKeyPath:    srv.clientKeyPath,
		KnownHostsPath:    srv.knownHostsPath,
		RemoteListenAddr:  "127.0.0.1:9",
		DialTimeout:       5 * time.Second,
		KeepAliveInterval: 50 * time.Millisecond,
		KeepAliveTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	// The server's OpenChannel blocks until the client accepts the channel, so
	// open the forwarded channel concurrently with the tunnel-side Accept.
	serverConn := srv.waitForConn(t)
	forwardErr := serverForward(serverConn, "hello")

	conn, err := tunnel.Listener().Accept()
	if err != nil {
		t.Fatalf("tunnel Accept: %v", err)
	}
	// A forwarded connection is an SSH channel, which natively rejects
	// SetDeadline ("ssh: tcpChan: deadline not supported"). The listener must
	// wrap it so the gateway's setup deadline is a no-op instead of an error that
	// would drop the connection before it is served.
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline on a tunneled conn must be a no-op, got: %v", err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read forwarded data: %v", err)
	}
	_ = conn.Close()
	if string(data) != "hello" {
		t.Fatalf("forwarded data = %q, want %q", data, "hello")
	}
	if err := <-forwardErr; err != nil {
		t.Fatalf("server forward: %v", err)
	}

	// No keepalive failure should have been reported during normal operation.
	select {
	case err := <-tunnel.Fatal():
		t.Fatalf("unexpected fatal during normal operation: %v", err)
	default:
	}

	if err := tunnel.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got: %v", err)
	}
}

// TestTunnelKeepAliveReportsFailure confirms a dropped SSH transport surfaces on
// the Fatal channel so the gateway can exit and be restarted.
func TestTunnelKeepAliveReportsFailure(t *testing.T) {
	srv := startTestSSHServer(t)

	tunnel, err := Open(Config{
		User:              "tester",
		Server:            srv.addr,
		PrivateKeyPath:    srv.clientKeyPath,
		KnownHostsPath:    srv.knownHostsPath,
		RemoteListenAddr:  "127.0.0.1:9",
		DialTimeout:       5 * time.Second,
		KeepAliveInterval: 50 * time.Millisecond,
		KeepAliveTimeout:  500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = tunnel.Close() }()

	// Kill the server side so the next keepalive probe fails.
	serverConn := srv.waitForConn(t)
	_ = serverConn.Close()

	select {
	case err := <-tunnel.Fatal():
		if err == nil {
			t.Fatal("expected non-nil fatal error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive failure was not reported on Fatal channel")
	}
}

// serverForward opens a forwarded-tcpip channel matching the tunnel's requested
// forward (127.0.0.1:9), writes data, and closes it. It runs concurrently
// because OpenChannel blocks until the client accepts the channel.
func serverForward(serverConn *ssh.ServerConn, data string) <-chan error {
	result := make(chan error, 1)
	go func() {
		channel, reqs, err := serverConn.OpenChannel("forwarded-tcpip", ssh.Marshal(forwardedTCPPayload{
			Addr:       "127.0.0.1",
			Port:       9,
			OriginAddr: "127.0.0.1",
			OriginPort: 54321,
		}))
		if err != nil {
			result <- err
			return
		}
		go ssh.DiscardRequests(reqs)
		_, writeErr := io.WriteString(channel, data)
		_ = channel.Close()
		result <- writeErr
	}()
	return result
}

type testSSHServer struct {
	addr           string
	clientKeyPath  string
	knownHostsPath string
	conns          chan *ssh.ServerConn
}

func (s *testSSHServer) waitForConn(t *testing.T) *ssh.ServerConn {
	t.Helper()
	select {
	case c := <-s.conns:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server connection")
		return nil
	}
}

func startTestSSHServer(t *testing.T) *testSSHServer {
	t.Helper()

	hostSigner := mustLoadSigner(t, writeTestKey(t, nil))
	clientKeyPath := writeTestKey(t, nil)
	clientSigner := mustLoadSigner(t, clientKeyPath)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown public key")
		},
	}
	cfg.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	srv := &testSSHServer{
		addr:           listener.Addr().String(),
		clientKeyPath:  clientKeyPath,
		knownHostsPath: writeKnownHosts(t, listener.Addr().String(), hostSigner.PublicKey()),
		conns:          make(chan *ssh.ServerConn, 1),
	}

	go srv.accept(listener, cfg)
	return srv
}

func (s *testSSHServer) accept(listener net.Listener, cfg *ssh.ServerConfig) {
	for {
		nConn, err := listener.Accept()
		if err != nil {
			return
		}

		serverConn, channels, requests, err := ssh.NewServerConn(nConn, cfg)
		if err != nil {
			_ = nConn.Close()
			continue
		}

		go rejectChannels(channels)
		go handleGlobalRequests(requests)
		s.conns <- serverConn
	}
}

// handleGlobalRequests grants tcpip-forward (so Client.Listen succeeds) and
// replies failure to everything else, including keepalive probes — a failure
// reply still confirms the transport is alive.
func handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		if req.Type == "tcpip-forward" {
			_ = req.Reply(true, nil)
			continue
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

func rejectChannels(channels <-chan ssh.NewChannel) {
	for ch := range channels {
		_ = ch.Reject(ssh.UnknownChannelType, "no channels accepted")
	}
}

func mustLoadSigner(t *testing.T, path string) ssh.Signer {
	t.Helper()
	signer, err := loadPrivateKey(path, nil)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	return signer
}

func writeKnownHosts(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}
