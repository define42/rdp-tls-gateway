// Package sshtunnel publishes the gateway's front listener through an SSH
// reverse tunnel to a public relay. Instead of binding :443 locally, the
// gateway dials out to the relay over SSH and asks it to listen on the
// gateway's behalf; the relay forwards every accepted connection back down the
// tunnel. The returned net.Listener is fed to the same accept loop used for a
// local listener, so a gateway behind NAT can publish its service on a
// reachable host without inbound firewall rules.
package sshtunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config describes how to reach the relay and what it should publish.
type Config struct {
	// User is the SSH username on the relay.
	User string
	// Server is the relay SSH endpoint as <ip>:<port>. It must be a literal IP
	// so DNS cannot redirect the outbound dial before the host key is pinned.
	Server string
	// PrivateKeyPath is the PEM private key authenticating to the relay.
	PrivateKeyPath string
	// Passphrase decrypts the private key; leave empty for an unencrypted key.
	Passphrase []byte
	// KnownHostsPath pins the relay's SSH host key.
	KnownHostsPath string
	// RemoteListenAddr is the address the relay listens on, e.g. ":443".
	RemoteListenAddr string
	// DialTimeout bounds the outbound SSH connection attempt.
	DialTimeout time.Duration
	// KeepAliveInterval is the gap between keepalive probes on the tunnel.
	KeepAliveInterval time.Duration
	// KeepAliveTimeout bounds how long a keepalive reply may take before the
	// tunnel is treated as dead.
	KeepAliveTimeout time.Duration
}

// Tunnel owns the SSH connection and the remote listener it forwards.
type Tunnel struct {
	client    *ssh.Client
	listener  net.Listener
	cancel    context.CancelFunc
	fatal     chan error
	closeOnce sync.Once
	closeErr  error
}

// Open dials the relay, requests the remote listener, and starts a keepalive
// loop that reports a dead tunnel on the channel returned by Fatal.
func Open(cfg Config) (*Tunnel, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	client, err := connectSSH(cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH connection failed: %w", err)
	}

	listener, err := client.Listen("tcp", cfg.RemoteListenAddr)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("remote listen on %q failed: %w", cfg.RemoteListenAddr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &Tunnel{
		client:   client,
		listener: chanListener{Listener: listener},
		cancel:   cancel,
		fatal:    make(chan error, 1),
	}

	go t.keepAlive(ctx, cfg.KeepAliveInterval, cfg.KeepAliveTimeout)

	return t, nil
}

// Listener returns the remote listener whose Accept yields connections
// forwarded from the relay.
func (t *Tunnel) Listener() net.Listener {
	return t.listener
}

// chanListener wraps the SSH remote listener so every accepted connection is
// adapted by chanConn before being handed to the gateway accept loop.
type chanListener struct {
	net.Listener
}

func (l chanListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return chanConn{Conn: conn}, nil
}

// chanConn adapts an SSH channel-backed connection so the deadline methods are
// accepted as no-ops instead of returning "ssh: tcpChan: deadline not
// supported". The gateway sets a setup deadline on every accepted connection and
// drops the connection if that call fails; without this shim every tunneled
// connection — the dashboard, RDP, and ACME TLS-ALPN-01 validation — would be
// closed before it is served. The trade-off is that socket-level deadlines are
// not enforced for tunneled connections; a dead tunnel is detected by the SSH
// keepalive instead.
type chanConn struct {
	net.Conn
}

func (c chanConn) SetDeadline(time.Time) error      { return nil }
func (c chanConn) SetReadDeadline(time.Time) error  { return nil }
func (c chanConn) SetWriteDeadline(time.Time) error { return nil }

// Fatal delivers the first keepalive or transport failure that takes the tunnel
// down. The caller should treat a receive as a signal to shut down (and let a
// process supervisor reconnect). It never receives when the tunnel is closed
// deliberately via Close.
func (t *Tunnel) Fatal() <-chan error {
	return t.fatal
}

// Close stops the keepalive loop and tears down the SSH connection. It is safe
// to call more than once.
//
// Only the SSH client is closed: that tears down the transport and, via
// forwardList.closeAll, unblocks the remote listener's Accept. We deliberately
// do not call listener.Close(), which issues a cancel-tcpip-forward round trip
// that blocks forever once the connection is already dead (e.g. after a
// keepalive failure). Dropping the SSH session already makes the relay release
// the forwarded port.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		t.closeErr = ignoreClosed(t.client.Close())
	})
	return t.closeErr
}

func ignoreClosed(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
