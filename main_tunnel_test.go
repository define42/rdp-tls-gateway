package main

import (
	"devboxgateway/internal/config"
	"net"
	"testing"
	"time"
)

func TestOpenFrontListenerLocal(t *testing.T) {
	t.Setenv(config.SSH_TUNNEL_ENABLE, "false")
	t.Setenv(config.LISTEN_ADDR, "127.0.0.1:0")
	settings := config.NewSettingType(false)

	ln, tunnel, err := openFrontListener(settings)
	if err != nil {
		t.Fatalf("openFrontListener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if tunnel != nil {
		t.Fatal("expected nil tunnel in local mode")
	}
	if _, ok := ln.Addr().(*net.TCPAddr); !ok {
		t.Fatalf("expected TCP listener, got %T", ln.Addr())
	}
}

func TestOpenFrontListenerTunnelConfigError(t *testing.T) {
	// A hostname relay address is rejected before any network dial, so this
	// exercises the tunnel branch without needing a live SSH server.
	t.Setenv(config.SSH_TUNNEL_ENABLE, "true")
	t.Setenv(config.SSH_TUNNEL_USER, "tunnel")
	t.Setenv(config.SSH_TUNNEL_SERVER, "relay.example.com:22")
	settings := config.NewSettingType(false)

	ln, tunnel, err := openFrontListener(settings)
	if err == nil {
		_ = ln.Close()
		_ = tunnel.Close()
		t.Fatal("expected error for hostname relay address")
	}
	if tunnel != nil {
		t.Fatal("expected nil tunnel on error")
	}
}

func TestGatewayRuntimeFatalLocalMode(t *testing.T) {
	// In local mode there is no tunnel, so Fatal must return a nil channel,
	// which blocks forever in a select and never triggers a shutdown.
	g := &gatewayRuntime{}
	if g.Fatal() != nil {
		t.Fatal("expected nil Fatal channel without a tunnel")
	}

	select {
	case <-g.Fatal():
		t.Fatal("nil Fatal channel should never fire")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSSHTunnelConfigMapsSettings(t *testing.T) {
	t.Setenv(config.SSH_TUNNEL_USER, "tunnel")
	t.Setenv(config.SSH_TUNNEL_SERVER, "203.0.113.7:2222")
	t.Setenv(config.SSH_TUNNEL_PRIVATE_KEY, "/keys/id")
	t.Setenv(config.SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE, "secret")
	t.Setenv(config.SSH_TUNNEL_KNOWN_HOSTS, "/keys/known_hosts")
	t.Setenv(config.SSH_TUNNEL_REMOTE_ADDR, "0.0.0.0:443")
	t.Setenv(config.SSH_TUNNEL_KEEPALIVE_INTERVAL, "7s")
	t.Setenv(config.SSH_TUNNEL_KEEPALIVE_TIMEOUT, "3s")
	t.Setenv(config.TIMEOUT, "12s")
	settings := config.NewSettingType(false)

	cfg := sshTunnelConfig(settings)

	if cfg.User != "tunnel" || cfg.Server != "203.0.113.7:2222" {
		t.Fatalf("unexpected user/server: %q %q", cfg.User, cfg.Server)
	}
	if cfg.PrivateKeyPath != "/keys/id" || cfg.KnownHostsPath != "/keys/known_hosts" {
		t.Fatalf("unexpected key paths: %q %q", cfg.PrivateKeyPath, cfg.KnownHostsPath)
	}
	if string(cfg.Passphrase) != "secret" {
		t.Fatalf("unexpected passphrase: %q", cfg.Passphrase)
	}
	if cfg.RemoteListenAddr != "0.0.0.0:443" {
		t.Fatalf("unexpected remote addr: %q", cfg.RemoteListenAddr)
	}
	if cfg.DialTimeout != 12*time.Second {
		t.Fatalf("unexpected dial timeout: %s", cfg.DialTimeout)
	}
	if cfg.KeepAliveInterval != 7*time.Second || cfg.KeepAliveTimeout != 3*time.Second {
		t.Fatalf("unexpected keepalive durations: %s %s", cfg.KeepAliveInterval, cfg.KeepAliveTimeout)
	}
}
