package sshtunnel

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateServerAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "ipv4 with port", addr: "203.0.113.7:22", wantErr: false},
		{name: "ipv6 with port", addr: "[2001:db8::1]:22", wantErr: false},
		{name: "hostname rejected", addr: "relay.example.com:22", wantErr: true},
		{name: "missing port", addr: "203.0.113.7", wantErr: true},
		{name: "empty port", addr: "203.0.113.7:", wantErr: true},
		{name: "port zero", addr: "203.0.113.7:0", wantErr: true},
		{name: "port too large", addr: "203.0.113.7:70000", wantErr: true},
		{name: "non-numeric port", addr: "203.0.113.7:ssh", wantErr: true},
		{name: "empty", addr: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServerAddress(tt.addr)
			if tt.wantErr && err == nil {
				t.Fatalf("validateServerAddress(%q) = nil, want error", tt.addr)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateServerAddress(%q) = %v, want nil", tt.addr, err)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	valid := Config{
		User:             "tunnel",
		Server:           "203.0.113.7:22",
		RemoteListenAddr: ":443",
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid config: unexpected error %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "missing user", mutate: func(c *Config) { c.User = "" }},
		{name: "hostname server", mutate: func(c *Config) { c.Server = "relay.example.com:22" }},
		{name: "missing remote addr", mutate: func(c *Config) { c.RemoteListenAddr = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			if err := cfg.validate(); err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

type fakeKeepAliveSender struct {
	err   error
	delay time.Duration
	calls int
}

func (f *fakeKeepAliveSender) SendRequest(string, bool, []byte) (bool, []byte, error) {
	f.calls++
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return false, nil, f.err
}

func TestSendKeepAlive(t *testing.T) {
	t.Run("reply confirms liveness", func(t *testing.T) {
		// A request-failure reply (false, nil) without a transport error still
		// proves the connection is alive.
		sender := &fakeKeepAliveSender{}
		if err := sendKeepAlive(sender, time.Second); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("transport error fails", func(t *testing.T) {
		sender := &fakeKeepAliveSender{err: errors.New("connection lost")}
		err := sendKeepAlive(sender, time.Second)
		if err == nil || !strings.Contains(err.Error(), "keepalive failed") {
			t.Fatalf("expected keepalive failure, got %v", err)
		}
	})

	t.Run("timeout fails", func(t *testing.T) {
		sender := &fakeKeepAliveSender{delay: 50 * time.Millisecond}
		err := sendKeepAlive(sender, time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("expected timeout failure, got %v", err)
		}
	})
}

func TestHostKeyAlgorithmsForKeyType(t *testing.T) {
	rsa := hostKeyAlgorithmsForKeyType("ssh-rsa")
	if len(rsa) != 3 || rsa[0] != "rsa-sha2-512" {
		t.Fatalf("expected RSA to expand to sha2 variants first, got %v", rsa)
	}

	ed := hostKeyAlgorithmsForKeyType("ssh-ed25519")
	if len(ed) != 1 || ed[0] != "ssh-ed25519" {
		t.Fatalf("expected ed25519 to pass through unchanged, got %v", ed)
	}
}
