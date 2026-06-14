package sshtunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeTestKey(t *testing.T, passphrase []byte) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var block *pem.Block
	if len(passphrase) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	}
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestLoadPrivateKey(t *testing.T) {
	t.Run("unencrypted", func(t *testing.T) {
		path := writeTestKey(t, nil)
		if _, err := loadPrivateKey(path, nil); err != nil {
			t.Fatalf("loadPrivateKey: %v", err)
		}
	})

	t.Run("with passphrase", func(t *testing.T) {
		passphrase := []byte("s3cret")
		path := writeTestKey(t, passphrase)
		if _, err := loadPrivateKey(path, passphrase); err != nil {
			t.Fatalf("loadPrivateKey with passphrase: %v", err)
		}
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		path := writeTestKey(t, []byte("right"))
		if _, err := loadPrivateKey(path, []byte("wrong")); err == nil {
			t.Fatal("expected error for wrong passphrase")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := loadPrivateKey(filepath.Join(t.TempDir(), "absent"), nil); err == nil {
			t.Fatal("expected error for missing key file")
		}
	})
}
