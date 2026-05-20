package cert

import (
	"crypto/tls"
	"rdptlsgateway/internal/config"
	"testing"

	"github.com/caddyserver/certmagic"
)

// resetACMEDefaultsForTest restores the package-global certmagic state so
// other tests are not affected by mutations performed here.
func resetACMEDefaultsForTest(t *testing.T) {
	t.Helper()
	origEmail := certmagic.DefaultACME.Email
	origCA := certmagic.DefaultACME.CA
	origAgreed := certmagic.DefaultACME.Agreed
	origDisable := certmagic.DefaultACME.DisableHTTPChallenge
	origStorage := certmagic.Default.Storage
	t.Cleanup(func() {
		certmagic.DefaultACME.Email = origEmail
		certmagic.DefaultACME.CA = origCA
		certmagic.DefaultACME.Agreed = origAgreed
		certmagic.DefaultACME.DisableHTTPChallenge = origDisable
		certmagic.Default.Storage = origStorage
	})
}

func TestConfigureACMEDefaultsWithEmail(t *testing.T) {
	resetACMEDefaultsForTest(t)
	t.Setenv(config.ACME_EMAIL, "ops@example.test")
	t.Setenv(config.ACME_CA, "")
	settings := config.NewSettingType(false)

	configureACMEDefaults(settings)

	if certmagic.DefaultACME.Email != "ops@example.test" {
		t.Fatalf("expected email to be set, got %q", certmagic.DefaultACME.Email)
	}
	if !certmagic.DefaultACME.Agreed {
		t.Fatal("expected Agreed=true")
	}
	if !certmagic.DefaultACME.DisableHTTPChallenge {
		t.Fatal("expected DisableHTTPChallenge=true")
	}
}

func TestConfigureACMEDefaultsWithCAAlias(t *testing.T) {
	resetACMEDefaultsForTest(t)
	t.Setenv(config.ACME_EMAIL, "")
	t.Setenv(config.ACME_CA, "staging")
	settings := config.NewSettingType(false)

	configureACMEDefaults(settings)

	if certmagic.DefaultACME.CA != certmagic.LetsEncryptStagingCA {
		t.Fatalf("expected staging CA, got %q", certmagic.DefaultACME.CA)
	}
}

func TestConfigureACMEDefaultsWithStorageDir(t *testing.T) {
	resetACMEDefaultsForTest(t)
	storage := t.TempDir()
	t.Setenv(config.ACME_EMAIL, "ops@example.test")
	t.Setenv(config.ACME_CA, "production")
	t.Setenv(config.DATA_ROOT_DIR, storage)
	settings := config.NewSettingType(false)

	configureACMEDefaults(settings)

	fs, ok := certmagic.Default.Storage.(*certmagic.FileStorage)
	if !ok {
		t.Fatalf("expected FileStorage, got %T", certmagic.Default.Storage)
	}
	if fs.Path != config.ACMEStorageDir(settings) {
		t.Fatalf("expected storage path %q, got %q", config.ACMEStorageDir(settings), fs.Path)
	}
	if certmagic.DefaultACME.CA != certmagic.LetsEncryptProductionCA {
		t.Fatalf("expected production CA, got %q", certmagic.DefaultACME.CA)
	}
}

func TestACMEGetCertificateUsesFallbackForEmptySNI(t *testing.T) {
	fallback, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate fallback: %v", err)
	}

	getCert := acmeGetCertificate(certmagic.NewDefault(), fallback)
	got, err := getCert(&tls.ClientHelloInfo{ServerName: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || len(got.Certificate) == 0 {
		t.Fatal("expected fallback cert with non-empty chain")
	}
}

func TestACMEGetCertificateUsesFallbackForNilHello(t *testing.T) {
	fallback, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate fallback: %v", err)
	}

	getCert := acmeGetCertificate(certmagic.NewDefault(), fallback)
	got, err := getCert(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || len(got.Certificate) == 0 {
		t.Fatal("expected fallback cert with non-empty chain")
	}
}

func TestLoadOrGenerateCertACMEFallback(t *testing.T) {
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.ACME_ENABLE, "true")
	settings := config.NewSettingType(false)

	cert, err := LoadOrGenerateCert(settings)
	if err != nil {
		t.Fatalf("LoadOrGenerateCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected non-empty fallback certificate when ACME enabled without static files")
	}
}
