package ldap

import (
	"devboxgateway/internal/config"
	"errors"
	"testing"
)

func TestAuthenticateAccessRejectsEmptyPassword(t *testing.T) {
	// Point at a reserved, non-resolvable host so that if the empty-password
	// guard were ever removed the test fails fast on a dial error rather than
	// authenticating or hanging.
	t.Setenv(config.LDAP_URL, "ldaps://ldap.invalid:636")
	settings := config.NewSettingType(false)

	user, err := AuthenticateAccess("johndoe", "", settings)
	if user != nil {
		t.Fatalf("expected no user for empty password, got %#v", user)
	}
	if !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
}

func TestConfigured(t *testing.T) {
	t.Setenv(config.LDAP_URL, "ldaps://ldap:389")
	if !Configured(config.NewSettingType(false)) {
		t.Fatal("expected Configured=true when LDAP_URL is set")
	}

	t.Setenv(config.LDAP_URL, "   ")
	if Configured(config.NewSettingType(false)) {
		t.Fatal("expected Configured=false when LDAP_URL is blank")
	}
}

func TestLoginIdentifierAppendsDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice@example.test" {
		t.Fatalf("expected alice@example.test, got %q", got)
	}
}

func TestLoginIdentifierAppendsDomainWithAtPrefix(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "@example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice@example.test" {
		t.Fatalf("expected alice@example.test, got %q", got)
	}
}

func TestLoginIdentifierKeepsExistingDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice@other.test", settings); got != "alice@other.test" {
		t.Fatalf("expected unmodified address, got %q", got)
	}
}

func TestLoginIdentifierWithoutDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice" {
		t.Fatalf("expected unmodified username, got %q", got)
	}
}
