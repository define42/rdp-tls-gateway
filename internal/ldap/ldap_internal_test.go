package ldap

import (
	"rdptlsgateway/internal/config"
	"testing"
)

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
