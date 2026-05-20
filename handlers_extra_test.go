package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"strings"
	"testing"
)

func TestParseFormWithBodyLimitSkipsAlreadyParsedForm(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.Form = url.Values{"username": {"alice"}}

	if err := parseFormWithBodyLimit(rec, req); err != nil {
		t.Fatalf("expected no error for pre-parsed form, got %v", err)
	}
	if got := req.FormValue("username"); got != "alice" {
		t.Fatalf("expected pre-parsed form to be preserved, got %q", got)
	}
}

func TestParseFormWithBodyLimitParsesUrlEncoded(t *testing.T) {
	rec := httptest.NewRecorder()
	body := url.Values{"username": {"alice"}, "password": {"dogood"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := parseFormWithBodyLimit(rec, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := req.FormValue("password"); got != "dogood" {
		t.Fatalf("expected password to be parsed, got %q", got)
	}
}

func TestHandleLogoutWithoutSession(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestHandleLoginPostRejectsMissingCredentials(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	body := url.Values{"username": {""}, "password": {""}}.Encode()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (re-rendered login), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Missing credentials.") {
		t.Fatal("expected 'Missing credentials.' message in body")
	}
}

func TestHandleLoginPostRejectsOversizedForm(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	body := "username=" + strings.Repeat("a", maxFormBodyBytes) + "&password=secret"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (re-rendered login), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid form submission.") {
		t.Fatal("expected 'Invalid form submission.' message in body")
	}
}

func TestHandleLoginPostRejectsBadCredentials(t *testing.T) {
	// No real LDAP available in unit tests; an LDAP_URL pointing to a closed
	// port should make AuthenticateAccess fail, which re-renders the login form.
	t.Setenv(config.LDAP_URL, "ldap://127.0.0.1:1")
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	body := url.Values{"username": {"alice"}, "password": {"dogood"}}.Encode()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (re-rendered login), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid credentials.") {
		t.Fatal("expected 'Invalid credentials.' message in body")
	}
}
