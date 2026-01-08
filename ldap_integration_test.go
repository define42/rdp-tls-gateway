package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/ldap"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLDAPAuthenticateWithGlauthConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	os.Setenv("LDAP_URL", ldapURL)
	os.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	os.Setenv("LDAP_STARTTLS", "false")
	os.Setenv("LDAP_USER_DOMAIN", "@example.com")

	settings := config.NewSettingType(false)
	u, err := ldap.LdapAuthenticateAccess("testuser", "dogood", settings)
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
	if u == nil {
		t.Fatalf("expected user, got nil")
	}
}

func TestLDAPAuthenticateJohndoeSingleNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	t.Setenv("LDAP_STARTTLS", "false")
	t.Setenv("LDAP_USER_DOMAIN", "@example.com")

	settings := config.NewSettingType(false)

	u, err := ldap.LdapAuthenticateAccess("johndoe", "dogood", settings)
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
	if u == nil {
		t.Fatalf("expected user, got nil")
	}
}

/*
	func TestCvRouterProxyWithLDAP(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		baseURL, _ := setupLDAPProxyServer(t, ctx)

		client := &http.Client{Timeout: 10 * time.Second}
		accessCases := []requestCase{
			{name: "health", method: http.MethodGet, path: "/api/health", wantStatus: http.StatusOK, wantBodyContains: []string{"ok"}},
			{name: "login page", method: http.MethodGet, path: "/login", wantStatus: http.StatusOK, wantBodyContains: []string{"RemoteGateway"}},
		}
		assertRequestCases(t, ctx, baseURL, client, accessCases)

		redirectClient := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		status, _, header := doRequest(t, ctx, baseURL, redirectClient, http.MethodGet, "/api/dashboard", "", "", nil, nil)
		if status != http.StatusSeeOther {
			t.Fatalf("expected 303 for dashboard redirect, got %d", status)
		}
		if loc := header.Get("Location"); loc != "/login" {
			t.Fatalf("expected redirect to /login, got %q", loc)
		}

		loginClient := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		sessionCookie := loginAndGetSessionCookie(t, ctx, baseURL, loginClient, "testuser", "dogood")
		assertLogoutSuccess(t, ctx, baseURL, loginClient, sessionCookie)
		sessionCookie = loginAndGetSessionCookie(t, ctx, baseURL, loginClient, "serviceuser", "mysecret")
		assertLogoutSuccess(t, ctx, baseURL, loginClient, sessionCookie)
		assertLoginFailure(t, ctx, baseURL, loginClient, "testuser", "wrongpass", "Invalid credentials.")
		assertLoginFailure(t, ctx, baseURL, loginClient, "testuser", "", "Missing credentials.")
	}

	type requestCase struct {
		name             string
		method           string
		path             string
		user             string
		pass             string
		wantStatus       int
		wantBodyContains []string
	}

	func doRequest(t *testing.T, ctx context.Context, baseURL string, client *http.Client, method, path, user, pass string, body io.Reader, headers map[string]string) (int, string, http.Header) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		if user != "" || pass != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data), resp.Header.Clone()
	}

	func assertRequestCases(t *testing.T, ctx context.Context, baseURL string, client *http.Client, cases []requestCase) {
		t.Helper()
		for _, tc := range cases {
			status, body, _ := doRequest(t, ctx, baseURL, client, tc.method, tc.path, tc.user, tc.pass, nil, nil)
			if status != tc.wantStatus {
				t.Fatalf("expected %d for %s, got %d: %s", tc.wantStatus, tc.name, status, body)
			}
			for _, want := range tc.wantBodyContains {
				if !strings.Contains(body, want) {
					t.Fatalf("expected body for %s to contain %q, got %q", tc.name, want, body)
				}
			}
		}
	}

	func loginAndGetSessionCookie(t *testing.T, ctx context.Context, baseURL string, client *http.Client, username, password string) *http.Cookie {
		t.Helper()
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", password)
		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		status, _, header := doRequest(t, ctx, baseURL, client, http.MethodPost, "/login", "", "", strings.NewReader(form.Encode()), headers)
		if status != http.StatusSeeOther {
			t.Fatalf("expected 303 for login, got %d", status)
		}
		if loc := header.Get("Location"); loc != "/api/dashboard" {
			t.Fatalf("expected redirect to /api/dashboard, got %q", loc)
		}
		for _, raw := range header["Set-Cookie"] {
			cookie, err := http.ParseSetCookie(raw)
			if err != nil {
				continue
			}
			if cookie.Name == "cv_session" {
				return cookie
			}
		}
		t.Fatalf("expected session cookie on login")
		return nil
	}

	func assertLogoutSuccess(t *testing.T, ctx context.Context, baseURL string, client *http.Client, sessionCookie *http.Cookie) {
		t.Helper()
		if sessionCookie == nil {
			t.Fatalf("expected session cookie to be set")
		}
		headers := map[string]string{
			"Cookie": sessionCookie.Name + "=" + sessionCookie.Value,
		}
		status, _, header := doRequest(t, ctx, baseURL, client, http.MethodGet, "/logout", "", "", nil, headers)
		if status != http.StatusSeeOther {
			t.Fatalf("expected 303 for logout, got %d", status)
		}
		if loc := header.Get("Location"); loc != "/login" {
			t.Fatalf("expected redirect to /login, got %q", loc)
		}
	}

	func assertLoginFailure(t *testing.T, ctx context.Context, baseURL string, client *http.Client, username, password, message string) {
		t.Helper()
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", password)
		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		status, body, _ := doRequest(t, ctx, baseURL, client, http.MethodPost, "/login", "", "", strings.NewReader(form.Encode()), headers)
		if status != http.StatusOK {
			t.Fatalf("expected 200 for login page, got %d: %s", status, body)
		}
		if !strings.Contains(body, message) {
			t.Fatalf("expected login message %q, got %q", message, body)
		}
	}

	func setupLDAPProxyServer(t *testing.T, ctx context.Context) (string, *session.Manager) {
		t.Helper()

		ldapURL, stopLDAP := startGlauth(ctx, t, "")
		t.Cleanup(stopLDAP)

		configureLDAPEnv(t, ldapURL)

		settings := configureLDAPEnv(t, ldapURL)

		sessionManager := session.NewManager()
		server := httptest.NewServer(getRemoteGatewayRotuer(sessionManager, settings))
		t.Cleanup(server.Close)

		return server.URL, sessionManager
	}

	func configureLDAPEnv(t *testing.T, ldapURL string) *config.SettingsType {
		t.Helper()
		t.Setenv("LDAP_URL", ldapURL)
		t.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
		t.Setenv("LDAP_STARTTLS", "false")
		t.Setenv("LDAP_USER_DOMAIN", "@example.com")
		return config.NewSettingType(false)
	}
*/
func startGlauth(ctx context.Context, t *testing.T, network string) (string, func()) {
	t.Helper()

	cfg := pathRelative(t, "testldap", "default-config.cfg")
	cert := pathRelative(t, "testldap", "cert.pem")
	key := pathRelative(t, "testldap", "key.pem")

	req := testcontainers.ContainerRequest{
		Image:        "glauth/glauth:latest",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"GLAUTH_CONFIG": "/app/config/config.cfg",
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfg, ContainerFilePath: "/app/config/config.cfg", FileMode: 0o644},
			{HostFilePath: cert, ContainerFilePath: "/app/config/cert.pem", FileMode: 0o644},
			{HostFilePath: key, ContainerFilePath: "/app/config/key.pem", FileMode: 0o600},
		},
		Networks:       nil,
		NetworkAliases: nil,
		WaitingFor: wait.ForLog("LDAPS server listening").
			WithStartupTimeout(1 * time.Minute).
			WithPollInterval(2 * time.Second),
	}
	if network != "" {
		req.Networks = []string{network}
		req.NetworkAliases = map[string][]string{
			network: {"ldap"},
		}
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start glauth container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatalf("get mapped port: %v", err)
	}

	url := fmt.Sprintf("ldaps://%s:%s", host, port.Port())

	return url, func() {
		_ = container.Terminate(context.Background())
	}
}

func pathRelative(t *testing.T, elems ...string) string {
	t.Helper()
	p := filepath.Join(elems...)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}
