package session

import (
	"net/http"
	"net/http/httptest"
	"rdptlsgateway/internal/types"
	"testing"
)

const testSessionRemoteAddr = "192.0.2.10:12345"

func issueSession(t *testing.T, m *Manager, user *types.User, remoteAddr string) *http.Cookie {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.CreateSession(r.Context(), user, r.RemoteAddr); err != nil {
			t.Fatalf("create session: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "cv_session" {
			return cookie
		}
	}

	t.Fatal("session cookie not set")
	return nil
}

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("expected non-nil Manager")
	}
	if m.SessionManager == nil {
		t.Fatal("expected non-nil SessionManager")
	}
}

func TestCreateAndGetSession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("alice", "secret")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	sessionCookie := issueSession(t, m, user, testSessionRemoteAddr)

	sess, ok := m.GetSessionFromUserName("alice")
	if !ok {
		t.Fatal("expected to find session for alice")
	}
	if sess.ClientIP != "192.0.2.10" {
		t.Fatalf("expected canonical client IP %q, got %q", "192.0.2.10", sess.ClientIP)
	}

	// Now verify UserFromContext works in a subsequent request with the cookie
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.AddCookie(sessionCookie)

	handler2 := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := m.UserFromContext(r.Context())
		if !ok {
			t.Fatal("expected user from context")
		}
		if u.GetName() != "alice" {
			t.Fatalf("expected user %q, got %q", "alice", u.GetName())
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler2.ServeHTTP(rec2, req2)
}

func TestUserFromContextNil(t *testing.T) {
	m := NewManager()

	//nolint:staticcheck // testing nil context behavior
	u, ok := m.UserFromContext(nil)
	if ok {
		t.Fatal("expected ok=false for nil context")
	}
	if u != nil {
		t.Fatal("expected nil user for nil context")
	}
}

func TestUserFromContextNoSession(t *testing.T) {
	m := NewManager()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := m.UserFromContext(r.Context())
		if ok {
			t.Fatal("expected ok=false when no session exists")
		}
		if u != nil {
			t.Fatal("expected nil user when no session exists")
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)
}

func TestGetSessionFromUserName(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("bob", "pass")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, testSessionRemoteAddr)

	sess, ok := m.GetSessionFromUserName("bob")
	if !ok {
		t.Fatal("expected to find session for bob")
	}
	if sess.User == nil {
		t.Fatal("expected non-nil user in session")
	}
	if sess.User.GetName() != "bob" {
		t.Fatalf("expected user %q, got %q", "bob", sess.User.GetName())
	}
	if sess.ClientIP != "192.0.2.10" {
		t.Fatalf("expected canonical client IP %q, got %q", "192.0.2.10", sess.ClientIP)
	}

	// Test non-existing user
	_, ok = m.GetSessionFromUserName("nonexistent")
	if ok {
		t.Fatal("expected not to find session for nonexistent user")
	}
}

func TestDestroySession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("charlie", "pass")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	sessionCookie := issueSession(t, m, user, testSessionRemoteAddr)

	// Now destroy the session
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req2.AddCookie(sessionCookie)

	handler2 := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.DestroySession(r.Context()); err != nil {
			t.Fatalf("destroy session: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler2.ServeHTTP(rec2, req2)

	// Verify the session is destroyed by checking the user is gone
	_, found := m.GetSessionFromUserName("charlie")
	if found {
		t.Fatal("expected session to be destroyed")
	}
	if m.UserHasActiveSessionFromIP("charlie", "192.0.2.10") {
		t.Fatal("expected destroyed session to be ignored")
	}
}

func TestUserHasActiveSessionFromIP(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("dora", "pass")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, "192.0.2.20:5000")

	if !m.UserHasActiveSessionFromIP("dora", "192.0.2.20") {
		t.Fatal("expected matching username/IP pair to authorize")
	}
	if m.UserHasActiveSessionFromIP("dora", "192.0.2.21") {
		t.Fatal("did not expect different IP to authorize")
	}
}

func TestUserHasActiveSessionFromIPAllowsAnyMatchingOwnerSession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("erin", "pass")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, "192.0.2.30:5000")
	issueSession(t, m, user, "192.0.2.31:5001")

	if !m.UserHasActiveSessionFromIP("erin", "192.0.2.31") {
		t.Fatal("expected one of multiple active sessions to authorize")
	}
}

func TestUserHasActiveSessionFromIPDoesNotCrossAuthorizeUsers(t *testing.T) {
	m := NewManager()

	alice, err := types.NewUser("alice", "pass")
	if err != nil {
		t.Fatalf("new alice: %v", err)
	}
	bob, err := types.NewUser("bob", "pass")
	if err != nil {
		t.Fatalf("new bob: %v", err)
	}

	issueSession(t, m, alice, "192.0.2.40:5000")
	issueSession(t, m, bob, "192.0.2.40:5001")

	if !m.UserHasActiveSessionFromIP("alice", "192.0.2.40") {
		t.Fatal("expected alice to authorize from her active session IP")
	}
	if !m.UserHasActiveSessionFromIP("bob", "192.0.2.40") {
		t.Fatal("expected bob to authorize from his active session IP")
	}
	if m.UserHasActiveSessionFromIP("carol", "192.0.2.40") {
		t.Fatal("did not expect unrelated user to authorize from shared IP")
	}
}

func TestCreateSessionNormalizesIPv4MappedIPv6(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("frank", "pass")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, "[::ffff:192.0.2.50]:5000")

	sess, ok := m.GetSessionFromUserName("frank")
	if !ok {
		t.Fatal("expected to find session for frank")
	}
	if sess.ClientIP != "192.0.2.50" {
		t.Fatalf("expected canonical client IP %q, got %q", "192.0.2.50", sess.ClientIP)
	}
	if !m.UserHasActiveSessionFromIP("frank", "192.0.2.50") {
		t.Fatal("expected IPv4-mapped IPv6 login to authorize plain IPv4 lookups")
	}
}
