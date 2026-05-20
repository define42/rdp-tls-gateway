package session

import (
	"testing"
)

func TestUserFromContextNilContext(t *testing.T) {
	m := NewManager()
	if user, ok := m.UserFromContext(nil); ok || user != nil {
		t.Fatalf("expected (nil, false) for nil context, got (%v, %v)", user, ok)
	}
}

func TestGetSessionFromUserNameBlank(t *testing.T) {
	m := NewManager()
	if _, ok := m.getSessionFromUserName(""); ok {
		t.Fatal("expected ok=false for blank username")
	}
	if _, ok := m.getSessionFromUserName("   "); ok {
		t.Fatal("expected ok=false for whitespace username")
	}
}

func TestUserHasActiveSessionFromIPBlank(t *testing.T) {
	m := NewManager()
	if m.UserHasActiveSessionFromIP("", "192.0.2.1") {
		t.Fatal("expected false for blank username")
	}
	if m.UserHasActiveSessionFromIP("alice", "") {
		t.Fatal("expected false for blank client IP")
	}
}
