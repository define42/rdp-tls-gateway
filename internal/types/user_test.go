package types

import (
	"testing"
)

func TestNewUser(t *testing.T) {
	user, err := NewUser("alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.GetName() != "alice" {
		t.Fatalf("expected name %q, got %q", "alice", user.GetName())
	}
}

func TestNewUserFieldAccess(t *testing.T) {
	user, err := NewUser("bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Name != "bob" {
		t.Fatalf("expected Name %q, got %q", "bob", user.Name)
	}
}
