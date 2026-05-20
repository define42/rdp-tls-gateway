package virt

import (
	"strings"
	"testing"
)

func TestDomainOwnerMetadataXMLEmpty(t *testing.T) {
	if _, err := domainOwnerMetadataXML(""); err == nil {
		t.Fatal("expected error for empty owner")
	}
	if _, err := domainOwnerMetadataXML("   "); err == nil {
		t.Fatal("expected error for whitespace-only owner")
	}
}

func TestDomainOwnerMetadataXMLValid(t *testing.T) {
	payload, err := domainOwnerMetadataXML("alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(payload, "alice") {
		t.Fatalf("expected owner in payload, got %q", payload)
	}
	if !strings.Contains(payload, "<owner>") {
		t.Fatalf("expected <owner> element in payload, got %q", payload)
	}
}

func TestUserOwnsVMEmptyName(t *testing.T) {
	owned, err := UserOwnsVM("", "alice")
	if err != nil {
		t.Fatalf("unexpected error for empty vm name: %v", err)
	}
	if owned {
		t.Fatal("expected ownership=false for empty vm name")
	}
	owned, err = UserOwnsVM("   ", "alice")
	if err != nil {
		t.Fatalf("unexpected error for whitespace vm name: %v", err)
	}
	if owned {
		t.Fatal("expected ownership=false for whitespace vm name")
	}
}

func TestVMOwnerEmptyName(t *testing.T) {
	owner, hasOwner, err := VMOwner("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasOwner || owner != "" {
		t.Fatalf("expected empty owner for empty name, got %q/%v", owner, hasOwner)
	}
}
