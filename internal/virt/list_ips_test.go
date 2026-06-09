package virt

import (
	"testing"

	"libvirt.org/go/libvirt"
)

func TestAppendUniqueDomainIPSkipsEmpty(t *testing.T) {
	seen := map[string]struct{}{}
	got := appendUniqueDomainIP(nil, seen, "")
	if got != nil {
		t.Fatalf("expected nil result for empty addr, got %v", got)
	}
	if len(seen) != 0 {
		t.Fatalf("expected seen map to remain empty, got %v", seen)
	}
}

func TestAppendUniqueDomainIPDeduplicates(t *testing.T) {
	seen := map[string]struct{}{}
	got := appendUniqueDomainIP(nil, seen, "10.0.0.1")
	got = appendUniqueDomainIP(got, seen, "10.0.0.1")
	got = appendUniqueDomainIP(got, seen, "10.0.0.2")
	got = appendUniqueDomainIP(got, seen, "10.0.0.2")
	got = appendUniqueDomainIP(got, seen, "10.0.0.3")
	if len(got) != 3 {
		t.Fatalf("expected 3 unique addresses, got %v", got)
	}
	expected := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, want := range expected {
		if got[i] != want {
			t.Fatalf("unexpected address at index %d: got %q, want %q", i, got[i], want)
		}
	}
}

func TestAppendDomainInterfaceIPsFlattensAddresses(t *testing.T) {
	iface := libvirt.DomainInterface{
		Name: "eth0",
		Addrs: []libvirt.DomainIPAddress{
			{Addr: "10.0.0.1"},
			{Addr: "10.0.0.2"},
			{Addr: ""},         // skipped
			{Addr: "10.0.0.1"}, // duplicate, skipped
		},
	}
	seen := map[string]struct{}{}
	got := appendDomainInterfaceIPs(nil, seen, iface)

	if len(got) != 2 {
		t.Fatalf("expected 2 unique addresses, got %v", got)
	}
	if got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("unexpected addresses: %v", got)
	}
}

func TestAppendDomainInterfaceIPsHandlesNoAddresses(t *testing.T) {
	iface := libvirt.DomainInterface{Name: "eth0"}
	seen := map[string]struct{}{}
	got := appendDomainInterfaceIPs([]string{"existing"}, seen, iface)
	if len(got) != 1 || got[0] != "existing" {
		t.Fatalf("expected existing slice to be returned unchanged, got %v", got)
	}
}

func TestIPInDefaultNetwork(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"192.168.122.2", true},
		{"192.168.122.254", true},
		{"  192.168.122.50  ", true}, // surrounding whitespace tolerated
		{"192.168.123.2", false},     // adjacent subnet
		{"10.0.0.5", false},          // off-network host (SSRF target)
		{"127.0.0.1", false},         // loopback
		{"192.168.122.0", true},      // network address still inside the /24
		{"fd00::1", false},           // IPv6 rejected
		{"::ffff:10.0.0.5", false},   // IPv4-mapped off-network host rejected
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := ipInDefaultNetwork(tc.addr); got != tc.want {
			t.Errorf("ipInDefaultNetwork(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestFirstRoutableVMIP(t *testing.T) {
	// An untrusted agent/ARP address ahead of the real lease must be skipped.
	got := firstRoutableVMIP([]string{"10.0.0.5", "192.168.122.42"})
	if got != "192.168.122.42" {
		t.Fatalf("expected first in-subnet address, got %q", got)
	}

	// No in-subnet address means no trusted route (fail closed).
	if got := firstRoutableVMIP([]string{"10.0.0.5", "172.16.0.1"}); got != "" {
		t.Fatalf("expected empty result for off-network addresses, got %q", got)
	}

	if got := firstRoutableVMIP(nil); got != "" {
		t.Fatalf("expected empty result for no addresses, got %q", got)
	}
}
