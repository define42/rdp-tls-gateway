package rdp

import (
	"testing"

	"github.com/tomatome/grdp/protocol/x224"
)

func TestFindServerSelectedProtocolNotFound(t *testing.T) {
	// Payload that does not contain an RDP_NEG_RSP — too short.
	if _, ok := findServerSelectedProtocol(make([]byte, 5)); ok {
		t.Fatal("expected ok=false when no RDP_NEG_RSP present")
	}
}

func TestFindClientRequestedProtocolsNotFound(t *testing.T) {
	// Build a TPKT/X.224 payload with an RDP_NEG_RSP only — the search for an
	// RDP_NEG_REQ should return ok=false.
	ccf := buildServerCCFSelectTLS()
	total := len(ccf) + 4
	tpkt := make([]byte, total)
	tpkt[0] = 0x03
	tpkt[2] = byte(total >> 8)
	tpkt[3] = byte(total)
	copy(tpkt[4:], ccf)

	if _, ok := findClientRequestedProtocols(tpkt); ok {
		t.Fatal("expected ok=false when no RDP_NEG_REQ present")
	}
}

func TestFindX224NegotiationOnlySevenBytePayload(t *testing.T) {
	// 4-byte TPKT header + 7-byte X.224 header but no negotiation block.
	payload := make([]byte, 4+7)
	if _, ok := findX224Negotiation(payload, x224.TYPE_RDP_NEG_REQ); ok {
		t.Fatal("expected ok=false when payload has no negotiation bytes")
	}
}
