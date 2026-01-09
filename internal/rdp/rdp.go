package rdp

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"rdptlsgateway/internal/config"
	"strings"
	"sync"
	"time"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
)

// InitLogging configures grdp's logger to use the standard logger.
func InitLogging() {
	glog.SetLogger(log.New(os.Stdout, "", 0))
	glog.SetLevel(glog.ERROR)
}

// HandleConn handles a single RDP connection over TLS.
func HandleConn(raw net.Conn, frontTLS *tls.Config, routeForSNI func(string) string, settings *config.SettingsType) {
	if routeForSNI == nil {
		log.Printf("rdp: no route function provided")
		return
	}

	// 1) Read client Connection Request (TPKT)
	crq, err := readTPKT(raw)
	if err != nil {
		log.Printf("read client CRQ: %v", err)
		return
	}

	// Require that client offered TLS in RDP_NEG_REQ (practical for SNI routing).
	reqProto, ok := findClientRequestedProtocols(crq)
	if !ok || (reqProto&x224.PROTOCOL_SSL) == 0 {
		log.Printf("client did not offer TLS (ok=%v requested=0x%08x) from %s", ok, reqProto, raw.RemoteAddr())
		return
	}

	// 2) Send server Connection Confirm selecting TLS
	ccfPayload := buildServerCCFSelectTLS()
	if err := writeTPKT(raw, ccfPayload); err != nil {
		log.Printf("write CCF(TLS): %v", err)
		return
	}

	// 3) TLS handshake with client; get SNI
	clientTLS := tls.Server(raw, frontTLS)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("client tls handshake: %v", err)
		return
	}
	sni := strings.ToLower(strings.TrimSpace(clientTLS.ConnectionState().ServerName))
	backendAddr := routeForSNI(sni)
	if backendAddr == "" {
		log.Printf("no route for SNI=%q from %s", sni, raw.RemoteAddr())
		_ = clientTLS.Close()
		return
	}
	log.Printf("client %s SNI=%q -> %s", raw.RemoteAddr(), sni, backendAddr)

	// 4) Dial backend TCP
	d := net.Dialer{Timeout: settings.GetDuration(config.TIMEOUT)}
	backendRaw, err := d.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("dial backend %s: %v", backendAddr, err)
		_ = clientTLS.Close()
		return
	}
	defer backendRaw.Close()

	_ = backendRaw.SetDeadline(time.Now().Add(settings.GetDuration(config.TIMEOUT)))

	// 5) Send CRQ to backend (force TLS-only negotiation)
	backendCRQ := buildClientCRQSelectTLS()
	if err := writeTPKT(backendRaw, backendCRQ); err != nil {
		log.Printf("write backend CRQ: %v", err)
		_ = clientTLS.Close()
		return
	}

	// 6) Read backend CCF and require TLS selected
	ccfBackend, err := readTPKT(backendRaw)
	if err != nil {
		log.Printf("read backend CCF: %v", err)
		_ = clientTLS.Close()
		return
	}
	sel, ok := findServerSelectedProtocol(ccfBackend)
	if !ok {
		log.Printf("backend did not include RDP_NEG_RSP (cannot confirm TLS); backend=%s", backendAddr)
		_ = clientTLS.Close()
		return
	}
	if sel != x224.PROTOCOL_SSL {
		log.Printf("backend did not select TLS (selected=0x%08x) backend=%s", sel, backendAddr)
		_ = clientTLS.Close()
		return
	}

	// 7) Start TLS to backend, ignoring certificate validation
	backendTLSCfg := &tls.Config{
		InsecureSkipVerify: true, // ignore backend cert chain + hostname
	}
	if settings.IsTrue(config.MIN_TLS12) {
		backendTLSCfg.MinVersion = tls.VersionTLS12
	}
	// Still send SNI to backend if we have it (helps if backend uses SNI-based cert selection)
	if sni != "" && sni != "*" {
		backendTLSCfg.ServerName = sni
	}

	backendTLS := tls.Client(backendRaw, backendTLSCfg)
	if err := backendTLS.Handshake(); err != nil {
		log.Printf("backend tls handshake: %v (backend=%s)", err, backendAddr)
		_ = clientTLS.Close()
		return
	}

	// Clear deadlines for steady-state proxying
	_ = clientTLS.SetDeadline(time.Time{})
	_ = backendTLS.SetDeadline(time.Time{})

	// 8) Proxy both directions: clientTLS <-> backendTLS
	proxyBidirectional(clientTLS, backendTLS)
}

func proxyBidirectional(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	go func() {
		_, _ = io.Copy(b, a)
		closeBoth()
	}()
	_, _ = io.Copy(a, b)
	closeBoth()
}

// readTPKT reads one TPKT-framed PDU (4-byte header + payload).
func readTPKT(c net.Conn) ([]byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	if h[0] != tpkt.FASTPATH_ACTION_X224 || h[1] != 0x00 {
		return nil, fmt.Errorf("not TPKT (v=%02x r=%02x)", h[0], h[1])
	}
	n := int(binary.BigEndian.Uint16(h[2:4]))
	if n < 4 || n > 64*1024 {
		return nil, fmt.Errorf("invalid TPKT length %d", n)
	}
	b := make([]byte, n)
	copy(b[:4], h)
	if _, err := io.ReadFull(c, b[4:]); err != nil {
		return nil, err
	}
	return b, nil
}

// findClientRequestedProtocols finds an embedded RDP_NEG_REQ and returns requestedProtocols.
// We scan the payload for the 8-byte structure: type=0x01, len=8, then uint32 LE protocols.
func findClientRequestedProtocols(tpktPayload []byte) (uint32, bool) {
	neg, ok := findX224Negotiation(tpktPayload, x224.TYPE_RDP_NEG_REQ)
	if !ok {
		return 0, false
	}
	return neg.Result, true
}

// findServerSelectedProtocol finds an embedded RDP_NEG_RSP and returns selectedProtocol.
func findServerSelectedProtocol(tpktPayload []byte) (uint32, bool) {
	neg, ok := findX224Negotiation(tpktPayload, x224.TYPE_RDP_NEG_RSP)
	if !ok {
		return 0, false
	}
	return neg.Result, true
}

// buildServerCCFSelectTLS returns a minimal X.224 Connection Confirm payload selecting TLS (PROTOCOL_SSL).
func buildServerCCFSelectTLS() []byte {
	neg := x224.Negotiation{
		Type:   x224.TYPE_RDP_NEG_RSP,
		Flag:   0,
		Length: 8,
		Result: x224.PROTOCOL_SSL,
	}

	li := uint8(6 + neg.Length) // CC header (6) + negotiation (8)
	payload := make([]byte, 0, int(li)+1)
	payload = append(payload,
		li,
		byte(x224.TPDU_CONNECTION_CONFIRM),
		0x00, 0x00, // dst ref
		0x12, 0x34, // src ref (arbitrary)
		0x00, // class/options
		byte(neg.Type),
		neg.Flag,
	)

	lengthBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBytes, neg.Length)
	payload = append(payload, lengthBytes...)

	resultBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(resultBytes, neg.Result)
	payload = append(payload, resultBytes...)

	return payload
}

func buildClientCRQSelectTLS() []byte {
	pdu := x224.NewClientConnectionRequestPDU(nil)
	pdu.ProtocolNeg.Type = x224.TYPE_RDP_NEG_REQ
	pdu.ProtocolNeg.Flag = 0
	pdu.ProtocolNeg.Length = 8
	pdu.ProtocolNeg.Result = x224.PROTOCOL_SSL
	pdu.Len = uint8(len(pdu.Serialize()) - 1)
	return pdu.Serialize()
}

func findX224Negotiation(tpktPayload []byte, wantType x224.NegotiationType) (*x224.Negotiation, bool) {
	if len(tpktPayload) < 11 { // TPKT(4) + X.224 header(7)
		return nil, false
	}
	payload := tpktPayload[4:]
	if len(payload) < 7 {
		return nil, false
	}
	for i := 7; i+8 <= len(payload); i++ {
		if payload[i] != byte(wantType) {
			continue
		}
		neg := &x224.Negotiation{
			Type:   x224.NegotiationType(payload[i]),
			Flag:   payload[i+1],
			Length: binary.LittleEndian.Uint16(payload[i+2 : i+4]),
			Result: binary.LittleEndian.Uint32(payload[i+4 : i+8]),
		}
		if neg.Length != 8 {
			continue
		}
		return neg, true
	}
	return nil, false
}

func writeTPKT(conn net.Conn, payload []byte) error {
	t := &tpkt.TPKT{Conn: core.NewSocketLayer(conn)}
	_, err := t.Write(payload)
	return err
}
