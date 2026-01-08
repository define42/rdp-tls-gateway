// main.go
//
// RDP TLS SNI gateway (TLS terminate on the front, TLS initiate to backend).
// Routing is based on the client's TLS SNI.
// Backend TLS certificates are NOT validated (InsecureSkipVerify=true).
//
// Flow (front side):
//   1) Read client's X.224 Connection Request (TPKT)
//   2) Reply with X.224 Connection Confirm selecting TLS (PROTOCOL_SSL)
//   3) Do TLS handshake with client, read SNI
//
// Flow (backend side):
//   4) TCP connect to chosen backend
//   5) Send a new Connection Request to backend that only requests TLS (RDP_NEG_REQ)
//   6) Read backend Connection Confirm, require it selects TLS (PROTOCOL_SSL)
//   7) Do TLS handshake to backend (skip cert verification)
//   8) Proxy bytes both ways: clientTLS <-> backendTLS
//
// Note: This is NOT Microsoft RD Gateway (no HTTP/UDP transports). It’s a TLS-to-TLS RDP proxy.

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
)

func main() {
	var (
		listenAddr      = flag.String("listen", ":443", "listen address")
		certFile        = flag.String("cert", "", "TLS certificate PEM for clients (front side)")
		keyFile         = flag.String("key", "", "TLS private key PEM for clients (front side, unencrypted)")
		routesArg       = flag.String("routes", "", "comma-separated routing rules: host=ip:port,*.suffix=ip:port,*=default (required)")
		timeout         = flag.Duration("timeout", 10*time.Second, "handshake/dial/read timeout for setup")
		minTLS12        = flag.Bool("tls12", true, "force TLS 1.2+ on both sides")
		acmeEnable      = flag.Bool("acme", false, "enable ACME certificate management with certmagic for front TLS")
		acmeEmail       = flag.String("acme-email", "", "ACME account email (recommended)")
		acmeCA          = flag.String("acme-ca", "", "ACME CA directory URL or 'staging'")
		acmeStore       = flag.String("acme-storage", "", "ACME storage path (optional)")
		frontPageDomain = flag.String("frontpage-domain", "", "optional domain to serve front page on HTTPS requests")
	)
	flag.Parse()

	initGRDPLogging()

	routes := parseRoutes(*routesArg)
	if len(routes) == 0 {
		log.Fatalf("no routes configured; use -routes")
	}

	cert, err := loadOrGenerateCert(*certFile, *keyFile, *acmeEnable)
	if err != nil {
		log.Fatalf("cert setup: %v", err)
	}

	frontTLS, err := buildFrontTLS(*acmeEnable, *acmeEmail, *acmeCA, *acmeStore, routes, cert, *minTLS12, *frontPageDomain)
	if err != nil {
		log.Fatalf("tls setup: %v", err)
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening on %s", *listenAddr)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(c, frontTLS, routes, *timeout, *minTLS12)
	}
}

func handleConn(raw net.Conn, frontTLS *tls.Config, routes map[string]string, timeout time.Duration, minTLS12 bool) {
	defer raw.Close()

	_ = raw.SetDeadline(time.Now().Add(timeout))

	br := bufio.NewReader(raw)
	first, err := br.Peek(1)
	if err != nil {
		log.Printf("peek protocol byte: %v", err)
		return
	}
	conn := &bufferedConn{Conn: raw, r: br}

	if first[0] == tlsHandshakeRecordType {
		handleHTTPS(conn, frontTLS, timeout)
		return
	}
	handleRDP(conn, frontTLS, routes, timeout, minTLS12)
}

const tlsHandshakeRecordType = 0x16

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func handleRDP(raw net.Conn, frontTLS *tls.Config, routes map[string]string, timeout time.Duration, minTLS12 bool) {
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
	backendAddr := routeForSNI(routes, sni)
	if backendAddr == "" {
		log.Printf("no route for SNI=%q from %s", sni, raw.RemoteAddr())
		_ = clientTLS.Close()
		return
	}
	log.Printf("client %s SNI=%q -> %s", raw.RemoteAddr(), sni, backendAddr)

	// 4) Dial backend TCP
	d := net.Dialer{Timeout: timeout}
	backendRaw, err := d.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("dial backend %s: %v", backendAddr, err)
		_ = clientTLS.Close()
		return
	}
	defer backendRaw.Close()

	_ = backendRaw.SetDeadline(time.Now().Add(timeout))

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
	if minTLS12 {
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

func handleHTTPS(raw net.Conn, frontTLS *tls.Config, timeout time.Duration) {
	// TLS handshake with client; get SNI
	clientTLS := tls.Server(raw, frontTLS)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("client tls handshake: %v", err)
		return
	}

	state := clientTLS.ConnectionState()
	if state.NegotiatedProtocol == acmez.ACMETLS1Protocol {
		_ = clientTLS.Close()
		return
	}

	sni := strings.ToLower(strings.TrimSpace(state.ServerName))
	log.Printf("https client %s SNI=%q -> hello world", raw.RemoteAddr(), sni)

	_ = clientTLS.SetDeadline(time.Time{})

	srv := &http.Server{
		Handler:           http.HandlerFunc(helloHandler),
		ReadHeaderTimeout: timeout,
	}
	ln := newSingleConnListener(clientTLS)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("https serve: %v", err)
	}
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}

	body := "<!doctype html><html><head><title>Hello</title></head><body><h1>Hello, world!</h1></body></html>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
}

type singleConnListener struct {
	conn net.Conn
	addr net.Addr
	done chan struct{}
	once sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	l := &singleConnListener{
		addr: conn.LocalAddr(),
		done: make(chan struct{}),
	}
	l.conn = &closeNotifyConn{Conn: conn, done: l.done, once: &l.once}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	if l.conn != nil {
		_ = l.conn.Close()
		l.conn = nil
	}
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}

type closeNotifyConn struct {
	net.Conn
	done chan struct{}
	once *sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
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
func findClientRequestedProtocols(tpkt []byte) (uint32, bool) {
	neg, ok := findX224Negotiation(tpkt, x224.TYPE_RDP_NEG_REQ)
	if !ok {
		return 0, false
	}
	return neg.Result, true
}

// findServerSelectedProtocol finds an embedded RDP_NEG_RSP and returns selectedProtocol.
func findServerSelectedProtocol(tpkt []byte) (uint32, bool) {
	neg, ok := findX224Negotiation(tpkt, x224.TYPE_RDP_NEG_RSP)
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

func findX224Negotiation(tpkt []byte, wantType x224.NegotiationType) (*x224.Negotiation, bool) {
	if len(tpkt) < 11 { // TPKT(4) + X.224 header(7)
		return nil, false
	}
	payload := tpkt[4:]
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

func initGRDPLogging() {
	glog.SetLogger(log.New(os.Stdout, "", 0))
	glog.SetLevel(glog.ERROR)
}

func parseRoutes(s string) map[string]string {
	m := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return m
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			log.Fatalf("bad route %q (want host=ip:port)", part)
		}
		host := strings.ToLower(strings.TrimSpace(kv[0]))
		addr := strings.TrimSpace(kv[1])
		if host == "" || addr == "" {
			log.Fatalf("bad route %q (empty host/addr)", part)
		}
		m[host] = addr
	}
	return m
}

func routeForSNI(routes map[string]string, sni string) string {
	// exact match first
	if sni != "" {
		if v, ok := routes[sni]; ok {
			return v
		}
		// wildcard suffix matches like *.example.com
		for k, v := range routes {
			if strings.HasPrefix(k, "*.") {
				suffix := strings.TrimPrefix(k, "*") // ".example.com"
				if strings.HasSuffix(sni, suffix) {
					return v
				}
			}
		}
	}

	// default
	if v, ok := routes["*"]; ok {
		return v
	}
	return ""
}

func buildFrontTLS(acmeEnabled bool, email, ca, storage string, routes map[string]string, fallback tls.Certificate, minTLS12 bool, frontPageDomain string) (*tls.Config, error) {
	if !acmeEnabled {
		frontTLS := &tls.Config{
			Certificates: []tls.Certificate{fallback},
		}
		if minTLS12 {
			frontTLS.MinVersion = tls.VersionTLS12
		}
		return frontTLS, nil
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DisableHTTPChallenge = true
	if email != "" {
		certmagic.DefaultACME.Email = email
	} else {
		log.Printf("acme: no -acme-email provided; account registration may be rejected by some CAs")
	}
	if ca != "" {
		certmagic.DefaultACME.CA = resolveACMECA(ca)
	}
	if storage != "" {
		certmagic.Default.Storage = &certmagic.FileStorage{Path: storage}
	}

	magic := certmagic.NewDefault()
	domains, skipped := acmeManagedHosts(routes)
	if frontPageDomain != "" {
		domains = append(domains, frontPageDomain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("acme enabled but no explicit hostnames provided in -routes or -frontpage-domain")
	}
	if len(skipped) > 0 {
		log.Printf("acme: skipping wildcard routes for pre-issuance: %s", strings.Join(skipped, ", "))
	}
	log.Printf("acme: pre-issuing certificates for: %s", strings.Join(domains, ", "))

	if err := magic.ManageSync(context.Background(), domains); err != nil {
		return nil, err
	}

	tlsCfg := magic.TLSConfig()
	tlsCfg.NextProtos = append([]string{"http/1.1"}, tlsCfg.NextProtos...)
	tlsCfg.GetCertificate = acmeGetCertificate(magic, fallback)
	if minTLS12 {
		tlsCfg.MinVersion = tls.VersionTLS12
	} else {
		tlsCfg.MinVersion = 0
		tlsCfg.CipherSuites = nil
		tlsCfg.CurvePreferences = nil
		tlsCfg.PreferServerCipherSuites = false
	}
	return tlsCfg, nil
}

func acmeGetCertificate(magic *certmagic.Config, fallback tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || hello.ServerName == "" {
			return &fallback, nil
		}
		return magic.GetCertificate(hello)
	}
}

func acmeManagedHosts(routes map[string]string) ([]string, []string) {
	var domains []string
	var skipped []string
	for host := range routes {
		if host == "*" {
			continue
		}
		if strings.Contains(host, "*") {
			skipped = append(skipped, host)
			continue
		}
		domains = append(domains, host)
	}
	sort.Strings(domains)
	sort.Strings(skipped)
	return domains, skipped
}

func resolveACMECA(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "staging":
		return certmagic.LetsEncryptStagingCA
	case "production", "prod":
		return certmagic.LetsEncryptProductionCA
	default:
		return raw
	}
}

func loadOrGenerateCert(certPath, keyPath string, acmeEnabled bool) (tls.Certificate, error) {
	if certPath == "" && keyPath == "" {
		if acmeEnabled {
			log.Printf("acme enabled; no -cert/-key provided; generating self-signed fallback certificate for non-SNI clients")
		} else {
			log.Printf("no -cert/-key provided; generating self-signed certificate for this run")
		}
		return generateSelfSignedCert()
	}
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("both -cert and -key must be provided, or neither for auto-generated cert")
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "rdp-tls-gateway",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
