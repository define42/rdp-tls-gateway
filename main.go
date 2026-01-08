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
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"

	"rdptlsgateway/internal/rdp"
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

	rdp.InitLogging()

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
	rdp.HandleConn(conn, frontTLS, func(sni string) string {
		return routeForSNI(routes, sni)
	}, timeout, minTLS12)
}

const tlsHandshakeRecordType = 0x16

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
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
