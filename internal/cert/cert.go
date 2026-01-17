package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/virt"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
)

type TLSManager struct {
	magic     *certmagic.Config
	settings  *config.SettingsType
	tlsConfig *tls.Config
	domains   []string
}

func (tm *TLSManager) GetTLSConfig() *tls.Config {
	return tm.tlsConfig
}

func (tm *TLSManager) worker() {

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		for range ticker.C {
			tm.updateDomains()
		}
	}
}

func (tm *TLSManager) updateDomains() {
	vmNames := virt.GetInstance().GetVMnames()
	frontPageDomain := tm.settings.Get(config.FRONT_DOMAIN)

	var domains []string
	domains = append(domains, frontPageDomain)

	for _, name := range vmNames {
		domains = append(domains, name+"."+frontPageDomain)
	}

	if sameElements(tm.domains, domains) {
		return
	}
	if err := tm.magic.ManageSync(context.Background(), domains); err != nil {
		log.Printf("acme: error updating managed domains: %v", err)
		return
	}
	tm.domains = domains
	log.Printf("acme: updated managed domains: %s", strings.Join(tm.domains, ", "))
}

func NewTLSManager(settings *config.SettingsType) (*TLSManager, error) {

	frontPageDomain := settings.Get(config.FRONT_DOMAIN)

	fallback, err := LoadOrGenerateCert(settings)
	if err != nil {
		log.Fatalf("cert setup: %v", err)
	}

	acmeEnabled := settings.IsTrue(config.ACME_ENABLE)
	email := settings.Get(config.ACME_EMAIL)
	ca := settings.Get(config.ACME_CA)
	storage := settings.Get(config.ACME_DATA_DIR)

	if !acmeEnabled {
		frontTLS := &tls.Config{
			Certificates: []tls.Certificate{fallback},
		}

		frontTLS.MinVersion = tls.VersionTLS10
		frontTLS.CipherSuites = allCipherSuiteIDs()

		return &TLSManager{
			tlsConfig: frontTLS,
			settings:  settings,
		}, nil
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
	var domains []string
	if frontPageDomain != "" {
		domains = append(domains, frontPageDomain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("acme enabled but no explicit hostnames provided in -routes or -frontpage-domain")
	}
	log.Printf("acme: pre-issuing certificates for: %s", strings.Join(domains, ", "))

	if err := magic.ManageSync(context.Background(), domains); err != nil {
		return nil, err
	}

	tlsCfg := magic.TLSConfig()
	tlsCfg.NextProtos = append([]string{"http/1.1"}, tlsCfg.NextProtos...)
	tlsCfg.GetCertificate = acmeGetCertificate(magic, fallback)
	tlsCfg.MinVersion = tls.VersionTLS10 // RDP backend compatibility
	tlsCfg.CipherSuites = allCipherSuiteIDs()

	tm := TLSManager{
		magic:     magic,
		tlsConfig: tlsCfg,
		settings:  settings,
	}

	go tm.worker()
	return &tm, nil
}

/*
func (tm *TLSManager) RemoveDomain(domain []string) error {
	tm.domains = removeStrings(tm.domains, domain)

	err := tm.magic.ManageSync(context.Background(), tm.domains)
	if err != nil {
		return err
	}

	return nil
}

func (tm *TLSManager) AddDomain(domain []string) error {

	tm.domains = append(tm.domains, domain...)

	err := tm.magic.ManageSync(context.Background(), tm.domains)
	if err != nil {
		return err
	}

	return nil
}
*/
/*
func buildFrontTLS(settings *config.SettingsType) (*tls.Config, error) {

	minTLS12 := settings.IsTrue(config.MIN_TLS12)
	frontPageDomain := settings.Get(config.FRONT_DOMAIN)

	fallback, err := LoadOrGenerateCert(settings)
	if err != nil {
		log.Fatalf("cert setup: %v", err)
	}

	acmeEnabled := settings.IsTrue(config.ACME_ENABLE)
	email := settings.Get(config.ACME_EMAIL)
	ca := settings.Get(config.ACME_CA)
	storage := settings.Get(config.ACME_DATA_DIR)

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
	var domains []string
	if frontPageDomain != "" {
		domains = append(domains, frontPageDomain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("acme enabled but no explicit hostnames provided in -routes or -frontpage-domain")
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
	}
	return tlsCfg, nil
}*/

func LoadOrGenerateCert(settings *config.SettingsType) (tls.Certificate, error) {
	certPath := settings.Get(config.CERT_FILE)
	keyPath := settings.Get(config.KEY_FILE)
	acmeEnabled := settings.IsTrue(config.ACME_ENABLE)
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

func IsACMETLSALPN(protocol string) bool {
	return protocol == acmez.ACMETLS1Protocol
}

func acmeGetCertificate(magic *certmagic.Config, fallback tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello == nil || hello.ServerName == "" {
			return &fallback, nil
		}
		return magic.GetCertificate(hello)
	}
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

/*
	func removeStrings(all []string, remove []string) []string {
		// Build lookup set
		toRemove := make(map[string]struct{}, len(remove))
		for _, s := range remove {
			toRemove[s] = struct{}{}
		}

		// Filter in-place
		result := all[:0]
		for _, s := range all {
			if _, found := toRemove[s]; !found {
				result = append(result, s)
			}
		}
		return result
	}
*/
func sameElements(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	count := make(map[string]int, len(a))
	for _, s := range a {
		count[s]++
	}

	for _, s := range b {
		if count[s] == 0 {
			return false
		}
		count[s]--
	}

	return true
}

func allCipherSuiteIDs() []uint16 {
	suites := make([]uint16, 0, len(tls.CipherSuites())+len(tls.InsecureCipherSuites()))
	for _, suite := range tls.CipherSuites() {
		suites = append(suites, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		suites = append(suites, suite.ID)
	}
	return suites
}
