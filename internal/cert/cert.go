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
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
)

func BuildFrontTLS(settings *config.SettingsType, routes map[string]string, fallback tls.Certificate, minTLS12 bool, frontPageDomain string) (*tls.Config, error) {

	acmeEnabled := settings.IsTrue(config.ACME_ENABLE)
	email := settings.Get(config.ACME_EMAIL)
	ca := settings.Get(config.ACME_CA)
	storage := settings.Get(config.ACME_STORE)

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
	}
	return tlsCfg, nil
}

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
