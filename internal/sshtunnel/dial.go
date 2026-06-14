package sshtunnel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// validate rejects configurations that cannot produce a safe outbound dial.
func (c Config) validate() error {
	if c.User == "" {
		return errors.New("SSH tunnel user must be set")
	}
	if err := validateServerAddress(c.Server); err != nil {
		return err
	}
	if c.RemoteListenAddr == "" {
		return errors.New("SSH tunnel remote listen address must be set")
	}
	return nil
}

// validateServerAddress requires the relay endpoint to be a literal IP address
// (IPv4 or IPv6) plus port. Hostnames are rejected so that DNS — which on a
// private host may be resolved through a VPN — cannot be used to redirect the
// outbound SSH dial. The relay's host key is still pinned via known_hosts, but
// pinning by IP closes the only attacker-controlled lookup before that pin is
// checked.
func validateServerAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("SSH tunnel server must be <ip>:<port>: %w", err)
	}
	if host == "" {
		return errors.New("SSH tunnel server must include an IP address")
	}
	if port == "" {
		return errors.New("SSH tunnel server must include a port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("SSH tunnel server port %q must be a number from 1 to 65535", port)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("SSH tunnel server host %q must be a literal IPv4 or IPv6 address, not a hostname", host)
	}
	return nil
}

func connectSSH(cfg Config) (*ssh.Client, error) {
	signer, err := loadPrivateKey(cfg.PrivateKeyPath, cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	hostKeyCallback, hostKeyAlgorithms, err := loadKnownHosts(cfg.KnownHostsPath, cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	config := &ssh.ClientConfig{
		User:              cfg.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           cfg.DialTimeout,
	}

	return ssh.Dial("tcp", cfg.Server, config)
}

func loadPrivateKey(path string, passphrase []byte) (ssh.Signer, error) {
	// #nosec G304 -- path is the operator-configured SSH_TUNNEL_PRIVATE_KEY.
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}

	if len(passphrase) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(keyBytes, passphrase)
	}
	return ssh.ParsePrivateKey(keyBytes)
}

func loadKnownHosts(path, sshServer string) (ssh.HostKeyCallback, []string, error) {
	hostKeyCallback, err := knownhosts.New(path)
	if err != nil {
		return nil, nil, err
	}

	hostKeyAlgorithms, err := hostKeyAlgorithmsForKnownHost(hostKeyCallback, sshServer)
	if err != nil {
		return nil, nil, err
	}

	return hostKeyCallback, hostKeyAlgorithms, nil
}

// hostKeyAlgorithmsForKnownHost probes the known_hosts callback with a sentinel
// key so it reports (via KeyError) which host keys are pinned for the relay. The
// returned algorithm list lets the handshake negotiate a key type we actually
// have pinned, rather than failing on a server default we cannot verify.
func hostKeyAlgorithmsForKnownHost(hostKeyCallback ssh.HostKeyCallback, sshServer string) ([]string, error) {
	err := hostKeyCallback(
		sshServer,
		hostKeyAlgorithmProbeAddr(sshServer),
		hostKeyAlgorithmProbeKey{},
	)
	if err == nil {
		return nil, fmt.Errorf("known_hosts algorithm probe unexpectedly matched %s", sshServer)
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return nil, err
	}
	if len(keyErr.Want) == 0 {
		return nil, fmt.Errorf("no known_hosts entry for %s", sshServer)
	}

	return hostKeyAlgorithmsForKnownKeys(keyErr.Want), nil
}

func hostKeyAlgorithmsForKnownKeys(knownKeys []knownhosts.KnownKey) []string {
	var algorithms []string
	seen := make(map[string]struct{})
	for _, knownKey := range knownKeys {
		for _, algorithm := range hostKeyAlgorithmsForKeyType(knownKey.Key.Type()) {
			if _, ok := seen[algorithm]; ok {
				continue
			}
			algorithms = append(algorithms, algorithm)
			seen[algorithm] = struct{}{}
		}
	}
	return algorithms
}

func hostKeyAlgorithmsForKeyType(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	case ssh.CertAlgoRSAv01:
		return []string{ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01}
	default:
		return []string{keyType}
	}
}

type hostKeyAlgorithmProbeAddr string

func (addr hostKeyAlgorithmProbeAddr) Network() string {
	return "tcp"
}

func (addr hostKeyAlgorithmProbeAddr) String() string {
	return string(addr)
}

type hostKeyAlgorithmProbeKey struct{}

func (hostKeyAlgorithmProbeKey) Type() string {
	return "blackhole-host-key-algorithm-probe"
}

func (hostKeyAlgorithmProbeKey) Marshal() []byte {
	return []byte("blackhole host key algorithm probe")
}

func (hostKeyAlgorithmProbeKey) Verify([]byte, *ssh.Signature) error {
	return errors.New("host key algorithm probe cannot verify signatures")
}
