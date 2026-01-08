package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
)

type SettingsType struct {
	m map[string]SettingType
}

type SettingType struct {
	Description string
	Value       string
	IntValue    *int
}

func NewSettingType(print bool) *SettingsType {
	s := &SettingsType{m: make(map[string]SettingType)}

	s.Set(ACME_DATA_DIR, "ACME data directory", "/data/acme/")

	s.Set(VDI_IMAGE_DIR, "Directory for VDI images", "/data/vdiimage/")
	s.Set(LDAP_URL, "LDAP server url", "ldaps://ldap:389")
	s.Set(LDAP_BASE_DN, "LDAP base DN", "dc=glauth,dc=com")
	s.Set(LDAP_USER_FILTER, "LDAP user filter", "(mail=%s)")
	s.Set(LDAP_USER_DOMAIN, "LDAP user mail domain", "@example.com")
	s.Set(LDAP_STARTTLS, "Use StartTLS when connecting to LDAP", "false")
	s.Set(LDAP_SKIP_TLS_VERIFY, "Skip TLS verification when connecting to LDAP", "true")
	s.Set(NTLM_DOMAIN, "NTLM domain name", "vdi")
	s.SetInt(RDPGW_SEND_BUF, "RD Gateway socket send buffer size (bytes)", 1048576)
	s.SetInt(RDPGW_RECV_BUF, "RD Gateway socket receive buffer size (bytes)", 1048576)
	s.SetInt(RDPGW_WS_READ_BUF, "RD Gateway websocket read buffer size (bytes)", 65536)
	s.SetInt(RDPGW_WS_WRITE_BUF, "RD Gateway websocket write buffer size (bytes)", 65536)
	s.Set(BASE_IMAGE_URL, "URL to download base VDI image if not found locally", "https://github.com/define42/ubuntu-desktop-cloud-image/releases/download/v0.0.25/noble-desktop-cloudimg-amd64-v0.0.25.img")

	s.Set(LISTEN_ADDR, "listen address", ":443")
	s.Set(CERT_FILE, "TLS certificate PEM for clients (front side)", "")
	s.Set(KEY_FILE, "TLS private key PEM for clients (front side, unencrypted)", "")
	s.Set(ROUTES_ARG, "comma-separated routing rules: host=ip:port,*.suffix=ip:port,*=default (required)", "localhost=192.168.122.29:3389")
	s.Set(TIMEOUT, "handshake/dial/read timeout for setup", "10s")
	s.Set(MIN_TLS12, "force TLS 1.2+ on both sides", "true")
	s.Set(ACME_ENABLE, "enable ACME certificate management with certmagic for front TLS", "false")
	s.Set(ACME_EMAIL, "ACME account email (recommended)", "")
	s.Set(ACME_CA, "ACME CA directory URL or 'staging'", "")
	s.Set(ACME_STORE, "ACME storage path (optional)", "")
	s.Set(FRONT_PAGE_DOMAIN, "optional domain to serve front page on HTTPS requests", "")

	if print {
		table := tablewriter.NewWriter(os.Stdout)

		table.Header("KEY", "Description", "value")
		for key, setting := range s.m {
			if err := table.Append([]string{key, setting.Description, setting.Value}); err != nil {
				panic(err)
			}
		}
		if err := table.Render(); err != nil {
			panic(err)
		}
	}
	return s
}

func (s *SettingsType) Get(id string) string {
	setting := s.m[id]
	if setting.Value != "" {
		return setting.Value
	}
	if setting.IntValue != nil {
		return strconv.Itoa(*setting.IntValue)
	}
	return ""
}

func (s *SettingsType) Has(id string) bool {
	setting := s.m[id]
	return setting.Value != "" || setting.IntValue != nil
}

func (s *SettingsType) IsTrue(id string) bool {
	return s.m[id].Value == "true"
}

func (s *SettingsType) Set(id string, description string, defaultValue string) {
	if value, ok := os.LookupEnv(id); ok {
		s.m[id] = SettingType{Description: description, Value: value}
	} else {
		s.m[id] = SettingType{Description: description, Value: defaultValue}
	}
}

func (s *SettingsType) SetInt(id string, description string, defaultValue int) {
	value := defaultValue
	if raw, ok := os.LookupEnv(id); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(raw))
		if err == nil {
			value = parsed
		}
	}
	valueCopy := value
	s.m[id] = SettingType{
		Description: description,
		Value:       strconv.Itoa(value),
		IntValue:    &valueCopy,
	}
}

func (s *SettingsType) GetInt(id string, fallback int) int {
	setting := s.m[id]
	if setting.IntValue != nil {
		return *setting.IntValue
	}
	value := strings.TrimSpace(setting.Value)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func (s *SettingsType) GetDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(s.Get(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

const (
	ACME_DATA_DIR        = "ACME_DATA_DIR"
	ACME_EMAIL           = "ACME_EMAIL"
	ACME_CA              = "ACME_CA"
	ACME_ENABLE          = "ACME_ENABLE"
	ACME_STORE           = "ACME_STORE"
	CERT_FILE            = "CERT_FILE"
	FRONT_PAGE_DOMAIN    = "FRONT_PAGE_DOMAIN"
	KEY_FILE             = "KEY_FILE"
	LDAP_URL             = "LDAP_URL"
	LDAP_BASE_DN         = "LDAP_BASE_DN"
	LDAP_USER_FILTER     = "LDAP_USER_FILTER"
	LDAP_USER_DOMAIN     = "LDAP_USER_DOMAIN"
	LDAP_STARTTLS        = "LDAP_STARTTLS"
	LDAP_SKIP_TLS_VERIFY = "LDAP_SKIP_TLS_VERIFY"
	LISTEN_ADDR          = "LISTEN_ADDR"
	MIN_TLS12            = "MIN_TLS12"
	VDI_IMAGE_DIR        = "VDI_IMAGE_DIR"
	NTLM_DOMAIN          = "NTLM_DOMAIN"
	RDPGW_SEND_BUF       = "RDPGW_SEND_BUF"
	RDPGW_RECV_BUF       = "RDPGW_RECV_BUF"
	RDPGW_WS_READ_BUF    = "RDPGW_WS_READ_BUF"
	RDPGW_WS_WRITE_BUF   = "RDPGW_WS_WRITE_BUF"
	BASE_IMAGE_URL       = "BASE_IMAGE_URL"
	ROUTES_ARG           = "ROUTES_ARG"
	TIMEOUT              = "TIMEOUT"
)

var Settings = NewSettingType(true)
