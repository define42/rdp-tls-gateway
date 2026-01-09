package main

import (
	"net"
	"net/http"
	"rdptlsgateway/internal/config"
	"strings"
)

const (
	defaultRDPAddress = "workstation:3389"
	defaultRDPPort    = "3389"
	rdpFilename       = "rdpgw.rdp"
)

func rdpTargetFromRequest(r *http.Request) string {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		return defaultRDPAddress
	}
	return rdpTargetHost(target)
}

func rdpTargetHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if hasPort(target) {
		return target
	}
	return addPort(target, defaultRDPPort)
}

func gatewayHostFromRequest(r *http.Request) string {
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host != "" {
		if idx := strings.Index(host, ","); idx >= 0 {
			host = strings.TrimSpace(host[:idx])
		}
	} else {
		host = strings.TrimSpace(r.Host)
	}

	if host == "" {
		return "localhost:8443"
	}

	port := strings.TrimSpace(r.Header.Get("X-Forwarded-Port"))
	if port != "" && !hasPort(host) {
		host = addPort(host, port)
	}
	return host
}

func hasPort(host string) bool {
	_, _, err := net.SplitHostPort(host)
	return err == nil
}

func addPort(host, port string) string {
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

func rdpFileContent(gatewayHost, targetHost string, settings *config.SettingsType, username string) string {
	var b strings.Builder
	write := func(line string) {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	write("screen mode id:i:2")
	write("full address:s:" + targetHost)
	write("gatewayhostname:s:" + gatewayHost)
	write("gatewayusagemethod:i:2")
	write("gatewaycredentialssource:i:4")
	write("gatewayprofileusagemethod:i:1")
	write("promptcredentialonce:i:0")
	write("authentication level:i:2")
	write("prompt for credentials:i:1")

	write("username:s:" + username)
	write("gatewayusername:s:" + settings.Get(config.NTLM_DOMAIN) + "\\" + username)
	//write("use redirection server name:i:1")
	return b.String()
}
