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
	"crypto/tls"
	"errors"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"rdptlsgateway/internal/cert"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/rdp"
)

func main() {

	rdp.InitLogging()

	routes := parseRoutes(config.Settings.Get(config.ROUTES_ARG))
	if len(routes) == 0 {
		log.Fatalf("no routes configured; use -routes")
	}

	cert2, err := cert.LoadOrGenerateCert(config.Settings.Get(config.CERT_FILE), config.Settings.Get(config.KEY_FILE), config.Settings.IsTrue(config.ACME_ENABLE))
	if err != nil {
		log.Fatalf("cert setup: %v", err)
	}

	frontTLS, err := cert.BuildFrontTLS(config.Settings.IsTrue(config.ACME_ENABLE), config.Settings.Get(config.ACME_EMAIL), config.Settings.Get(config.ACME_CA), config.Settings.Get(config.ACME_STORE), routes, cert2, config.Settings.IsTrue(config.MIN_TLS12), config.Settings.Get(config.FRONT_PAGE_DOMAIN))
	if err != nil {
		log.Fatalf("tls setup: %v", err)
	}

	ln, err := net.Listen("tcp", config.Settings.Get(config.LISTEN_ADDR))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening on %s", config.Settings.Get(config.LISTEN_ADDR))
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(c, frontTLS, routes)
	}
}

func handleConn(raw net.Conn, frontTLS *tls.Config, routes map[string]string) {
	defer raw.Close()

	br := bufio.NewReader(raw)
	first, err := br.Peek(1)
	if err != nil {
		log.Printf("peek protocol byte: %v", err)
		return
	}
	conn := &bufferedConn{Conn: raw, r: br}

	if first[0] == tlsHandshakeRecordType {
		handleHTTPS(conn, frontTLS, routes)
		return
	}
	rdp.HandleConn(conn, frontTLS, func(sni string) string {
		return routeForSNI(routes, sni)
	}, config.Settings.IsTrue(config.MIN_TLS12))
}

const tlsHandshakeRecordType = 0x16

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func handleHTTPS(raw net.Conn, frontTLS *tls.Config, routes map[string]string) {
	// TLS handshake with client; get SNI
	clientTLS := tls.Server(raw, frontTLS)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("client tls handshake: %v", err)
		return
	}

	state := clientTLS.ConnectionState()
	if cert.IsACMETLSALPN(state.NegotiatedProtocol) {
		_ = clientTLS.Close()
		return
	}

	sni := strings.ToLower(strings.TrimSpace(state.ServerName))
	log.Printf("https client %s SNI=%q -> https page", raw.RemoteAddr(), sni)

	_ = clientTLS.SetDeadline(time.Time{})

	srv := &http.Server{
		Handler: helloHandler(routes, sni),
	}
	ln := newSingleConnListener(clientTLS)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("https serve: %v", err)
	}
}

func helloHandler(routes map[string]string, connSNI string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}

		host := strings.ToLower(normalizeHost(r.Host))
		sni := strings.ToLower(strings.TrimSpace(connSNI))
		domain := host
		if domain == "" {
			domain = sni
		}

		addr, pattern, matchType := matchRoute(routes, domain)
		data := httpsPageData{
			Domain:       domain,
			Host:         host,
			SNI:          sni,
			MatchPattern: pattern,
			MatchType:    matchType,
			Backend:      addr,
			Routes:       routesForView(routes, pattern),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if err := httpsPageTemplate.Execute(w, data); err != nil {
			log.Printf("https page render: %v", err)
		}
	}
}

type httpsPageData struct {
	Domain       string
	Host         string
	SNI          string
	MatchPattern string
	MatchType    string
	Backend      string
	Routes       []routeEntry
}

type routeEntry struct {
	Host    string
	Target  string
	IsMatch bool
}

func routesForView(routes map[string]string, matchPattern string) []routeEntry {
	list := make([]routeEntry, 0, len(routes))
	for host, target := range routes {
		list = append(list, routeEntry{
			Host:    host,
			Target:  target,
			IsMatch: host == matchPattern,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Host < list[j].Host
	})
	return list
}

func normalizeHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if strings.HasPrefix(hostport, "[") {
		if idx := strings.LastIndex(hostport, "]"); idx != -1 {
			host := hostport[1:idx]
			return host
		}
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

var httpsPageTemplate = template.Must(template.New("https-page").Parse(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>RDP TLS Gateway</title>
  <style>
    :root {
      --ink: #1f2933;
      --muted: #556270;
      --accent: #0f766e;
      --paper: #fff7ee;
      --border: #e2d8c6;
      --bg1: #f5efe6;
      --bg2: #e6f2f2;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: "Spectral", "Georgia", serif;
      background:
        radial-gradient(900px circle at 10% 10%, var(--bg2), transparent 60%),
        linear-gradient(135deg, var(--bg1), #ffffff);
    }
    main {
      max-width: 960px;
      margin: 0 auto;
      padding: 48px 20px 64px;
    }
    h1 {
      margin: 0 0 6px;
      font-size: 40px;
      letter-spacing: 0.4px;
    }
    p.lead {
      margin: 0 0 24px;
      color: var(--muted);
      font-size: 18px;
    }
    section {
      background: var(--paper);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
      box-shadow: 0 10px 22px rgba(31, 41, 51, 0.08);
      margin-bottom: 20px;
    }
    h2 {
      margin: 0 0 12px;
      font-size: 20px;
      color: var(--accent);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 15px;
    }
    th {
      text-align: left;
      font-weight: 600;
      color: var(--muted);
      padding: 6px 0;
      width: 190px;
    }
    td {
      padding: 6px 0;
      font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
    }
    code {
      background: #efe6d8;
      padding: 2px 6px;
      border-radius: 6px;
    }
    ul {
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 8px;
    }
    li {
      display: flex;
      justify-content: space-between;
      border-bottom: 1px dashed var(--border);
      padding: 6px 0;
      font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
    }
    .tag {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-left: 8px;
    }
    .match {
      color: var(--accent);
      font-weight: 700;
    }
    .empty {
      color: var(--muted);
      font-family: "Spectral", "Georgia", serif;
    }
  </style>
</head>
<body>
  <main>
    <h1>Hello, world!</h1>
    <p class="lead">This HTTPS page shows the active configuration for the requested domain.</p>
    <section>
      <h2>Domain configuration</h2>
      <table>
        <tr><th>Lookup domain</th><td>{{if .Domain}}{{.Domain}}{{else}}(none){{end}}</td></tr>
        <tr><th>Request host</th><td>{{if .Host}}{{.Host}}{{else}}(none){{end}}</td></tr>
        <tr><th>TLS SNI</th><td>{{if .SNI}}{{.SNI}}{{else}}(none){{end}}</td></tr>
        <tr><th>Matched route</th><td>{{if .MatchType}}{{.MatchType}} {{.MatchPattern}}{{else}}none{{end}}</td></tr>
        <tr><th>Backend target</th><td>{{if .Backend}}<code>{{.Backend}}</code>{{else}}(none){{end}}</td></tr>
      </table>
    </section>
    <section>
      <h2>Configured routes</h2>
      {{if .Routes}}
      <ul>
        {{range .Routes}}
        <li>
          <span>{{.Host}}{{if .IsMatch}}<span class="tag match">match</span>{{end}}</span>
          <code>{{.Target}}</code>
        </li>
        {{end}}
      </ul>
      {{else}}
      <div class="empty">No routes configured.</div>
      {{end}}
    </section>
  </main>
</body>
</html>
`))

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
	addr, _, _ := matchRoute(routes, sni)
	return addr
}

func matchRoute(routes map[string]string, sni string) (string, string, string) {
	// exact match first
	if sni != "" {
		if v, ok := routes[sni]; ok {
			return v, sni, "exact"
		}
		// wildcard suffix matches like *.example.com
		for k, v := range routes {
			if strings.HasPrefix(k, "*.") {
				suffix := strings.TrimPrefix(k, "*") // ".example.com"
				if strings.HasSuffix(sni, suffix) {
					return v, k, "wildcard"
				}
			}
		}
	}

	// default
	if v, ok := routes["*"]; ok {
		return v, "*", "default"
	}
	return "", "", ""
}
