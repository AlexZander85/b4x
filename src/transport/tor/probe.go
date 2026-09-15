package tor

// Liveness probes per transport (design §4.2, research-nova-tor §F): the
// probes are deliberately DIFFERENT per transport family because "alive"
// means different things:
//
//	obfs4/vanilla — a TCP connect to the OR endpoint (6 s) proves the
//	                 bridge box answers SYN;
//	webtunnel     — a WebSocket upgrade GET over raw HTTP/1.1 (strictly
//	                 1.1: RFC 6455 Upgrade is forbidden over h2 — a h2-only
//	                 endpoint can never serve a webtunnel bridge, measured
//	                 0 of 8 alive) expecting `101 Switching Protocols`,
//	                 no redirects, ALPN http/1.1;
//	snowflake     — ANY HTTP status from the rendezvous place ("the
//	                 broker root answers 404 or 502 depending on the
//	                 weather") — probed plain, the uTLS/fronting happens
//	                 inside the transport.
//
// All dials go through the injected egress dial seam (classes bridge-pt /
// bridge-vanilla / rendezvous) so probes never leak outside the egress
// policy and never travel through tor itself.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ProbeDial is the egress dial seam for probes (production: the runtime's
// egress Dialer.Dial).
type ProbeDial func(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error)

// Probe timeouts and budgets (design §4.2: per-transport budgets 16 TCP /
// 8 webtunnel upgrades / snowflake uncapped; overall 60 s; pool 8).
const (
	ProbeTCPTimeout      = 6 * time.Second
	ProbeWebtunnelBudget = 8
	ProbeTCPBudget       = 16
	ProbeSnowflakeBudget = 0 // uncapped by design
	ProbeOverallTimeout  = 60 * time.Second
	ProbePoolSize        = 8
)

// ProbeTCP reports whether the endpoint answers a TCP connect.
func ProbeTCP(ctx context.Context, dial ProbeDial, class ConnClass, host string, port uint16) bool {
	if dial == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, ProbeTCPTimeout)
	defer cancel()
	conn, err := dial(cctx, class, host, port)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ProbeWebtunnel performs the WebSocket upgrade check against the bridge's
// url= host: raw HTTP/1.1 GET with RFC 6455 upgrade headers, TLS with ALPN
// http/1.1 when the URL is https, expecting exactly `101 Switching
// Protocols`. Redirects are NOT followed (a redirecting front is not a
// webtunnel bridge). A h2-only answer fails the status line check by
// construction.
func ProbeWebtunnel(ctx context.Context, dial ProbeDial, rawURL string) bool {
	if dial == nil {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	port := uint16(0)
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
		port = uint16(n)
	} else if strings.EqualFold(u.Scheme, "https") {
		port = 443
	} else {
		port = 80
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	cctx, cancel := context.WithTimeout(ctx, ProbeTCPTimeout)
	defer cancel()
	conn, err := dial(cctx, ClassBridgePT, host, port)
	if err != nil {
		return false
	}
	defer conn.Close()
	if strings.EqualFold(u.Scheme, "https") {
		tc := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // liveness probe, not WebPKI validation
			NextProtos:         []string{"http/1.1"},
		})
		if err := tc.HandshakeContext(cctx); err != nil {
			return false
		}
		conn = tc
	}

	key := make([]byte, 16)
	_, _ = rand.Read(key)
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
		"\r\n"
	_ = conn.SetDeadline(time.Now().Add(ProbeTCPTimeout))
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
	if err != nil {
		return false
	}
	// strictly HTTP/1.1 + 101: an h2 answer would not carry "HTTP/1.1 101"
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return false
	}
	if !strings.HasPrefix(parts[0], "HTTP/1.1") && parts[0] != "HTTP/1.0" {
		return false
	}
	if parts[0] != "HTTP/1.1" {
		return false // h2 or unknown: not a webtunnel-capable front
	}
	return parts[1] == "101"
}

// ProbeRendezvous reports whether the snowflake rendezvous place answers
// with ANY HTTP status (404/502 count as alive — G165/G202 canon).
func ProbeRendezvous(ctx context.Context, client *http.Client, rawURL string) bool {
	if client == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, ProbeTCPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return true // any status code counts
}

// ProbeBridge dispatches the per-transport probe for one parsed bridge and
// reports alive. Decoration endpoints are never dialed (webtunnel/snowflake
// identifiers) — their liveness is decided by the URL/rendezvous probes or
// the set chooser.
func ProbeBridge(ctx context.Context, dial ProbeDial, client *http.Client, b Bridge) bool {
	switch b.Transport {
	case "obfs4", "vanilla":
		host, portStr, err := net.SplitHostPort(b.AddrPort)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return false
		}
		class := ClassBridgePT
		if b.Transport == "vanilla" {
			class = ClassBridgeVanilla
		}
		return ProbeTCP(ctx, dial, class, host, uint16(port))
	case "webtunnel":
		raw := b.Args["url"]
		if raw == "" {
			return false
		}
		return ProbeWebtunnel(ctx, dial, raw)
	case "snowflake":
		// decoration endpoint: the rendezvous probe covers the set choice;
		// a per-bridge probe would re-probe the same broker for every line.
		return true
	case "meek_lite":
		// owner-only transport: front reachability is the transport's own
		// runtime concern; the collector never has a live source to probe.
		return true
	default:
		return false
	}
}

// probeClassBudget maps a transport to its probe budget (design §4.2).
func probeClassBudget(transport string) int {
	switch transport {
	case "obfs4", "vanilla":
		return ProbeTCPBudget
	case "webtunnel":
		return ProbeWebtunnelBudget
	case "snowflake", "meek_lite":
		return ProbeSnowflakeBudget
	default:
		return 0
	}
}
