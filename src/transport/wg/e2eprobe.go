// PATCH-10 (WG MINOR 14 / A5): the ironclad-lite E2E probe builder.
//
// The DNS trust gate alone cannot distinguish a real CF edge from an
// on-path injector that forges DNS replies with the correct TXID. The
// E2E probe closes that hole: an HTTP GET /cdn-cgi/trace THROUGH the
// established tunnel must answer with a trace body containing warp=on
// (twice, per the double-measurement design). Failure is a STRUCTURAL
// gate failure (fail-closed), never a warning.
//
// The prod-wiring level flips TrustGate.E2EProbeEnabled for netstack-mode
// sessions; the kernel-TUN probe stays a field-layer concern.
//
// bd b4x-wh6/FIELD2 phase E: the exchange dials the LITERAL 1.1.1.1:443 over
// TLS — netstack v1 cannot resolve host names (b4x-4cl) and 1.1.1.1:80 answers
// 301, so plain HTTP is unusable. The body is optionally reported through
// NetstackE2EProbeWithTrace so the caller can read loc=/colo= (the pool ->
// country mapping).
package transportwg

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
)

// traceDialFunc is the raw-TCP dial seam (satisfied by the netstack's
// DialContext; kept untyped here to avoid importing gvisor into the probe).
type traceDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// E2E trace constants (Cloudflare /cdn-cgi/trace contract). The host is a
// LITERAL IPv4 and the transport is TLS: netstack v1 needs a literal target
// (b4x-4cl) and 1.1.1.1:80 only redirects (301).
const (
	tracePath     = "/cdn-cgi/trace"
	traceHost     = "1.1.1.1"
	tracePort     = "443"
	traceAttempts = 2 // double measurement (warp=on|plus design)
)

// traceTLSConfig builds the trace client's TLS config. Production verifies the
// certificate (1.1.1.1 carries an IP SAN); tests override it to trust an
// httptest certificate.
var traceTLSConfig = func() *tls.Config { return &tls.Config{} }

// NetstackE2EProbe builds the gate's E2E probe over a TCP dial seam: two
// /cdn-cgi/trace GET exchanges; every response must carry warp=on (a plus
// trace also contains warp=on — the plan's on|plus double shot). Any error,
// non-200, or missing mark is a structural failure.
func NetstackE2EProbe(dial traceDialFunc, localV4 [4]byte) E2EProbe {
	return NetstackE2EProbeWithTrace(dial, localV4, nil)
}

// NetstackE2EProbeWithTrace is NetstackE2EProbe with an optional body sink:
// onTrace receives the raw /cdn-cgi/trace body of every successful exchange
// (nil-safe). FIELD2 phase E reads loc=/colo=/warp= from it.
func NetstackE2EProbeWithTrace(dial traceDialFunc, localV4 [4]byte, onTrace func(string)) E2EProbe {
	return func(ctx context.Context) error {
		_ = localV4 // kept in the signature for symmetric seam evolution
		for i := 0; i < traceAttempts; i++ {
			body, err := oneTraceExchange(ctx, dial)
			if err != nil {
				return fmt.Errorf("trace[%d]: %w", i, err)
			}
			if onTrace != nil {
				onTrace(body)
			}
		}
		return nil
	}
}

// oneTraceExchange performs one HTTPS GET /cdn-cgi/trace through the tunnel and
// validates the warp=on mark, returning the RAW body (headers + payload).
func oneTraceExchange(ctx context.Context, dial traceDialFunc) (string, error) {
	conn, err := dial(ctx, "tcp", net.JoinHostPort(traceHost, tracePort))
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	cfg := traceTLSConfig()
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = traceHost
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("tls: %w", err)
	}

	req := "GET " + tracePath + " HTTP/1.1\r\n" +
		"Host: " + traceHost + "\r\n" +
		"User-Agent: b4-e2e-probe\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}

	reader := bufio.NewReader(tc)
	status, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("status: %w", err)
	}
	if !strings.Contains(status, "200") {
		return "", fmt.Errorf("trace status %q, want 200", strings.TrimSpace(status))
	}
	// Connection: close makes EOF the natural terminator; headers and body
	// are scanned together for the warp=on mark.
	rest, err := io.ReadAll(reader)
	if err != nil && len(rest) == 0 {
		return "", fmt.Errorf("read: %w", err)
	}
	body := string(rest)
	if !strings.Contains(body, "warp=on") {
		return "", fmt.Errorf("trace answer lacks warp=on (spoofed edge?)")
	}
	return body, nil
}
