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
package transportwg

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
)

// traceDialFunc dials one TCP conn through the tunnel's stack.
type traceDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// nsTCPDial adapts a netstack.Net's DialContext to the trace dialer seam
// (kept untyped here to avoid importing gvisor into the probe; the session
// wiring passes ns.DialContext directly).
//
// E2E trace constants (Cloudflare /cdn-cgi/trace contract).
const (
	tracePath     = "/cdn-cgi/trace"
	traceHost     = "www.cloudflare.com"
	traceAttempts = 2 // double measurement (warp=on|plus design)
)

// NetstackE2EProbe builds the gate's E2E probe over a TCP dial seam: two
// /cdn-cgi/trace GET exchanges; every response must carry warp=on (a plus
// trace also contains warp=on — the plan's on|plus double shot). Any error,
// non-200, or missing mark is a structural failure.
func NetstackE2EProbe(dial traceDialFunc, localV4 [4]byte) E2EProbe {
	return func(ctx context.Context) error {
		// 192.0.2.1 is the RFC 5737 TEST-NET-1 anycast surrogate the engine
		// rewrites through the tunnel's resolver; prod wiring may override
		// by dialing through its own resolver. Here: direct host dial.
		addr := netip.AddrPortFrom(netip.AddrFrom4(localV4), 0)
		_ = addr // localV4 kept in the signature for symmetric seam evolution
		for i := 0; i < traceAttempts; i++ {
			if err := oneTraceExchange(ctx, dial); err != nil {
				return fmt.Errorf("trace[%d]: %w", i, err)
			}
		}
		return nil
	}
}

// oneTraceExchange performs one HTTP/1.1 GET /cdn-cgi/trace and validates
// the warp=on mark in the body.
func oneTraceExchange(ctx context.Context, dial traceDialFunc) error {
	conn, err := dial(ctx, "tcp", net.JoinHostPort(traceHost, "80"))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	req := "GET " + tracePath + " HTTP/1.1\r\n" +
		"Host: " + traceHost + "\r\n" +
		"User-Agent: b4-e2e-probe\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if !strings.Contains(status, "200") {
		return fmt.Errorf("trace status %q, want 200", strings.TrimSpace(status))
	}
	// Connection: close makes EOF the natural terminator; headers and body
	// are scanned together for the warp=on mark.
	rest, err := io.ReadAll(reader)
	if err != nil && len(rest) == 0 {
		return fmt.Errorf("read: %w", err)
	}
	if !strings.Contains(string(rest), "warp=on") {
		return fmt.Errorf("trace answer lacks warp=on (spoofed edge?)")
	}
	return nil
}
