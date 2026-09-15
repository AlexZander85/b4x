package torservice

// The reserve.Carrier contract (design §9.1): kind "tor", priority 5 (the
// registry-side constant), TCP-only with an honest SupportsUDP=false —
// UDP-scope traffic must NEVER route into a TCP-only reserve (the red
// line; DialUDP refuses). DialStream dials through tor's SOCKS listener
// with the hostname passing through UNRESOLVED (atypDomain — `.onion`
// never touches a resolver, the tessera TorSocksDialer canon). Before
// bootstrap the carrier refuses with ErrNotListening instead of hanging.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/socks5"
	"github.com/daniellavrushin/b4/transport/tor"
)

// Kind returns the reserve kind (registry contract).
func (r *Runtime) Kind() reserve.Kind { return reserve.KindTor }

// SupportsUDP is the honest refusal: tor carries TCP streams only.
func (r *Runtime) SupportsUDP() bool { return false }

// DialUDP refuses: a TCP-only reserve never takes UDP scopes (fail-closed
// at the carrier, not at some distant router).
func (r *Runtime) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return nil, fmt.Errorf("torservice: UDP is not supported by the tor reserve (TCP-only by design)")
}

// DialStream dials ONE TCP stream to addr THROUGH tor's SOCKS listener.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return r.dialStreamTarget(ctx, addr.Addr().String(), addr.Port(), "")
}

// HostCarrier is the optional scoped-router seam for name-based scopes
// (`.onion` and domain scopes — design §9.1, phase 2 consumers): the
// hostname rides the SOCKS exchange unresolved. No consumers yet; the
// declaration + implementation land together, honestly unused.
type HostCarrier interface {
	DialStreamHost(ctx context.Context, host string, port uint16) (net.Conn, error)
}

// DialStreamHost implements HostCarrier.
func (r *Runtime) DialStreamHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if strings.HasSuffix(strings.ToLower(host), ".onion") && len(host) > len(".onion") {
		// onion hostnames pass unresolved (no DNS touch, no leak)
		return r.dialStreamTarget(ctx, host, port, "")
	}
	// non-onion hostnames: resolve through the egress DoH resolver then
	// dial by address (the scoped router's future domain scopes)
	if r.dialer == nil {
		return nil, tor.ErrNotListening
	}
	if r.hostResolve == nil {
		return nil, fmt.Errorf("torservice: hostname resolution not wired")
	}
	addrs, err := r.hostResolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("torservice: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("torservice: no addresses for %q", host)
	}
	return r.dialStreamTarget(ctx, addrs[0].String(), port, "")
}

// dialStreamTarget performs the SOCKS exchange through tor's listener.
func (r *Runtime) dialStreamTarget(ctx context.Context, host string, port uint16, _ string) (net.Conn, error) {
	r.mu.Lock()
	socks := r.socksAddr
	state := r.state
	r.mu.Unlock()
	if socks == "" || (state != StateEstablished && state != StateRotating) {
		return nil, tor.ErrNotListening
	}
	// self-loop guard: never dial our own listeners through ourselves
	if r.isSelfTarget(host, port) {
		return nil, tor.ErrTorSelfLoop
	}
	sHost, sPort, err := net.SplitHostPort(socks)
	if err != nil {
		return nil, fmt.Errorf("torservice: socks addr: %w", err)
	}
	p := 0
	if _, err := fmt.Sscanf(sPort, "%d", &p); err != nil {
		return nil, fmt.Errorf("torservice: socks port: %w", err)
	}
	cfg := socks5.ClientConfig{Host: sHost, Port: p, Timeout: 15 * time.Second}
	return socks5.DialUpstream(ctx, cfg, host, int(port))
}

// isSelfTarget checks the runtime's own listener set.
func (r *Runtime) isSelfTarget(host string, port uint16) bool {
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	r.mu.Lock()
	defer r.mu.Unlock()
	candidates := []string{target}
	if r.egressBridge != nil {
		candidates = append(candidates, r.egressBridge.Addr())
	}
	if r.ptProxy != nil {
		candidates = append(candidates, r.ptProxy.Addr())
	}
	if r.socksAddr != "" {
		candidates = append(candidates, r.socksAddr)
	}
	for i := 1; i < len(candidates); i++ {
		if candidates[i] == target {
			return true
		}
	}
	return false
}

var (
	_ reserve.Carrier = (*Runtime)(nil)
	_ HostCarrier     = (*Runtime)(nil)
)
