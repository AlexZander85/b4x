// Shared data-plane contracts for the fxvpn CONNECT tunnels (both carriers):
// the opener interface supervisors program against, per-attempt budgets, the
// non-2xx CONNECT verdict, and the reference's session-unhealthy heuristic
// (>=3 DISTINCT target authorities in a row timing out or answering 502;
// any success or other error class resets the counters — main.go:1479-1522).
package fxvpn

import (
        "context"
        "crypto/tls"
        "errors"
        "fmt"
        "net"
        "strconv"
        "sync"
        "time"
)

var (
        // ErrSessionUnhealthy marks the tracker threshold: the SESSION (not one
        // target) is dead; the supervisor must recycle it, not retry targets.
        ErrSessionUnhealthy = errors.New("fxvpn: proxy session unhealthy")

        errUDPEgressBlocked    = errors.New("fxvpn: udp egress blocked (handshake blackhole)")
        errH3NegotiationFailed = errors.New("fxvpn: h3 negotiation failed")
)

// Carriers for events/metrics.
const (
        CarrierH2 = "h2"
        CarrierH3 = "h3"
)

// TunnelOpener is one established upstream proxy session (either carrier).
type TunnelOpener interface {
        // OpenTunnel connects through the proxy to authority ("host:port").
        // A returned net.Conn carries the raw relay bytes bidirectionally.
        OpenTunnel(ctx context.Context, authority string) (net.Conn, error)
        // UpdateToken swaps the bearer credential IN PLACE (proxy-pass renew,
        // lead 2 min before exp): subsequent tunnels use it, live streams are
        // untouched (reference UpdateToken semantics).
        UpdateToken(token string) error
        // IsAlive reports whether new tunnels may be opened on this session.
        IsAlive() bool
        Close() error
}

// TunnelConfig parameterizes one session dial. Zero durations fall back to
// defaults via fillDefaults.
type TunnelConfig struct {
        Host   string
        Port   int
        Token  string      // initial proxy pass JWT (raw)
        Policy DialPolicy  //
        TLS    *tls.Config // optional BASE config (test/bootstrap seam: RootCAs,
        // InsecureSkipVerify for fake stands). Carrier knobs (MinVersion,
        // NextProtos, ServerName) are enforced on top and cannot be relaxed.
        HandshakeBudget time.Duration // TCP/TLS or QUIC/session establishment
        OpenBudget      time.Duration // one CONNECT round trip
        // Resolver resolves the edge HOSTNAME for the UDP carrier (review F2:
        // the server list serves names, H3 dials IPs). nil = net.DefaultResolver.
        // The SNI stays the NAME regardless of the resolved address.
        Resolver resolver
}

// resolver is the lookup seam (*net.Resolver satisfies it); a narrow local
// alias keeps the fake-stand tests free of DNS plumbing.
type resolver interface {
        LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

func (c *TunnelConfig) fillDefaults() {
        if c.HandshakeBudget <= 0 {
                c.HandshakeBudget = 15 * time.Second
        }
        if c.OpenBudget <= 0 {
                c.OpenBudget = 20 * time.Second
        }
}

// Authority renders host:port (RFC 3986 bracketing for IPv6 literals).
func (c *TunnelConfig) Authority() string {
        return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// ConnectRejectedError is a completed CONNECT round trip that the edge
// answered with a non-2xx status.
type ConnectRejectedError struct {
        StatusCode int
        Status     string
        Body       string
}

func (e *ConnectRejectedError) Error() string {
        return fmt.Sprintf("fxvpn: connect rejected: HTTP %d %s", e.StatusCode, e.Body)
}

// IsQuota reports the data-plane quota signal: the edge answering 429 on
// CONNECT means the account's proxy quota is exhausted server-side even if
// local X-Quota-* bookkeeping lagged.
func (e *ConnectRejectedError) IsQuota() bool { return e.StatusCode == 429 }

// failureTracker implements the reference health heuristic verbatim in
// shape: distinct-authority streaks of timeouts and 502s, threshold 3,
// mutual reset between classes, success clears both.
type failureTracker struct {
        mu                 sync.Mutex
        openTimeoutTargets map[string]struct{}
        badGatewayTargets  map[string]struct{}
}

// observe records one OpenTunnel outcome for authority. Returned error is
// err itself, except when the threshold trips: then it is a chain ending in
// ErrSessionUnhealthy so callers can branch without losing the cause.
func (t *failureTracker) observe(authority string, kind string, err error) error {
        if err == nil && kind == "" {
                t.mu.Lock()
                t.openTimeoutTargets = nil
                t.badGatewayTargets = nil
                t.mu.Unlock()
                return nil
        }
        t.mu.Lock()
        defer t.mu.Unlock()
        switch kind {
        case "timeout":
                if t.openTimeoutTargets == nil {
                        t.openTimeoutTargets = make(map[string]struct{})
                }
                t.openTimeoutTargets[authority] = struct{}{}
                t.badGatewayTargets = nil
                if len(t.openTimeoutTargets) >= 3 {
                        return fmt.Errorf("%w: %w", ErrSessionUnhealthy, err)
                }
        case "bad-gateway":
                if t.badGatewayTargets == nil {
                        t.badGatewayTargets = make(map[string]struct{})
                }
                t.badGatewayTargets[authority] = struct{}{}
                t.openTimeoutTargets = nil
                if len(t.badGatewayTargets) >= 3 {
                        return fmt.Errorf("%w: %w", ErrSessionUnhealthy, err)
                }
        default:
                t.openTimeoutTargets = nil
                t.badGatewayTargets = nil
        }
        return err
}
