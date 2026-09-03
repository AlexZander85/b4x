// DialPolicy controls how fxvpn sockets reach the endpoint (addendum §18
// requirements extend to this transport: base sockets MUST carry an explicit
// SO_MARK and/or SO_BINDTODEVICE so they can never recurse into a tunnel of
// our own making; no silent fallback to an unmarked socket).
//
// Zero-value policy means "no routing constraint": used by unit tests and
// non-Linux builds. A production instance MUST set FwMark or BindToDevice;
// on platforms where a constrained policy cannot be applied every dial and
// listen fails closed.
package fxvpn

import (
        "context"
        "net"
        "syscall"
        "time"
)

const policyDialTimeout = 10 * time.Second

// DialPolicy is applied via net.Dialer/net.ListenConfig Control right after
// socket() and before connect/bind.
type DialPolicy struct {
        // FwMark sets SO_MARK (Linux); value opaque here by design.
        FwMark uint32
        // BindDevice pins the socket to the named interface (SO_BINDTODEVICE).
        BindDevice string
        // RequireMark fails closed when mark application is not possible.
        RequireMark bool
        // TTL caps the socket's IP hop limit (IP_TTL / IPV6_UNICAST_HOPS) —
        // the preflight-fake bait dies in transit by design (masquerade
        // §7.4.1); zero keeps the OS default. Only ever set on the THROWAWAY
        // fake socket: TTL tricks on a live flow are forbidden (§7.8.2).
        TTL int
        // BaseDial routes the TCP leg through an active base tunnel — the
        // carrier-nesting seam of §7.5 (FX-M2). nil = direct egress. The
        // carrier leg is deliberately NOT SO_MARKed: the outer tunnel applies
        // its own egress discipline, and double-obfuscating it would be a
        // marker of its own (§7.8.3).
        BaseDial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// dialTCP performs one TCP connect per policy: through the carrier when
// nested (BaseDial), otherwise the constrained direct dialer with the
// caller's timeout.
func (p DialPolicy) dialTCP(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
        if p.BaseDial != nil {
                // Carrier leg: the outer tunnel owns its own egress discipline
                // (SO_MARK double-tagging would be a marker of its own, §7.8.3).
                return p.BaseDial(ctx, network, addr)
        }
        dd := p.Dialer()
        dd.Timeout = timeout
        return dd.DialContext(ctx, network, addr)
}

// applyControl implements the platform hook.
func (p DialPolicy) applyControl(_ string, _ string, c syscall.RawConn) error {
        return applyControlPlatform(p, c)
}

// Dialer returns a net.Dialer carrying this policy (TCP branch: H2 tunnels).
func (p DialPolicy) Dialer() *net.Dialer {
        return &net.Dialer{
                Timeout: policyDialTimeout,
                ControlContext: func(_ context.Context, network, address string, c syscall.RawConn) error {
                        return p.applyControl(network, address, c)
                },
        }
}

// ListenConfig returns a net.ListenConfig carrying this policy (UDP branch:
// H3 carrier socket handed to quic.Transport/quic.Dial).
func (p DialPolicy) ListenConfig() *net.ListenConfig {
        return &net.ListenConfig{
                Control: func(_ string, _ string, c syscall.RawConn) error {
                        return p.applyControl("", "", c)
                },
        }
}

// Constrained reports whether the policy actually pins the path.
func (p DialPolicy) Constrained() bool {
        return p.FwMark != 0 || p.BindDevice != ""
}

// ttlActive reports whether the policy caps the hop limit (the throwaway
// preflight-fake socket; masquerade §7.4.1).
func (p DialPolicy) ttlActive() bool { return p.TTL > 0 }
