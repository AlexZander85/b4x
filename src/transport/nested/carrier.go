// Carrier contract (design §1): one abstract "носитель" on the OUTER side.
// Any outer×inner pair is assembled from engines behind these three methods;
// the matrix layer never branches on transports, only on data-plane modes.
package nested

import (
        "context"
        "errors"
        "net"
        "net/netip"
        "time"
)

// NestedCarrier is the minimal proof-carrying surface every OUTER mode
// provides to the INNER layer (design §1):
//
//   - InjectUDPDatagram pushes ONE datagram toward dst as if sent from
//     inside the outer tunnel (WG/AWG handshake and transport traffic);
//   - DialTCPThrough opens one TCP stream to dst through the outer tunnel
//     (MASQUE-inner control socket, W+M);
//   - ProofSnapshot names the evidence that traffic really traverses the
//     outer (pin verification, live netstack, capsule counters). ok=false
//     means "carrier unproven": consumers must fail closed.
type NestedCarrier interface {
        InjectUDPDatagram(dst netip.AddrPort, payload []byte) error
        DialTCPThrough(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
        ProofSnapshot() (proof string, ok bool)
}

// UDPSession is the minimal bidirectional surface relay-based inner layers
// need (the transportwg Backend-B LoopbackForwarder seam): connected UDP
// semantics whose Write injects into the outer and whose Read yields the
// matching replies.
type UDPSession interface {
        Write(b []byte) (int, error)
        Read(b []byte) (int, error)
        Close() error
}

// UDPSessionCarrier is carried by every outer mode: kernel pins and the
// netstack back it with real sockets, the MASQUE datagram plane with its
// tuple demux. A returned net.Conn satisfies UDPSession structurally.
type UDPSessionCarrier interface {
        DialUDPThrough(ctx context.Context, dst netip.AddrPort) (UDPSession, error)
}

// Structural event classes (design §5). They are carried verbatim in
// Event.Class so diagnostics can reason about nested failures without
// parsing free text.
const (
        ClassCarrierRouteLost     = "nested/carrier-route-lost"
        ClassPinRestored          = "nested/pin-restored"
        ClassEdgeCollision        = "nested/edge-collision"
        ClassInnerVersionMismatch = "nested/inner-version-mismatch"
)

// Child lifecycle taxonomy (PATCH-07, M-14). ClassCarrierRouteLost stays
// strictly for kernel-route incidents emitted by kernelroute*.go; child
// start/teardown outcomes carry their own classes so route diagnostics and
// the RouteLostTotal counter never absorb unrelated failures. Values keep
// the historical "wg_nested_*" spelling consumed by the field tooling.
const (
        // ClassChildStartFailed: the inner layer failed to start (carrier build,
        // supervisor construction or first start). Not a route incident.
        ClassChildStartFailed = "wg_nested_child_start_failed"
        // ClassChildInvalidated: the inner layer was invalidated (parent loss or
        // start-failure aftermath). Not a route incident.
        ClassChildInvalidated = "wg_nested_child_invalidated"
)

// Event is one structured composition event (supervisor-sink contract:
// non-blocking consumer, never called synchronously from Stop).
type Event struct {
        Class  string // ClassCarrierRouteLost … or engine-native class
        Reason string
        At     time.Time
}

// Errors shared by all carriers. Every failure is structural: callers
// classify with errors.Is, never by string match.
var (
        // ErrCarrierUnproven: an operation was attempted while the carrier has
        // no verified path (fail-closed; design red line #1/#2).
        ErrCarrierUnproven = errors.New("nested: carrier path not proven")
        // ErrCarrierClosed: the carrier is stopped or tearing down.
        ErrCarrierClosed = errors.New("nested: carrier closed")
        // ErrNoTCPCarrier: this outer mode cannot carry TCP streams at all
        // (MASQUE CONNECT-IP carries IP datagrams; a userspace TCP stack is
        // bd b4x-9aa). Callers must treat it as BLOCKED_CARRIER semantics —
        // a structural limitation, not a network failure.
        ErrNoTCPCarrier = errors.New("nested: outer mode carries no TCP streams")
        // ErrFamilyUnsupported: the requested address family has no carrier
        // path and the family policy says mandatory (v4 default).
        ErrFamilyUnsupported = errors.New("nested: address family unsupported by carrier")
)

// FamilyPolicy encodes the asymmetric criticality of address families
// (design §1.1, zapret-gui :296-330): a failed v6 pin is a warning, a
// failed v4 pin rolls the whole setup back.
//
// Zero value = NO family mandatory (explicit opt-in posture); production
// wiring sets RequireV4 explicitly - no silent default flip.
type FamilyPolicy struct {
        // RequireV4: a failed v4 pin fails the setup and rolls it back.
        RequireV4 bool
        // AttemptV6: try a v6 pin too; failure = warning event only.
        AttemptV6 bool
}
