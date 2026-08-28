// Instance-level transport ladder H3→H2 (E-H3 design §6, continuation prompt
// EH3): one MASQUE instance prefers the QUIC/H3 carrier and falls back to the
// H2 carrier of the SAME endpoint profile only on CONFIRMED failure classes
// (udp-egress-blocked / handshake-fail family produced by
// classifyH3HandshakeError, plus the data-plane-validation timeout — the
// design §6 "handshake-ok-but-silent" case). Every switch emits a structured
// trace event with the reason; there are NO silent transport changes.
//
// Anti-oscillation contract (the acceptance criterion): after a confirmed H3
// failure the dialer blocks H3 until H3ReturnCooldown elapses. While blocked,
// generations dial H2 directly — zero H3 attempts, zero switch events. H3 is
// retried only once the cooldown has expired inside the supervisor's normal
// cooldown cycle (backoff pause between generations), so N ticks against a
// live H2 edge and a dead H3 edge produce exactly ONE transport_switched.
//
// tls-pin-mismatch is deliberately NOT a switch class: it is a fail-closed
// identity verdict (the H2 carrier of the same endpoint presents the same
// pinned key), and silently degrading transport on a pin violation would
// mask an attack indicator.
package transportwarp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Carrier identifiers used in events, scores and metrics.
const (
	TransportH2 = "h2"
	TransportH3 = "h3"
)

// packetTransport is the common live-session contract shared by the H2 and
// H3 carriers. Both concrete sessions satisfy it (compile-time assertions
// below); supervisors and discovery bursts program against it.
type packetTransport interface {
	WritePacket([]byte) error
	ReadPacket(context.Context) ([]byte, error)
	TryRead() ([]byte, bool, error)
	ValidateDataPlane(context.Context) error
	SubscribePackets() (<-chan []byte, func())
	Done() <-chan struct{}
	Close() error
}

var (
	_ packetTransport = (*Session)(nil)
	_ packetTransport = (*H3Session)(nil)
)

// TransportAttempt is the structured outcome of one generation's carrier
// selection. Events are emitted BY THE SUPERVISOR right after Dial returns
// (single emit path; the dialer never touches the sink directly).
type TransportAttempt struct {
	// Transport identifies the carrier of the returned session (or of the
	// last attempt when the generation failed outright).
	Transport string
	// Result carries the unified ConnectResult fields. H3ConnectResult maps
	// 1:1 (identical field sets), so traces keep one shape per phase.
	Result ConnectResult
	// Events carries ladder events produced while dialing
	// (warp_transport_switched / warp_h3_negotiated).
	Events []SupervisorEvent
}

// TransportDialer picks and establishes the carrier for one supervisor
// generation. The returned session is ESTABLISHED but NOT yet trusted;
// the supervisor owns ValidateDataPlane and MUST feed the outcome back
// through ObserveValidation (this is how the ladder learns the
// control-ok-but-data-dead case).
type TransportDialer interface {
	Dial(ctx context.Context, scfg SessionConfig) (packetTransport, TransportAttempt, error)
	ObserveValidation(transport string, validationErr error) []SupervisorEvent
}

// BootstrapCover arms/releases the fake-QUIC NFQ profile around an H3
// establishment window (EH5). Arm must be called before the H3 dial;
// Release fires on every terminal outcome — including AFTER a passed trust
// gate (established ⇒ camouflage off, §C.4 semantics).
type BootstrapCover interface {
	Arm() error
	Release(reason string)
}

// LadderConfig tunes NewH3FirstDialer. Zero durations fall back to defaults;
// the Dial hooks exist for deterministic tests and MUST stay nil outside
// them (documented test-only seam, same discipline as CandidatesOverride).
type LadderConfig struct {
	// H3ReturnCooldown blocks H3 re-attempts after a confirmed failure.
	H3ReturnCooldown time.Duration // default 300s (aligned with RestartCooldown)
	OpenStreamBudget time.Duration // default DefaultH3OpenStreamBudget

	Now func() time.Time

	// DialH3/DialH2 replace the real carriers. TESTS ONLY: production must
	// leave both nil.
	DialH3 func(context.Context, H3SessionConfig) (*H3Session, H3ConnectResult, error)
	DialH2 func(context.Context, SessionConfig) (*Session, ConnectResult, error)

	// Cover optionally wraps every H3 establishment in the fake-QUIC
	// bootstrap profile (nil = no cover).
	Cover BootstrapCover
}

func (c *LadderConfig) fillDefaults() {
	if c.H3ReturnCooldown <= 0 {
		c.H3ReturnCooldown = 300 * time.Second
	}
	if c.OpenStreamBudget <= 0 {
		c.OpenStreamBudget = DefaultH3OpenStreamBudget
	}
}

func (c *LadderConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// H3FirstDialer is the production TransportDialer implementing the ladder.
type H3FirstDialer struct {
	cfg LadderConfig

	mu             sync.Mutex
	h3BlockedUntil time.Time

	h3Dials      map[string]uint64 // by result class ("ok" on success)
	fallbackH2N  uint64
	switchEvents uint64
}

// NewH3FirstDialer validates the config shape and returns the ladder.
func NewH3FirstDialer(cfg LadderConfig) (*H3FirstDialer, error) {
	cfg.fillDefaults()
	return &H3FirstDialer{cfg: cfg, h3Dials: map[string]uint64{}}, nil
}

// Metrics snapshots the EH4 counters (h3_dial_total{result},
// h3_fallback_to_h2_total style; named-counter convention of src/warp —
// this package stays dependency-free).
type LadderMetrics struct {
	H3DialTotal  map[string]uint64 // label result → count ("ok" | failure class)
	FallbackToH2 uint64            // h3_fallback_to_h2_total
	Switches     uint64            // emitted warp_transport_switched count
	H3Blocked    bool              // anti-oscillation gate currently closed
}

func (d *H3FirstDialer) Metrics() LadderMetrics {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := LadderMetrics{
		H3DialTotal:  make(map[string]uint64, len(d.h3Dials)),
		FallbackToH2: d.fallbackH2N,
		Switches:     d.switchEvents,
		H3Blocked:    d.cfg.now().Before(d.h3BlockedUntil),
	}
	for k, v := range d.h3Dials {
		out.H3DialTotal[k] = v
	}
	return out
}

// h3Allowed reports whether the anti-oscillation gate admits an H3 attempt.
func (d *H3FirstDialer) h3Allowed(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !now.Before(d.h3BlockedUntil)
}

// blockH3 closes the gate for the cooldown window and counts the fallback.
func (d *H3FirstDialer) blockH3(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.h3BlockedUntil = now.Add(d.cfg.H3ReturnCooldown)
	d.fallbackH2N++
}

func (d *H3FirstDialer) countH3(class string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.h3Dials[class]++
}

func (d *H3FirstDialer) countSwitch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.switchEvents++
}

// Dial implements TransportDialer.
func (d *H3FirstDialer) Dial(ctx context.Context, scfg SessionConfig) (packetTransport, TransportAttempt, error) {
	now := d.cfg.now()
	if !d.h3Allowed(now) {
		// Anti-oscillation core: straight to H2, no H3 contact, no events.
		return d.dialH2Generation(ctx, scfg)
	}

	sess, res, err := d.tryH3(ctx, scfg)
	if err == nil {
		d.countH3("ok")
		ev := SupervisorEvent{
			Name:         EvH3Negotiated,
			FailureClass: "",
			Status:       res.Status,
			DurationMS:   res.DurationMS,
			Colo:         res.Colo,
			Detail:       "transport=h3",
		}
		return sess, TransportAttempt{
			Transport: TransportH3,
			Result:    res.connectResult(),
			Events:    []SupervisorEvent{ev},
		}, nil
	}

	d.countH3(res.FailureClass)
	if errors.Is(err, ErrCoverUnavailable) {
		// Local bootstrap-cover problem is NOT a network verdict: skip H3
		// for this generation (fail closed to the proven H2 carrier) but do
		// NOT poison the gate — the very next cooldown cycle retries H3.
		d.releaseCover("arm-failed")
		return d.dialH2Generation(ctx, scfg)
	}
	d.releaseCover("h3-dial-failed")
	if !isLadderSwitchClass(res.FailureClass) {
		// Unconfirmed class (pin mismatch, 403, quota hang, negotiation…):
		// no transport degradation, no switch event — the generation fails
		// with the H3 verdict and the supervisor backoff applies.
		return nil, TransportAttempt{Transport: TransportH3, Result: res.connectResult()}, err
	}

	// Confirmed class: exactly one switch event, gate closed for cooldown.
	now = d.cfg.now()
	d.blockH3(now)
	d.countSwitch()
	ev := switchedEvent(TransportH3, TransportH2, res.FailureClass)
	ev.Status = res.Status
	ev.DurationMS = res.DurationMS
	return d.dialH2Generation(ctx, scfg, ev)
}

// ErrCoverUnavailable reports that the fake-QUIC bootstrap cover could not
// be armed (local applier failure). It is deliberately NOT a network
// verdict: the generation falls back to H2 without blocking H3.
var ErrCoverUnavailable = errors.New("transportwarp: fake-quic cover unavailable")

// tryH3 runs one H3 establishment (the carrier itself retries ×2 internally
// on the retriable family; the ladder adds no further H3 attempts).
func (d *H3FirstDialer) tryH3(ctx context.Context, scfg SessionConfig) (*H3Session, H3ConnectResult, error) {
	hcfg := h3ConfigFromSession(scfg)
	hcfg.OpenStreamBudet = d.cfg.OpenStreamBudget
	if armErr := d.armCover(); armErr != nil {
		// Cover is a hard precondition of the H3 establishment window
		// (bootstrap protection); failing OPEN by dialing bare H3 is
		// forbidden — the caller skips to H2 for this generation only.
		res := H3ConnectResult{FailureClass: "cover-arm-failed"}
		return nil, res, fmt.Errorf("%w: %v", ErrCoverUnavailable, armErr)
	}
	if d.cfg.DialH3 != nil {
		return d.cfg.DialH3(ctx, hcfg)
	}
	return DialH3Session(ctx, hcfg)
}

func (d *H3FirstDialer) armCover() error {
	if d.cfg.Cover == nil {
		return nil
	}
	return d.cfg.Cover.Arm()
}

func (d *H3FirstDialer) releaseCover(reason string) {
	if d.cfg.Cover != nil {
		d.cfg.Cover.Release(reason)
	}
}

// dialH2Generation establishes the H2 carrier of the SAME endpoint profile
// and attaches any pending ladder events to the attempt.
func (d *H3FirstDialer) dialH2Generation(ctx context.Context, scfg SessionConfig, evs ...SupervisorEvent) (packetTransport, TransportAttempt, error) {
	var sess *Session
	var res ConnectResult
	var err error
	if d.cfg.DialH2 != nil {
		sess, res, err = d.cfg.DialH2(ctx, scfg)
	} else {
		sess, res, err = DialSession(ctx, scfg)
	}
	return sess, TransportAttempt{Transport: TransportH2, Result: res, Events: evs}, err
}

// ObserveValidation implements TransportDialer. An H3 session that passed
// the control phase but failed the data-plane gate is the design §6
// "handshake-ok-but-silent" case: confirmed silent ⇒ block H3 for the
// cooldown, emit the switch event, release the cover. A PASSED validation
// releases the cover strictly after the trust gate (§C.4 cutoff).
func (d *H3FirstDialer) ObserveValidation(transport string, validationErr error) []SupervisorEvent {
	switch {
	case transport != TransportH3:
		return nil // H2 outcomes carry no ladder semantics
	case validationErr == nil:
		d.releaseCover("validated")
		return nil
	case errors.Is(validationErr, context.Canceled):
		// M-06: validation aborted by shutdown/rebalance is NOT a "handshake-ok-
		// but-silent" verdict. Ignore it: no switch event, no blockH3 cooldown.
		d.releaseCover("validation-aborted")
		return nil
	default:
		d.releaseCover("validation-failed")
	}
	now := d.cfg.now()
	d.blockH3(now)
	d.countSwitch()
	ev := switchedEvent(TransportH3, TransportH2, FailureValidation)
	return []SupervisorEvent{ev}
}

// isLadderSwitchClass reports whether a dial-phase failure class confirms
// the transport verdict strongly enough to degrade to H2. Exactly the
// handshake-fail family of classifyH3HandshakeError minus the pin verdict
// (fail-closed, never masked).
func isLadderSwitchClass(class string) bool {
	switch class {
	case FailureUDPEgressBlocked, FailureTLSAlert:
		return true
	default:
		return false
	}
}

func switchedEvent(from, to, reason string) SupervisorEvent {
	return SupervisorEvent{
		Name:         EvTransportSwitched,
		FailureClass: reason,
		Detail:       "from=" + from + " to=" + to + " reason=" + reason,
	}
}

// h3ConfigFromSession derives the H3 carrier config from the shared
// endpoint profile (SNI/pins/policy/local address/MTU/budgets travel 1:1).
func h3ConfigFromSession(s SessionConfig) H3SessionConfig {
	return H3SessionConfig{
		Endpoint:        s.Endpoint,
		SNI:             s.SNI,
		ClientKey:       s.ClientKey,
		Pin:             s.Pin,
		ExtraPins:       s.ExtraPins,
		Policy:          s.Policy,
		LocalV4:         s.LocalV4,
		MTU:             s.MTU,
		ValidateWindow:  s.ValidateWindow,
		ProbeInterval:   s.ProbeInterval,
		HandshakeBudget: s.HandshakeBudget,
	}
}

func (r H3ConnectResult) connectResult() ConnectResult {
	return ConnectResult{
		Status:       r.Status,
		DurationMS:   r.DurationMS,
		FailureClass: r.FailureClass,
		PinDigest:    r.PinDigest,
		ProtocolErr:  r.ProtocolErr,
		Colo:         r.Colo,
	}
}

// ---- fast UDP reachability probe (discovery EH3) ----

// ReachabilityClass is the outcome of the fast UDP probe. Egress block and
// handshake-path failures are DIFFERENT classes by mandate: silence over the
// whole budget (blackhole) is the egress-block verdict; a fast network
// refusal and an edge that SPOKE (any QUIC/TLS bytes came back) are
// distinct, cheaper verdicts.
type ReachabilityClass string

const (
	ReachReachable ReachabilityClass = "reachable"     // edge spoke (TLS/VN/reset)
	ReachRefused   ReachabilityClass = "udp-refused"   // fast ICMP-class refusal
	ReachBlackhole ReachabilityClass = "udp-blackhole" // budget silence ⇒ udp-egress-blocked
)

// DefaultReachabilityProbeBudget bounds the fast probe (a fraction of the
// 20s session handshake budget; design v2 per-probe ceiling is 2s).
const DefaultReachabilityProbeBudget = 1500 * time.Millisecond

// ProbeUDPReachability performs a minimal QUIC dial against ep purely to
// classify the path. The connection (if any) is torn down immediately; no
// CONNECT is attempted and no live-Cloudflare traffic is generated by tests
// (loopback fixtures only).
func ProbeUDPReachability(ctx context.Context, scfg SessionConfig, budget time.Duration) (ReachabilityClass, error) {
	if budget <= 0 {
		budget = DefaultReachabilityProbeBudget
	}
	cert, err := ClientCertificate(scfg.ClientKey)
	if err != nil {
		return "", err
	}
	tlsCfg, err := PrepareH3TLSConfig(cert, scfg.SNI, scfg.Pin, scfg.ExtraPins)
	if err != nil {
		return "", err
	}

	network, laddr := "udp4", "0.0.0.0:0"
	if !scfg.Endpoint.Addr().Is4() {
		network, laddr = "udp6", "[::]:0"
	}
	uc, lerr := scfg.Policy.ListenUDP(ctx, network, laddr)
	if lerr != nil {
		// Local egress constraint: same structural verdict the session
		// classifier produces (classifyUDPListenError).
		return ReachBlackhole, lerr
	}
	tr := &quic.Transport{Conn: uc, ConnectionIDLength: 20} // CID20 mandatory
	pctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	conn, err := tr.Dial(pctx, net.UDPAddrFromAddrPort(scfg.Endpoint), tlsCfg, &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: budget,
	})
	if conn != nil {
		_ = conn.CloseWithError(0, "probe done")
	}
	_ = tr.Close()
	_ = uc.Close()
	if err == nil {
		return ReachReachable, nil
	}
	return classifyProbeError(err), err
}

// classifyProbeError splits dial-phase errors into the three probe classes.
// Pure function: unit-tested against synthetic quic-go error values.
func classifyProbeError(err error) ReachabilityClass {
	if err == nil {
		return ReachReachable
	}
	// The edge SPOKE: version negotiation reply, stateless reset, or any
	// TLS-layer diagnosis all prove bidirectional UDP connectivity.
	var vn *quic.VersionNegotiationError
	var sr *quic.StatelessResetError
	if errors.As(err, &vn) || errors.As(err, &sr) {
		return ReachReachable
	}
	msg := err.Error()
	if strings.Contains(msg, "tls:") || strings.Contains(msg, "certificate") || strings.Contains(msg, "crypto") {
		return ReachReachable
	}
	// Silence across the whole budget: the egress-block signature (same
	// mapping the session classifier applies to handshake timeouts).
	var idle *quic.IdleTimeoutError
	var hs *quic.HandshakeTimeoutError
	if errors.As(err, &idle) || errors.As(err, &hs) || errors.Is(err, context.DeadlineExceeded) {
		return ReachBlackhole
	}
	// Everything else arrives fast (never after the budget): network-level
	// refusal family (ECONNREFUSED / ECONNRESET / unreachable …).
	return ReachRefused
}
