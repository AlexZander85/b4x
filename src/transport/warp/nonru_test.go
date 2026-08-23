// Non-RU gate tests (design §7; addendum §42–47, §62.5, §63, §69).
// Verification matrix per the implementation plan: §69 scenarios 1-7, 11,
// 19-21 against fake providers/servers, the pure quorum table, the §43
// single-cloudflare-trace-is-not-enough invariant, and one end-to-end run
// of real DNS providers through a fake tunnel session. H-NONRU-1 (colo
// base vs inner) is deliberately NOT unit-tested: its verdict belongs to
// the field experiment; only telemetry passthrough exists.
package transportwarp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fixtures ----

type geoHarness struct {
	t    *testing.T
	fs   *fakeServer
	sess *Session
	tr   *TunnelGeoTransport
	down atomic.Bool
}

func newGeoHarness(t *testing.T) *geoHarness {
	t.Helper()
	h := &geoHarness{t: t}
	h.fs = newFakeServer(t)
	// Answer every DNS query with a proper QR=1 A-response (the plain echo
	// would never pass isDNSReply and every provider exchange would time
	// out); tests that need a specific answer IP override this.
	h.fs.setResponder(func(q []byte) []byte { return dnsReplyFor(q, [4]byte{81, 9, 9, 9}) })
	privB64, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := SessionConfig{
		SNI:             DefaultSNI,
		ConnectURI:      DefaultConnectURI,
		ClientKey:       clientPriv,
		Pin:             h.fs.pinPub(),
		LocalV4:         [4]byte{172, 16, 0, 2},
		ValidateWindow:  200 * time.Millisecond,
		ProbeInterval:   5 * time.Millisecond,
		HandshakeBudget: 3 * time.Second,
	}
	h.sess = establishSession(t, tmpl, h.fs)
	h.tr = AttachTunnelGeoTransport(h.sess).WithResolveTimeout(200 * time.Millisecond)
	t.Cleanup(func() {
		h.tr.Close()
		h.sess.Close()
		h.fs.close()
	})
	return h
}

func (h *geoHarness) transport() func() (GeoProbeTransport, error) {
	return func() (GeoProbeTransport, error) {
		if h.down.Load() {
			return nil, ErrInnerTransportDown
		}
		return h.tr, nil
	}
}

// stubGeoProvider answers canned results; when exchange is set it first
// performs a REAL DNS exchange through the inner transport so the §43
// counter-delta proof sees genuine inner traffic.
type stubGeoProvider struct {
	id       string
	class    string
	mu       sync.Mutex
	res      GeoResult
	err      error
	exchange bool
	calls    int
}

func newStubProvider(id string, res GeoResult) *stubGeoProvider {
	res.ProviderID = id
	return &stubGeoProvider{id: id, class: "stub-class", res: res}
}

func (p *stubGeoProvider) ID() string            { return p.id }
func (p *stubGeoProvider) ProviderClass() string { return p.class }

func (p *stubGeoProvider) Probe(ctx context.Context, tr GeoProbeTransport) (GeoResult, error) {
	p.mu.Lock()
	p.calls++
	res, err, exch := p.res, p.err, p.exchange
	p.mu.Unlock()
	if exch {
		if _, _, e := tr.ResolveA(ctx, "gate-probe.test"); e != nil {
			return GeoResult{}, e
		}
	}
	return res, err
}

func (p *stubGeoProvider) set(res GeoResult, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if res.ProviderID == "" {
		res.ProviderID = p.id
	}
	p.res, p.err = res, err
}

func (p *stubGeoProvider) setExchange(v bool) {
	p.mu.Lock()
	p.exchange = v
	p.mu.Unlock()
}

func (p *stubGeoProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type eventLog struct {
	mu  sync.Mutex
	evs []NonRUEvent
}

func (l *eventLog) sink(ev NonRUEvent) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	l.mu.Unlock()
}

func (l *eventLog) names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.evs))
	for i, ev := range l.evs {
		out[i] = ev.Name
	}
	return out
}

func (l *eventLog) count(name string) int {
	n := 0
	for _, e := range l.names() {
		if e == name {
			n++
		}
	}
	return n
}

func (l *eventLog) lastDetail(name string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.evs) - 1; i >= 0; i-- {
		if l.evs[i].Name == name {
			return l.evs[i].Detail
		}
	}
	return ""
}

func waitUntil(t *testing.T, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met in time: %s", desc)
}

func geoTestConfig(h *geoHarness, log *eventLog, provs []GeoProvider, gen *atomic.Uint64) NonRUConfig {
	return NonRUConfig{
		Providers:         provs,
		RequiredProviders: 2,
		Transport:         h.transport(),
		CurrentGen:        func() uint64 { return gen.Load() },
		AttestationTTL:    250 * time.Millisecond,
		RefreshInterval:   40 * time.Millisecond,
		ProbeTimeout:      600 * time.Millisecond,
		PollInterval:      10 * time.Millisecond,
		Sink:              log.sink,
		OnRouteOpen:       func(a GeoAttestation) error { return nil },
		OnRouteRevoke:     func(reason string) error { return nil },
	}
}

// hookRecorder captures OnRouteOpen/OnRouteRevoke invocations.
type hookRecorder struct {
	mu      sync.Mutex
	opens   []GeoAttestation
	revokes []string
}

func (r *hookRecorder) open(a GeoAttestation) error {
	r.mu.Lock()
	r.opens = append(r.opens, a)
	r.mu.Unlock()
	return nil
}

func (r *hookRecorder) revoke(reason string) error {
	r.mu.Lock()
	r.revokes = append(r.revokes, reason)
	r.mu.Unlock()
	return nil
}

func (r *hookRecorder) snapshot() ([]GeoAttestation, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]GeoAttestation(nil), r.opens...), append([]string(nil), r.revokes...)
}

var (
	testIP1 = netip.AddrFrom4([4]byte{81, 2, 3, 4})
	testIP2 = netip.AddrFrom4([4]byte{81, 2, 3, 5})
)

func deResult(ip netip.Addr) GeoResult {
	return GeoResult{Country: "DE", PublicIPHash: HashPublicIP(ip)}
}

// ---- §69-3: two same-country non-RU providers open the gate ----

func TestNonRUGateOpensOnQuorumPass(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}
	gen.Store(7)

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))
	pa.setExchange(true)
	pb.setExchange(true)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, err := NewNonRUGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := g.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	waitUntil(t, "gate opens", func() bool { return g.Status().Open })

	st := g.Status()
	if st.Verdict != VerdictPassNonRU {
		t.Fatalf("verdict = %q", st.Verdict)
	}
	att := st.Attestation
	if att.Country != "DE" || att.Providers != 2 || att.Quorum != 2 {
		t.Fatalf("attestation = %+v", att)
	}
	if att.PublicIPHash != HashPublicIP(testIP1) {
		t.Fatalf("public ip hash mismatch")
	}
	if att.PathID != h.tr.PathID() {
		t.Fatalf("path id = %q want %q", att.PathID, h.tr.PathID())
	}
	if att.SessionGeneration != 7 {
		t.Fatalf("attestation generation = %d", att.SessionGeneration)
	}
	if !att.Valid(time.Now()) {
		t.Fatal("attestation must be valid right after issue")
	}

	opens, revokes := rec.snapshot()
	if len(opens) != 1 || len(revokes) != 0 {
		t.Fatalf("hooks: %d opens %d revokes", len(opens), len(revokes))
	}

	// Event order: probe_started -> >=2 provider results -> quorum ->
	// issued -> opened -> promoted (§62.5: no summary without providers).
	names := log.names()
	idxOf := func(n string) int {
		for i, x := range names {
			if x == n {
				return i
			}
		}
		t.Fatalf("event %s missing", n)
		return -1
	}
	seq := []string{
		EvGeoProbeStarted,
		EvGeoProviderResult,
		EvGeoQuorumEvaluated,
		EvGeoAttestationIssued,
		EvNonRUGateOpened,
		EvNonRURoutePromoted,
	}
	for i := 1; i < len(seq); i++ {
		if idxOf(seq[i]) <= idxOf(seq[i-1]) {
			t.Fatalf("event order violated: %s (at %d) not after %s (at %d); full=%v",
				seq[i], idxOf(seq[i]), seq[i-1], idxOf(seq[i-1]), names)
		}
	}
	if got := log.count(EvGeoProviderResult); got < 2 {
		t.Fatalf("provider results = %d", got)
	}
	if d := log.lastDetail(EvGeoQuorumEvaluated); !strings.Contains(d, "valid=2") {
		t.Fatalf("quorum detail = %q", d)
	}
}

// ---- §69-2: all providers say RU -> immediate revoke + fail-closed ----

func TestNonRUGateAllProvidersRU(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}
	gen.Store(1)

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))
	pa.setExchange(true)
	pb.setExchange(true)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "gate opens", func() bool { return g.Status().Open })

	ru := GeoResult{Country: "RU", PublicIPHash: HashPublicIP(testIP1)}
	pa.set(ru, nil)
	pb.set(ru, nil)

	waitUntil(t, "revoked on provider-ru", func() bool { return g.Status().CloseReason == CloseProviderRU })
	st := g.Status()
	if st.Open {
		t.Fatal("gate still open")
	}
	if st.Verdict != VerdictFailRU {
		t.Fatalf("verdict = %q", st.Verdict)
	}
	if st.LastRevocationLatency <= 0 {
		t.Fatalf("revocation latency not measured: %v", st.LastRevocationLatency)
	}
	if _, revokes := rec.snapshot(); len(revokes) == 0 || revokes[0] != CloseProviderRU {
		t.Fatalf("revoke hooks = %v", revokes)
	}
	if log.count(EvNonRUFailClosed) == 0 {
		t.Fatal("fail-closed event missing")
	}
	if log.count(EvNonRURouteRevocationStarted) == 0 || log.count(EvNonRURouteRevoked) == 0 ||
		log.count(EvNonRUGateClosed) == 0 {
		t.Fatalf("revocation events incomplete: %v", log.names())
	}
}

// ---- §69-4: one provider non-RU, one RU -> FAIL_RU dominates ----

func TestNonRUGateMixedRUDisagrees(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", GeoResult{Country: "RU", PublicIPHash: HashPublicIP(testIP1)})
	pa.setExchange(true)
	pb.setExchange(true)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	time.Sleep(200 * time.Millisecond) // several refresh rounds
	st := g.Status()
	if st.Open {
		t.Fatal("gate opened despite RU provider")
	}
	if st.Verdict != VerdictFailRU {
		t.Fatalf("verdict = %q", st.Verdict)
	}
	opens, revokes := rec.snapshot()
	if len(opens) != 0 || len(revokes) != 0 {
		t.Fatalf("route hooks fired while closed: %d/%d", len(opens), len(revokes))
	}
	if log.count(EvNonRUGateOpened) != 0 {
		t.Fatal("gate_opened emitted while closed")
	}
}

// ---- §69-1: base active but inner never connects -> stays closed ----

func TestNonRUGateHoldsClosedWithoutInner(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}
	h.down.Store(true) // inner path never becomes available

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))

	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	time.Sleep(250 * time.Millisecond)
	st := g.Status()
	if st.Open || st.CloseReason != "" {
		t.Fatalf("unexpected state: open=%v close=%q", st.Open, st.CloseReason)
	}
	if log.count(EvNonRUGateOpened) != 0 || log.count(EvGeoProbeStarted) != 0 {
		t.Fatalf("probe/open activity without inner path: %v", log.names())
	}
	if pa.callCount()+pb.callCount() != 0 {
		t.Fatal("providers called without inner transport")
	}
}

// ---- §69-5 + §69-7: quorum lost -> hold until attestation-stale ----

func TestNonRUGateStalesWhenQuorumLost(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))
	pa.setExchange(true)
	pb.setExchange(true)

	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "gate opens", func() bool { return g.Status().Open })

	// One provider dies: single remaining vote is INSUFFICIENT (not
	// disagreement), so the gate holds and simply stops renewing.
	pb.set(GeoResult{}, errors.New("provider unavailable"))

	waitUntil(t, "attestation-stale revoke", func() bool {
		return g.Status().CloseReason == CloseAttestationStale
	})
	st := g.Status()
	if st.Open {
		t.Fatal("gate still open after TTL")
	}
	if st.Verdict != VerdictStale {
		t.Fatalf("verdict = %q", st.Verdict)
	}
	if st.Revocations != 1 || st.LastRevocationLatency <= 0 {
		t.Fatalf("revocations=%d latency=%v", st.Revocations, st.LastRevocationLatency)
	}
	if log.count(EvGeoAttestationExpired) == 0 {
		t.Fatal("attestation_expired event missing")
	}
	if log.count(EvNonRURouteRevoked) != 1 {
		t.Fatalf("expected exactly one revocation, events=%v", log.names())
	}
	if strings.Contains(strings.Join(log.names(), ","), string(EvNonRUFailClosed)) {
		t.Fatal("insufficient evidence must not trigger fail-closed")
	}
}

// ---- §69-6: public IP change -> revoke + refresh-on-change reopen ----

func TestNonRUGateRevokesOnPublicIPChange(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))
	pa.setExchange(true)
	pb.setExchange(true)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "gate opens", func() bool { return g.Status().Open })

	newRes := deResult(testIP2) // same country, different egress IP
	pa.set(newRes, nil)
	pb.set(newRes, nil)

	waitUntil(t, "ip change observed", func() bool {
		return g.Status().CloseReason == ClosePublicIPChanged || g.Status().Revocations > 0
	})
	waitUntil(t, "reopen on stable new ip", func() bool { return g.Status().Open })
	st := g.Status()
	if st.Attestation.PublicIPHash != HashPublicIP(testIP2) {
		t.Fatalf("attestation ip hash = %s", st.Attestation.PublicIPHash)
	}
	if log.count(EvGeoPublicIPChanged) == 0 {
		t.Fatal("public_ip_changed event missing")
	}
	if st.Revocations != 1 {
		t.Fatalf("revocations = %d", st.Revocations)
	}
	_, revokes := rec.snapshot()
	if len(revokes) != 1 || revokes[0] != ClosePublicIPChanged {
		t.Fatalf("revoke hooks = %v", revokes)
	}
}

// ---- §69-11: outer tunnel drops while inner active -> inner-path-lost ----

func TestNonRUGateInnerPathLost(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))
	pa.setExchange(true)
	pb.setExchange(true)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "gate opens", func() bool { return g.Status().Open })

	h.down.Store(true)
	waitUntil(t, "inner-path-lost revoke", func() bool {
		return g.Status().CloseReason == CloseInnerPathLost
	})
	if g.Status().Open {
		t.Fatal("gate still open after inner loss")
	}
	_, revokes := rec.snapshot()
	if len(revokes) != 1 || revokes[0] != CloseInnerPathLost {
		t.Fatalf("revoke hooks = %v", revokes)
	}
}

// ---- §69-19/20: parent reconnect invalidates; stale-gen token rejected ----

func TestNonRUGateParentReconnectInvalidatesAttestation(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}
	gen.Store(3)

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))
	pa.setExchange(true)
	pb.setExchange(true)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "gate opens at gen 3", func() bool {
		return g.Status().Open && g.Status().SessionGen == 3
	})

	gen.Store(4) // parent reconnected: child revalidated against a NEW generation
	waitUntil(t, "parent-reconnected revoke", func() bool {
		return g.Status().CloseReason == CloseParentReconnected
	})
	// The next fresh PASS reopens the gate against generation 4 only.
	waitUntil(t, "reopen at gen 4", func() bool {
		return g.Status().Open && g.Status().SessionGen == 4
	})
	_, revokes := rec.snapshot()
	found := false
	for _, r := range revokes {
		if r == CloseParentReconnected {
			found = true
		}
	}
	if !found {
		t.Fatalf("no parent-reconnected revoke in %v", revokes)
	}
}

// ---- §69-21: results without inner counter delta = direct-WAN escape ----

func TestNonRUGateRejectsDirectWANEscape(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))
	pa.setExchange(true)
	pb.setExchange(true)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "gate opens", func() bool { return g.Status().Open })

	// Both providers start fabricating answers WITHOUT traversing the inner
	// path: no counter movement -> results invalid -> fail closed.
	pa.setExchange(false)
	pb.setExchange(false)

	waitUntil(t, "direct-wan revoke", func() bool {
		return g.Status().CloseReason == CloseDirectWANObserved
	})
	if g.Status().Open {
		t.Fatal("gate survived a direct-WAN escape attempt")
	}
	detail := log.lastDetail(EvGeoProviderFailed)
	if !strings.Contains(detail, ErrNoCounterDelta.Error()) {
		t.Fatalf("provider_failed detail = %q", detail)
	}
	if log.count(EvNonRUFailClosed) == 0 {
		t.Fatal("direct-WAN escape while active must be fail-closed")
	}
}

// ---- §43 invariant: configuration floor and provider identity ----

func TestNewNonRUGateRejectsBadConfigs(t *testing.T) {
	h := newGeoHarness(t)
	gen := &atomic.Uint64{}
	pa := newStubProvider("prov-a", deResult(testIP1))
	pdup := newStubProvider("prov-a", deResult(testIP1)) // same id as pa
	pb := newStubProvider("prov-b", deResult(testIP1))

	cases := []struct {
		name string
		mut  func(*NonRUConfig)
	}{
		{"nil transport", func(c *NonRUConfig) { c.Transport = nil }},
		{"single provider", func(c *NonRUConfig) { c.Providers = []GeoProvider{pa} }},
		{"duplicate ids", func(c *NonRUConfig) { c.Providers = []GeoProvider{pa, pdup} }},
		{"empty provider id", func(c *NonRUConfig) {
			c.Providers = []GeoProvider{pa, newStubProvider("", deResult(testIP1))}
		}},
	}
	for _, tc := range cases {
		cfg := geoTestConfig(h, &eventLog{}, []GeoProvider{pa, pb}, gen)
		tc.mut(&cfg)
		if _, err := NewNonRUGate(cfg); !errors.Is(err, ErrGeoConfig) {
			t.Errorf("%s: got %v", tc.name, err)
		}
	}
	if _, err := NewNonRUGate(geoTestConfig(h, &eventLog{}, []GeoProvider{pa, pb}, gen)); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// ---- pure quorum table (mirrors src/warp.BuildGeoAttestation semantics) ----

func TestEvaluateGeoQuorumTable(t *testing.T) {
	now := time.Now()
	fresh := now.Add(time.Minute)
	mk := func(class, country, iph string, delta uint64, exp time.Time) GeoObservation {
		return GeoObservation{
			Provider: class + country, Class: class, Country: country,
			PublicIPHash: iph, CounterDelta: delta, ExpiresAt: exp,
			DNSProof: true,
		}
	}
	de1 := mk(geoClassNonRU, "DE", "h1", 1, fresh)
	de2 := mk(geoClassNonRU, "DE", "h1", 1, fresh)
	fr := mk(geoClassNonRU, "FR", "h1", 1, fresh)
	ru := mk(geoClassRU, "RU", "h1", 1, fresh)
	unknown := mk(geoClassUnknown, "", "h1", 1, fresh)
	expired := mk(geoClassNonRU, "DE", "h1", 1, now.Add(-time.Minute))
	noDelta := mk(geoClassNonRU, "DE", "h1", 0, fresh)
	ipOther := mk(geoClassNonRU, "DE", "h2", 1, fresh)

	cases := []struct {
		name     string
		obs      []GeoObservation
		required int
		verdict  GeoVerdict
		disagree bool
		insuffic bool
		country  string
	}{
		{"pass two same country", []GeoObservation{de1, de2}, 2, VerdictPassNonRU, false, false, "DE"},
		{"ru dominates", []GeoObservation{de1, ru}, 2, VerdictFailRU, false, false, ""},
		{"two countries disagree", []GeoObservation{de1, fr}, 2, VerdictInconclusive, true, false, ""},
		{"nonru+unknown disagree", []GeoObservation{de1, unknown}, 2, VerdictInconclusive, true, false, ""},
		{"ip mismatch disagrees", []GeoObservation{de1, ipOther}, 2, VerdictInconclusive, true, false, ""},
		{"single vote insufficient", []GeoObservation{de1, expired}, 2, VerdictInconclusive, false, true, ""},
		{"zero delta excluded", []GeoObservation{de1, noDelta}, 2, VerdictInconclusive, false, true, ""},
		{"expired skipped", []GeoObservation{de1, de2, expired}, 2, VerdictPassNonRU, false, false, "DE"},
		{"higher quorum insufficient", []GeoObservation{de1, de2}, 3, VerdictInconclusive, false, true, ""},
	}
	for _, tc := range cases {
		q := EvaluateGeoQuorum(tc.obs, tc.required, now)
		if q.Verdict != tc.verdict || q.Disagreement != tc.disagree ||
			q.Insufficient != tc.insuffic || q.Country != tc.country {
			t.Errorf("%s: got verdict=%s dis=%v ins=%v country=%q, want %s/%v/%v/%q",
				tc.name, q.Verdict, q.Disagreement, q.Insufficient, q.Country,
				tc.verdict, tc.disagree, tc.insuffic, tc.country)
		}
	}
	if q := EvaluateGeoQuorum([]GeoObservation{de1, de2}, 2, now); q.AnyZeroDelta {
		t.Error("zero-delta flag leaked into pass case")
	}
	if q := EvaluateGeoQuorum([]GeoObservation{de1, noDelta}, 2, now); !q.AnyZeroDelta {
		t.Error("zero-delta observation not flagged")
	}
}

// ---- manual disable (§47 checkbox off) ----

func TestNonRUGateManualDisable(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}

	pa := newStubProvider("prov-a", deResult(testIP1))
	pb := newStubProvider("prov-b", deResult(testIP1))
	pa.setExchange(true)
	pb.setExchange(true)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "gate opens", func() bool { return g.Status().Open })

	callsBefore := pa.callCount() + pb.callCount()
	g.ManualDisable()
	waitUntil(t, "manual-disable revoke", func() bool {
		return g.Status().CloseReason == CloseManualDisable && !g.Status().Open
	})
	time.Sleep(120 * time.Millisecond)
	callsAfter := pa.callCount() + pb.callCount()
	if callsAfter != callsBefore {
		t.Fatalf("probing continued after disable: %d -> %d", callsBefore, callsAfter)
	}
	if !g.Status().ManualDisabled {
		t.Fatal("manual flag not surfaced")
	}
}

// ---- end-to-end: real whoami DNS providers through the fake tunnel ----

func TestNonRUGateDNSProvidersEndToEnd(t *testing.T) {
	h := newGeoHarness(t)
	log := &eventLog{}
	gen := &atomic.Uint64{}

	answer := [4]byte{81, 2, 3, 4}
	h.fs.setResponder(func(q []byte) []byte { return dnsReplyFor(q, answer) })

	classify := func(a netip.Addr) string {
		if a == netip.AddrFrom4(answer) {
			return "DE"
		}
		return ""
	}
	pa := NewWhoamiDNSProvider("akamai-whoami", "whoami.akamai.net", classify)
	pb := NewWhoamiDNSProvider("google-myaddr", "o-o.myaddr.l.google.com", classify)

	rec := &hookRecorder{}
	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, gen)
	cfg.OnRouteOpen = rec.open
	cfg.OnRouteRevoke = rec.revoke

	g, _ := NewNonRUGate(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "gate opens via dns providers", func() bool { return g.Status().Open })
	st := g.Status()
	if st.Attestation.Country != "DE" {
		t.Fatalf("country = %q", st.Attestation.Country)
	}
	if st.Attestation.PublicIPHash != HashPublicIP(netip.AddrFrom4(answer)) {
		t.Fatal("public ip hash mismatch")
	}
	obs := st.Observations
	if len(obs) < 2 {
		t.Fatalf("observations = %d", len(obs))
	}
	for _, o := range obs {
		if !o.DNSProof || o.CounterDelta == 0 || o.PathID != h.tr.PathID() {
			t.Fatalf("observation lacks §43 proof: %+v", o)
		}
		if o.Class != geoClassNonRU {
			t.Fatalf("class = %q", o.Class)
		}
	}
	if log.count(EvDNSPathProven) == 0 || log.count(EvGeoProbePathProven) == 0 {
		t.Fatal("dns/probe path proof events missing")
	}
}

// ---- session plumbing: counters, taps, drop-instead-of-block ----

func TestSessionPacketCountersAndTap(t *testing.T) {
	h := newGeoHarness(t)
	sess := h.sess

	beforeTx, beforeRx := sess.Counters(), sess.Counters()
	payload := make([]byte, 64)
	if err := sess.WritePacket(payload); err != nil {
		t.Fatal(err)
	}
	after := sess.Counters()
	if after.TxPackets != beforeTx.TxPackets+1 {
		t.Fatalf("tx packets = %d", after.TxPackets-after.TxPackets)
	}

	ch, cancel := sess.SubscribePackets()
	defer cancel()

	// The echo server replies to every capsule (reshaped by the harness
	// responder); wait for ANY frame to surface on the tap.
	got := false
	waitUntil(t, "tap receives echo", func() bool {
		select {
		case pkt := <-ch:
			if len(pkt) > 0 {
				got = true
			}
		default:
		}
		return got
	})
	if sess.Counters().RxPackets == beforeRx.RxPackets {
		t.Fatal("rx counter did not move")
	}
	cancel() // unsubscribe closes the channel
	if _, open := <-ch; open {
		t.Fatal("tap channel not closed on unsubscribe")
	}

	// Drop-instead-of-block: flood without reading; drops are counted, the
	// session keeps working.
	slowCh, slowCancel := sess.SubscribePackets()
	defer slowCancel()
	_ = slowCh // intentionally never drained
	for i := 0; i < 80; i++ {
		if err := sess.WritePacket(payload); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, "drops accounted", func() bool {
		primary, taps := sess.DroppedFrames()
		return primary+taps > 0
	})
	// Session still functional afterwards.
	if err := sess.WritePacket(payload); err != nil {
		t.Fatalf("session wedged after flood: %v", err)
	}
}

// compile-time interface checks
var (
	_ GeoProvider       = (*stubGeoProvider)(nil)
	_ GeoProvider       = (*WhoamiDNSProvider)(nil)
	_ GeoProvider       = (*CFTraceProvider)(nil)
	_ GeoProbeTransport = (*TunnelGeoTransport)(nil)
)
