package dnspath

import (
	"context"
	"errors"
	"testing"
	"time"
)

// stubProvider is a controlled in-memory provider for manager/transaction
// tests. No mocks of external systems: it implements the real provider
// contract.
type stubProvider struct {
	id       DNSPathID
	caps     DNSPathCapabilities
	resolve  func(ctx context.Context, q DNSQuery) (DNSResponse, error)
	prepared bool
}

func (s *stubProvider) ID() DNSPathID               { return s.id }
func (s *stubProvider) Capabilities() DNSPathCapabilities { return s.caps }
func (s *stubProvider) Prepare(_ context.Context, req DNSPrepareRequest) (PreparedDNSPath, error) {
	s.prepared = true
	return PreparedDNSPath{PathID: s.id, Generation: req.Generation, PreparedAt: time.Now()}, nil
}
func (s *stubProvider) Probe(_ context.Context, p PreparedDNSPath, q DNSProbeQuery) (DNSPathProbeOutcome, error) {
	return DNSPathProbeOutcome{PathID: s.id, Class: OutcomePassCorrect, QuerySuiteID: q.SuiteCase}, nil
}
func (s *stubProvider) Resolve(ctx context.Context, _ PreparedDNSPath, q DNSQuery) (DNSResponse, error) {
	if s.resolve != nil {
		return s.resolve(ctx, q)
	}
	return DNSResponse{Payload: []byte("ok"), Fingerprint: ResponseFingerprint{}}, nil
}
func (s *stubProvider) Health(_ context.Context, _ PreparedDNSPath) DNSPathHealth {
	return DNSPathHealth{State: CapReady}
}
func (s *stubProvider) Retire(_ context.Context, _ PreparedDNSPath) error { return nil }

func managerFixture(t *testing.T) (*Manager, *stubProvider, *stubProvider) {
	t.Helper()
	pol := DefaultAdaptivePolicy()
	pol.Enabled = true
	m := NewManager(DNSModeAdaptive, pol, 7, "epoch-1", "wan-1")
	primary := &stubProvider{
		id:   DNSPathID{Family: DNSPathDoH, ResolverID: "r-p", EndpointID: "e-p", IPFamily: "ipv4"},
		caps: DNSPathCapabilities{State: CapAvailable, IPv4: true},
	}
	fallback := &stubProvider{
		id:   DNSPathID{Family: DNSPathTCP, ResolverID: "r-f", EndpointID: "e-f", IPFamily: "ipv4"},
		caps: DNSPathCapabilities{State: CapAvailable, IPv4: true},
	}
	return m, primary, fallback
}

func adoptTestProfile(t *testing.T, m *Manager, primary, fallback DNSPathID) *DNSPathProfile {
	t.Helper()
	now := time.Now()
	p := &DNSPathProfile{
		ProfileID: "dnsprof-mgr", Status: ProfileStatusReady,
		NetworkContextID: "wan-1", ConfigGeneration: 7, RuntimeEpoch: "epoch-1",
		QuerySuiteVersion: "adns-suite-v1",
		Primary:           primary,
		Fallbacks:         []DNSPathID{fallback},
		CandidateOutcomes: []DNSPathProbeOutcome{
			{PathID: primary, Class: OutcomePassCorrect},
			{PathID: fallback, Class: OutcomePassCorrect},
		},
		CreatedAt: now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := m.AdoptProfile(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagerRejectsStaleProfile(t *testing.T) {
	m, primary, _ := managerFixture(t)
	p := &DNSPathProfile{
		ProfileID: "dnsprof-stale", Status: ProfileStatusStale,
		NetworkContextID: "wan-1", ConfigGeneration: 7, RuntimeEpoch: "epoch-1",
		QuerySuiteVersion: "adns-suite-v1", Primary: primary.id,
		CreatedAt: time.Now(), ValidatedAt: time.Now(), ValidUntil: time.Now().Add(time.Hour),
	}
	p.Seal()
	if err := m.AdoptProfile(p); err == nil {
		t.Fatal("stale profile must never be applied (dns_stale_profile_applied_total)")
	}
}

func TestManagerRejectsCrossGenerationProfile(t *testing.T) {
	m, primary, fallback := managerFixture(t)
	now := time.Now()
	p := &DNSPathProfile{
		ProfileID: "dnsprof-gen", Status: ProfileStatusReady,
		NetworkContextID: "wan-1", ConfigGeneration: 999, RuntimeEpoch: "epoch-1",
		QuerySuiteVersion: "adns-suite-v1", Primary: primary.id, Fallbacks: []DNSPathID{fallback.id},
		CandidateOutcomes: []DNSPathProbeOutcome{
			{PathID: primary.id, Class: OutcomePassCorrect},
			{PathID: fallback.id, Class: OutcomePassCorrect},
		},
		CreatedAt: now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	p.Seal()
	if err := m.AdoptProfile(p); err == nil {
		t.Fatal("profile from another generation must be rejected")
	}
}

func TestResolveDisabledWithoutAdaptive(t *testing.T) {
	pol := DefaultAdaptivePolicy()
	m := NewManager(DNSModeCurrent, pol, 7, "epoch-1", "wan-1")
	if _, err := m.Resolve(context.Background(), DNSQuery{Name: "example.com", QType: 1, TxID: 1}); err == nil {
		t.Fatal("resolve must fail when adaptive mode is off (default-safe)")
	}
}

func TestResolveRequiresBinding(t *testing.T) {
	m, _, _ := managerFixture(t)
	if _, err := m.Resolve(context.Background(), DNSQuery{Name: "example.com", QType: 1, TxID: 1}); err == nil {
		t.Fatal("resolve without binding must fail")
	}
}

func TestTransactionPromoteAndRollback(t *testing.T) {
	m, primary, fallback := managerFixture(t)
	ctx := context.Background()
	if err := m.PreparePath(ctx, primary, false); err != nil {
		t.Fatal(err)
	}
	if err := m.PreparePath(ctx, fallback, false); err != nil {
		t.Fatal(err)
	}
	m.MarkPathHealth(primary.id, DNSPathHealth{State: CapReady})
	m.MarkPathHealth(fallback.id, DNSPathHealth{State: CapReady})
	profile := adoptTestProfile(t, m, primary.id, fallback.id)

	binding, err := m.NewBinding("lan", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tx := &Transaction{
		Profile: profile, Candidate: binding,
		Gate: PromotionGate{
			FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
			SameServiceControls: true, UnrelatedControls: true,
			NoBlockingHardGate: true, MetricsParity: true,
		},
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(ctx, m); err != nil {
		t.Fatalf("transaction must promote: %v", err)
	}
	if m.ActiveBinding() == nil || !m.ActiveBinding().Promoted() {
		t.Fatal("binding must be promoted")
	}

	// second transaction with failing canary must roll back to last-good
	profile2 := adoptTestProfile(t, m, fallback.id, primary.id)
	binding2, _ := m.NewBinding("lan", time.Hour)
	tx2 := &Transaction{
		Profile: profile2, Candidate: binding2, LastGood: m.ActiveBinding(),
		Gate: PromotionGate{
			FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
			SameServiceControls: true, UnrelatedControls: true,
			NoBlockingHardGate: true, MetricsParity: true,
		},
		Canary: func(context.Context, *DNSPathBinding) error { return errors.New("android canary failed") },
	}
	if err := tx2.Run(ctx, m); err == nil {
		t.Fatal("canary failure must abort transaction")
	}
	if m.ActiveBinding().Primary.Hash() != primary.id.Hash() {
		t.Fatal("rollback must restore last-good binding")
	}
	if m.Counters().RollbackTotal == 0 {
		t.Fatal("rollback counter must increment")
	}
}

func TestPromotionGateRequiresControlsAndCanary(t *testing.T) {
	g := PromotionGate{
		FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
		SameServiceControls: true, UnrelatedControls: false,
		AndroidCanary: true, CacheReady: true, RollbackReady: true,
		NoBlockingHardGate: true, MetricsParity: true,
	}
	if err := g.Check(); err == nil {
		t.Fatal("promotion without unrelated controls must be blocked")
	}
	g.UnrelatedControls = true
	g.AndroidCanary = false
	if err := g.Check(); err == nil {
		t.Fatal("promotion without Android canary must be blocked")
	}
}

func TestPrepareFailureLeavesBindingUnchanged(t *testing.T) {
	m, primary, fallback := managerFixture(t)
	ctx := context.Background()
	m.PreparePath(ctx, primary, false)
	m.PreparePath(ctx, fallback, false)
	m.MarkPathHealth(primary.id, DNSPathHealth{State: CapReady})
	m.MarkPathHealth(fallback.id, DNSPathHealth{State: CapReady})
	profile := adoptTestProfile(t, m, primary.id, fallback.id)
	binding, _ := m.NewBinding("lan", time.Hour)
	tx := &Transaction{
		Profile: profile, Candidate: binding,
		Gate: PromotionGate{
			FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
			SameServiceControls: true, UnrelatedControls: true,
			NoBlockingHardGate: true, MetricsParity: true,
		},
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(ctx, m); err != nil {
		t.Fatal(err)
	}
	active := m.ActiveBinding()
	// invalid profile aborts before any mutation
	badProfile := *profile
	badProfile.ContentHash = "tampered"
	tx2 := &Transaction{Profile: &badProfile, Candidate: binding}
	if err := tx2.Run(ctx, m); err == nil {
		t.Fatal("invalid profile must abort")
	}
	if m.ActiveBinding() != active {
		t.Fatal("failed prepare must leave current binding unchanged")
	}
}

func TestFastFallbackOnlyReadyPaths(t *testing.T) {
	m, primary, fallback := managerFixture(t)
	ctx := context.Background()
	primary.resolve = func(context.Context, DNSQuery) (DNSResponse, error) {
		return DNSResponse{}, errors.New("primary timeout")
	}
	m.PreparePath(ctx, primary, false)
	m.PreparePath(ctx, fallback, false)
	// fallback NOT marked ready → must not be used inline
	m.MarkPathHealth(primary.id, DNSPathHealth{State: CapReady})
	adoptTestProfile(t, m, primary.id, fallback.id)
	binding, _ := m.NewBinding("lan", time.Hour)
	tx := &Transaction{
		Profile: m.Profile(), Candidate: binding,
		Gate: PromotionGate{
			FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
			SameServiceControls: true, UnrelatedControls: true,
			NoBlockingHardGate: true, MetricsParity: true,
		},
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(ctx, m); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(ctx, DNSQuery{Name: "example.com", QType: 1, TxID: 1}); err == nil {
		t.Fatal("unready fallback must not serve inline")
	}
	// now mark fallback ready → fallback serves
	m.MarkPathHealth(fallback.id, DNSPathHealth{State: CapReady})
	resp, err := m.Resolve(ctx, DNSQuery{Name: "example.com", QType: 1, TxID: 2})
	if err != nil {
		t.Fatalf("ready fallback must serve: %v", err)
	}
	if string(resp.Payload) != "ok" {
		t.Fatal("fallback response mismatch")
	}
	if m.Counters().FallbackTotal == 0 {
		t.Fatal("fallback counter must increment")
	}
}

func TestWANChangeInvalidatesBinding(t *testing.T) {
	m, primary, fallback := managerFixture(t)
	ctx := context.Background()
	m.PreparePath(ctx, primary, false)
	m.PreparePath(ctx, fallback, false)
	m.MarkPathHealth(primary.id, DNSPathHealth{State: CapReady})
	m.MarkPathHealth(fallback.id, DNSPathHealth{State: CapReady})
	adoptTestProfile(t, m, primary.id, fallback.id)
	binding, _ := m.NewBinding("lan", time.Hour)
	tx := &Transaction{
		Profile: m.Profile(), Candidate: binding,
		Gate: PromotionGate{
			FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
			SameServiceControls: true, UnrelatedControls: true,
			NoBlockingHardGate: true, MetricsParity: true,
		},
		Canary: func(context.Context, *DNSPathBinding) error { return nil },
	}
	if err := tx.Run(ctx, m); err != nil {
		t.Fatal(err)
	}
	m.InvalidateOnContextChange(8, "wan-2")
	if m.ActiveBinding() != nil {
		t.Fatal("WAN change must invalidate binding")
	}
	if m.Profile().Status != ProfileStatusStale {
		t.Fatal("WAN change must mark profile stale")
	}
}

func TestHealthComposition(t *testing.T) {
	r := ComposeHealth(map[HealthAxis]AxisState{
		AxisTransport: AxisHealthy, AxisCorrectness: AxisHealthy, AxisFreshness: AxisHealthy, AxisFallback: AxisHealthy,
	})
	if r.Overall != AxisHealthy {
		t.Fatal("all-green axes must compose green")
	}
	r = ComposeHealth(map[HealthAxis]AxisState{AxisTransport: AxisHealthy, AxisBackend: AxisFailed})
	if r.Overall != AxisFailed {
		t.Fatal("single failed axis must fail overall")
	}
	r = ComposeHealth(map[HealthAxis]AxisState{AxisTransport: AxisHealthy, AxisFreshness: AxisUnknown})
	if r.Overall == AxisHealthy {
		t.Fatal("unknown freshness forbids green (beginner UI rule §20)")
	}
}

func TestRecurrenceThreshold(t *testing.T) {
	tr := NewRecurrenceTracker(3)
	now := time.Now()
	if tr.Record(DNSPathUDP, "timeout", now) {
		t.Fatal("single transient timeout must not trigger diagnosis")
	}
	tr.Record(DNSPathUDP, "timeout", now)
	if !tr.Record(DNSPathUDP, "timeout", now) {
		t.Fatal("persistent recurrence must trigger bounded diagnosis")
	}
	tr.Reset(DNSPathUDP, "timeout")
	if tr.Record(DNSPathUDP, "timeout", now) {
		t.Fatal("reset must clear recurrence")
	}
}

func TestManualPinSemantics(t *testing.T) {
	m, _, _ := managerFixture(t)
	m.SetManualPin("hash-x")
	if m.ManualPin() != "hash-x" {
		t.Fatal("manual pin must persist")
	}
	m.SetManualPin("")
	if m.ManualPin() != "" {
		t.Fatal("removing pin must return control to profile selection")
	}
}
