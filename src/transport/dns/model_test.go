package dnspath

import (
	"strings"
	"testing"
	"time"
)

func TestDNSPathIDCanonicalDeterministic(t *testing.T) {
	id := DNSPathID{
		Family: DNSPathDoH, ResolverID: "r-a", EndpointID: "e-a",
		IPFamily: "ipv4", CatalogVersion: "catalog-1",
	}
	if id.Canonical() != id.Canonical() {
		t.Fatal("canonical serialization must be deterministic")
	}
	if id.Hash() != id.Hash() {
		t.Fatal("hash must be stable")
	}
	other := id
	other.ResolverID = "r-b"
	if id.Hash() == other.Hash() {
		t.Fatal("different resolver must change hash")
	}
}

func TestDNSPathIDValid(t *testing.T) {
	base := DNSPathID{Family: DNSPathUDP, ResolverID: "r-1", IPFamily: "ipv4"}
	if !base.Valid() {
		t.Fatal("base id must be valid")
	}
	noResolver := base
	noResolver.ResolverID = ""
	if noResolver.Valid() {
		t.Fatal("resolver id required")
	}
	badFamily := base
	badFamily.IPFamily = "ipx"
	if badFamily.Valid() {
		t.Fatal("ip family must be ipv4/ipv6")
	}
	anon := DNSPathID{Family: DNSPathAnonymizedDNSCrypt, ResolverID: "r-1", IPFamily: "ipv4"}
	if anon.Valid() {
		t.Fatal("anonymized path requires relay identity")
	}
	anon.RelayID = "rl-1"
	if !anon.Valid() {
		t.Fatal("anonymized path with relay must be valid")
	}
}

func TestSamePathAlias(t *testing.T) {
	a := DNSPathID{Family: DNSPathDoH, ResolverID: "r-a", EndpointID: "e-1", IPFamily: "ipv4"}
	b := a
	b.CatalogVersion = "catalog-2" // version noise must not break alias detection
	if !a.SamePathAlias(b) {
		t.Fatal("version noise must not break alias detection")
	}
	c := a
	c.EndpointID = "e-2"
	if a.SamePathAlias(c) {
		t.Fatal("different endpoint is not an alias")
	}
}

func TestManagedFamilyAttribution(t *testing.T) {
	// ADR-ADNS-003: DoT/DoQ are native, never managed backend.
	if DNSPathDoT.Managed() || DNSPathDoQ.Managed() {
		t.Fatal("DoT/DoQ must never be attributed to managed dnscrypt backend")
	}
	if !DNSPathDNSCrypt.Managed() || !DNSPathODoH.Managed() {
		t.Fatal("dnscrypt families must be managed")
	}
}

func TestCapabilityTerminalStates(t *testing.T) {
	for _, s := range []CapabilityState{CapUnsupported, CapStale, CapBlockedByPolicy, CapBlockedByCapability} {
		if !s.Terminal() {
			t.Fatalf("%s must be terminal (never converts to READY)", s)
		}
	}
	if CapReady.Terminal() || CapDegraded.Terminal() {
		t.Fatal("ready/degraded are not terminal")
	}
}

func validProfileFixture(t *testing.T) *DNSPathProfile {
	t.Helper()
	now := time.Now()
	primary := DNSPathID{Family: DNSPathDoH, ResolverID: "r-a", EndpointID: "e-1", IPFamily: "ipv4"}
	fallback := DNSPathID{Family: DNSPathTCP, ResolverID: "r-b", EndpointID: "e-2", IPFamily: "ipv4"}
	p := &DNSPathProfile{
		ProfileID:         "dnsprof-test",
		Status:            ProfileStatusReady,
		NetworkContextID:  "wan-1",
		ConfigGeneration:  42,
		RuntimeEpoch:      "epoch-1",
		QuerySuiteVersion: "adns-suite-v1",
		Primary:           primary,
		Fallbacks:         []DNSPathID{fallback},
		CandidateOutcomes: []DNSPathProbeOutcome{
			{PathID: primary, Class: OutcomePassCorrect},
			{PathID: fallback, Class: OutcomePassCorrect},
		},
		CreatedAt:   now,
		ValidatedAt: now,
		ValidUntil:  now.Add(time.Hour),
	}
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProfileValid(t *testing.T) {
	p := validProfileFixture(t)
	if err := p.Valid(time.Now()); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
}

func TestProfileRejectsTampering(t *testing.T) {
	p := validProfileFixture(t)
	p.Confidence.Score = 0.99 // mutate without resealing
	if err := p.Valid(time.Now()); err == nil || !strings.Contains(err.Error(), "content hash") {
		t.Fatalf("tampered profile must fail content hash check, got %v", err)
	}
}

func TestProfileRejectsExpired(t *testing.T) {
	p := validProfileFixture(t)
	p.ValidUntil = time.Now().Add(-time.Minute)
	p.Seal()
	if err := p.Valid(time.Now()); err == nil {
		t.Fatal("expired profile must be rejected")
	}
}

func TestProfileRejectsStale(t *testing.T) {
	p := validProfileFixture(t)
	p.MarkStale()
	if err := p.Valid(time.Now()); err == nil {
		t.Fatal("stale profile must be rejected")
	}
}

func TestProfileRejectsAliasFallback(t *testing.T) {
	p := validProfileFixture(t)
	alias := p.Primary
	alias.CatalogVersion = "catalog-9"
	p.Fallbacks = []DNSPathID{alias}
	p.CandidateOutcomes = append(p.CandidateOutcomes, DNSPathProbeOutcome{PathID: alias, Class: OutcomePassCorrect})
	p.Seal()
	if err := p.Valid(time.Now()); err == nil {
		t.Fatal("fallback alias of primary must be rejected")
	}
}

func TestProfileRejectsUnvalidatedPrimary(t *testing.T) {
	p := validProfileFixture(t)
	p.CandidateOutcomes = p.CandidateOutcomes[1:] // drop primary outcome
	p.Seal()
	if err := p.Valid(time.Now()); err == nil {
		t.Fatal("primary without passing outcome must be rejected")
	}
}

func TestProfileRejectsUnknownSuite(t *testing.T) {
	p := validProfileFixture(t)
	p.QuerySuiteVersion = "adns-suite-v999"
	p.Seal()
	if err := p.Valid(time.Now()); err == nil {
		t.Fatal("unknown query suite version must be rejected")
	}
}

func TestCachePartitionKeyIsolation(t *testing.T) {
	c := NewGenerationCache(8, time.Minute)
	now := time.Now()
	k1 := DNSCachePartitionKey{NetworkContextID: "wan-1", ConfigGeneration: 1, PathHash: "p1", QueryNameHash: "q1", QType: 1, DNSSECPolicy: "off", ClientScopeClass: "router-origin"}
	k2 := k1
	k2.ConfigGeneration = 2
	c.Put(k1, []byte("answer"), ResponseFingerprint{}, time.Minute, false, now)
	if _, ok := c.Get(k2, now); ok {
		t.Fatal("cross-generation cache reuse is prohibited")
	}
	if _, ok := c.Get(k1, now); !ok {
		t.Fatal("same-partition entry must be served")
	}
	c.ResetPartition("wan-1", 1, "p1")
	if _, ok := c.Get(k1, now); ok {
		t.Fatal("reset partition must drop entries")
	}
}

func TestCacheNeverCachesTruncated(t *testing.T) {
	c := NewGenerationCache(8, time.Minute)
	k := DNSCachePartitionKey{NetworkContextID: "w", ConfigGeneration: 1, PathHash: "p", QueryNameHash: "q", QType: 1}
	c.Put(k, []byte("x"), ResponseFingerprint{Truncated: true}, time.Minute, false, time.Now())
	if _, ok := c.Get(k, time.Now()); ok {
		t.Fatal("truncated answer must never be cached as complete")
	}
}

func TestCacheNegativeTTLBounded(t *testing.T) {
	c := NewGenerationCache(8, 30*time.Second)
	now := time.Now()
	k := DNSCachePartitionKey{NetworkContextID: "w", ConfigGeneration: 1, PathHash: "p", QueryNameHash: "q", QType: 1}
	c.Put(k, []byte("nx"), ResponseFingerprint{}, time.Hour, true, now)
	if _, ok := c.Get(k, now.Add(31*time.Second)); ok {
		t.Fatal("negative cache TTL must be bounded")
	}
}

func TestBindingCompatibility(t *testing.T) {
	now := time.Now()
	b := &DNSPathBinding{ConfigGeneration: 7, RuntimeEpoch: "e1", ValidUntil: now.Add(time.Hour)}
	if !b.CompatibleWith(7, "e1", now) {
		t.Fatal("compatible binding rejected")
	}
	if b.CompatibleWith(8, "e1", now) {
		t.Fatal("generation mismatch must invalidate binding")
	}
	if b.CompatibleWith(7, "e2", now) {
		t.Fatal("epoch mismatch must invalidate binding")
	}
}

func TestModeValidation(t *testing.T) {
	if !DNSModeAdaptive.Valid() || DNSOperatingMode("yolo").Valid() {
		t.Fatal("mode validation broken")
	}
}
