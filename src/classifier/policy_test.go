package classifier

import (
	"net/netip"
	"testing"
	"time"
)

func testClient() ClientKey {
	return ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.10"), IfIndex: 2, VLAN: 10}
}

func testEvidence(source EvidenceSource, domain, set string, confidence uint8, now time.Time) Evidence {
	return Evidence{
		Source:         source,
		Client:         testClient(),
		DestinationIP:  netip.MustParseAddr("203.0.113.7"),
		Domain:         domain,
		SetID:          set,
		Confidence:     confidence,
		DomainEvidence: domain != "",
		CreatedAt:      now.Add(-time.Second),
		ExpiresAt:      now.Add(time.Minute),
		ConfigGen:      7,
	}
}

func testContext(now time.Time) DecisionContext {
	return DecisionContext{Now: now, Client: testClient(), ConfigGen: 7, InputIncomplete: false}
}

func TestDecideSourcePriorityAndFreshness(t *testing.T) {
	now := time.Unix(100, 0)
	ctx := testContext(now)
	d := Decide(ctx, []Evidence{
		testEvidence(EvidenceDNSAnswer, "dns.example", "dns", 89, now),
		testEvidence(EvidenceReassembledSNI, "clear.example", "clear", 0, now),
		testEvidence(EvidencePacketSNI, "stale.example", "stale", 100, now).withExpiry(now.Add(-time.Second)),
	}, DefaultConfidenceThresholds)
	if d.Selected == nil || d.Selected.SetID != "clear" || d.Phase != PhaseFinal {
		t.Fatalf("decision = %+v", d)
	}
	if len(d.Candidates) != 3 || d.Candidates[0].SetID != "clear" {
		t.Fatalf("candidate trace was not deterministic: %+v", d.Candidates)
	}
}

func TestDecideAmbiguityRetainsAllCandidates(t *testing.T) {
	now := time.Unix(200, 0)
	ctx := testContext(now)
	d := Decide(ctx, []Evidence{
		testEvidence(EvidenceDNSAnswer, "one.example", "one", 80, now),
		testEvidence(EvidenceDNSAnswer, "two.example", "two", 80, now),
	}, DefaultConfidenceThresholds)
	if d.Phase != PhaseAmbiguous || d.Selected != nil || len(d.Candidates) != 2 {
		t.Fatalf("decision = %+v", d)
	}
	if d.CanDestructivelyMutate(DefaultConfidenceThresholds) {
		t.Fatal("ambiguous DNS evidence crossed destructive threshold")
	}
}

func TestDecideClearSNIOverridesConflictingDNS(t *testing.T) {
	now := time.Unix(300, 0)
	d := Decide(testContext(now), []Evidence{
		testEvidence(EvidenceDNSAnswer, "wrong.example", "wrong", 89, now),
		testEvidence(EvidencePacketSNI, "right.example", "right", 95, now),
	}, DefaultConfidenceThresholds)
	if d.Selected == nil || d.Selected.SetID != "right" || d.Reason != "clear SNI overrides conflicting DNS evidence" {
		t.Fatalf("decision = %+v", d)
	}
}

func TestDecideIncompleteAndECHAreNeverFinalUnknown(t *testing.T) {
	now := time.Unix(400, 0)
	ctx := testContext(now)
	ctx.InputIncomplete = true
	d := Decide(ctx, nil, DefaultConfidenceThresholds)
	if d.Phase == PhaseFinal || d.Final {
		t.Fatalf("incomplete empty decision became final: %+v", d)
	}

	ech := testEvidence(EvidenceDNSAnswer, "", "ip-fallback", 50, now)
	ech.DomainEvidence = false
	ech.ECHRelated = true
	d = Decide(testContext(now), []Evidence{ech}, DefaultConfidenceThresholds)
	if d.Phase == PhaseFinal || d.Final || !d.ECHPresent {
		t.Fatalf("ECH decision became final: %+v", d)
	}
}

func TestDecideLegacyFallbackAndThresholds(t *testing.T) {
	now := time.Unix(500, 0)
	d := Decide(testContext(now), []Evidence{testEvidence(EvidenceLegacyLearnedIP, "", "legacy", 100, now)}, DefaultConfidenceThresholds)
	if d.Selected == nil || d.Selected.Source != EvidenceLegacyLearnedIP || d.Confidence != 45 {
		t.Fatalf("legacy decision = %+v", d)
	}
	if d.CanDestructivelyMutate(DefaultConfidenceThresholds) || d.CanMutate(DefaultConfidenceThresholds) {
		t.Fatal("legacy fallback crossed mutation threshold")
	}
	if !d.CanProxyFallback(DefaultConfidenceThresholds) {
		t.Fatal("legacy fallback should remain eligible for proxy fallback")
	}
}

func TestDecideRevalidatesContext(t *testing.T) {
	now := time.Unix(600, 0)
	e := testEvidence(EvidenceDNSAnswer, "client.example", "set", 89, now)
	e.DestinationPort = 443
	e.L4Proto = 6
	e.SourceDevice = "lan0"
	ctx := testContext(now)
	ctx.ConfigGen = 8
	d := Decide(ctx, []Evidence{e}, DefaultConfidenceThresholds)
	if d.Selected != nil || d.Phase != PhaseFinal {
		t.Fatalf("stale generation was selected: %+v", d)
	}

	e = testEvidence(EvidenceDNSAnswer, "other-client.example", "set", 89, now)
	e.Client = ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.11"), IfIndex: 2, VLAN: 10}
	e.DestinationPort = 443
	e.L4Proto = 6
	e.SourceDevice = "lan0"
	d = Decide(testContext(now), []Evidence{e}, DefaultConfidenceThresholds)
	if d.Selected != nil {
		t.Fatalf("cross-client evidence was selected: %+v", d)
	}

	ctx = testContext(now)
	ctx.Client = e.Client
	ctx.DestinationPort = 443
	ctx.L4Proto = 6
	ctx.SourceDevice = "guest0"
	d = Decide(ctx, []Evidence{e}, DefaultConfidenceThresholds)
	if d.Selected != nil {
		t.Fatalf("source-device evidence was selected across interfaces: %+v", d)
	}
	ctx.SourceDevice = "lan0"
	d = Decide(ctx, []Evidence{e}, DefaultConfidenceThresholds)
	if d.Selected == nil {
		t.Fatalf("valid protocol/device evidence was rejected: %+v", d)
	}
}

func (e Evidence) withExpiry(expiry time.Time) Evidence {
	e.ExpiresAt = expiry
	return e
}

func FuzzDecideNeverPanics(f *testing.F) {
	f.Add("example.com", "set", uint8(89), uint8(EvidenceDNSAnswer), false)
	f.Add("", "fallback", uint8(45), uint8(EvidenceLegacyLearnedIP), true)
	f.Fuzz(func(t *testing.T, domain, set string, confidence, source uint8, expired bool) {
		now := time.Unix(700, 0)
		e := Evidence{
			Source:         EvidenceSource(source % uint8(EvidencePortProtocol+1)),
			Client:         testClient(),
			DestinationIP:  netip.MustParseAddr("203.0.113.7"),
			Domain:         domain,
			SetID:          set,
			Confidence:     confidence,
			DomainEvidence: domain != "",
			CreatedAt:      now.Add(-time.Second),
			ConfigGen:      7,
		}
		if expired {
			e.ExpiresAt = now.Add(-time.Second)
		} else {
			e.ExpiresAt = now.Add(time.Minute)
		}
		decision := Decide(testContext(now), []Evidence{e}, DefaultConfidenceThresholds)
		_ = decision.CanClassify(DefaultConfidenceThresholds)
		_ = decision.CanMutate(DefaultConfidenceThresholds)
		_ = decision.CanDestructivelyMutate(DefaultConfidenceThresholds)
		_ = decision.CanProxyFallback(DefaultConfidenceThresholds)
	})
}
