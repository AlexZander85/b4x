package nfq

import (
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fixtures"
)

func TestNFQDomainOnlyDecisionModes(t *testing.T) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	set := config.NewSetConfig()
	set.Id = "domain-only"
	set.Name = "domain-only"
	set.Enabled = true
	set.Targets.DomainOnly = true
	cfg.Sets = []*config.SetConfig{&set}
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 60), dst: net.IPv4(203, 0, 113, 60), srcMac: "aa:bb:cc:dd:ee:60"}

	cfg.System.Classifier.DomainOnlyMode = config.DomainStrict
	if worker.allowNFQDomainDecision(&cfg, pkt, 443, 6, &set, classifier.EvidenceStaticIP, "", false, "test") {
		t.Fatal("strict DomainOnly accepted static IP evidence")
	}
	if !worker.allowNFQDomainDecision(&cfg, pkt, 443, 6, &set, classifier.EvidencePacketSNI, "api.youtube.com", true, "test") {
		t.Fatal("strict DomainOnly rejected clear SNI evidence")
	}

	cfg.System.Classifier.DomainOnlyMode = config.DomainScopedHints
	if !worker.allowNFQDomainDecision(&cfg, pkt, 443, 6, &set, classifier.EvidenceDNSAnswer, "api.youtube.com", true, "test") {
		t.Fatal("scoped-hints DomainOnly rejected DNS domain evidence")
	}

	cfg.System.Classifier.DomainOnlyMode = config.DomainDisabled
	if !worker.allowNFQDomainDecision(&cfg, pkt, 443, 6, &set, classifier.EvidenceStaticIP, "", false, "test") {
		t.Fatal("disabled DomainOnly rejected configured static fallback")
	}

	cfg.System.Classifier.DomainOnlyMode = config.DomainLegacy
	if !worker.allowNFQDomainDecision(&cfg, pkt, 443, 6, &set, classifier.EvidenceStaticIP, "", false, "test") {
		t.Fatal("legacy DomainOnly compatibility rejected existing static path")
	}
}

func TestNFQECHMetadataReachesScopedDecision(t *testing.T) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.ClassifierV2Enabled = true
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 61), dst: net.IPv4(203, 0, 113, 61), srcMac: ""}
	now := time.Now()
	decision := worker.decideNFQEvidenceWithMetadata(&cfg, pkt, 443, 6, classifier.TLSMetadata{ECHPresent: true}, classifier.Evidence{
		Source:         classifier.EvidenceDNSAnswer,
		Domain:         "api.youtube.com",
		SetID:          "youtube-api",
		Confidence:     89,
		DomainEvidence: true,
		CreatedAt:      now.Add(-time.Second),
		ExpiresAt:      now.Add(time.Minute),
	})
	if decision.Selected == nil || !decision.ECHPresent || decision.Final || decision.CanUseHostMarkers() {
		t.Fatalf("NFQ ECH decision = %+v", decision)
	}
}

func TestNFQTLSMetadataDetectsECHWithoutClearHost(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Classifier.Flags.TCPReassemblyMode = config.ReassemblyObserve
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 62), dst: net.IPv4(203, 0, 113, 62)}
	metadata := worker.tcpTLSDecisionMetadata(&cfg, pkt, 51000, 443, fixtures.TLSCorpus()[9].Record)
	if !metadata.ECHPresent || metadata.ClearSNI || !metadata.HandshakeParsed {
		t.Fatalf("ECH TLS metadata = %+v", metadata)
	}
}

func TestLearnedIPAuthorizationAllowedPolicyMatrix(t *testing.T) {
	domainOnly := config.NewSetConfig()
	domainOnly.Id = "cdn"
	domainOnly.Name = "cdn"
	domainOnly.Enabled = true
	domainOnly.Targets.DomainOnly = true

	nonDomainOnly := config.NewSetConfig()
	nonDomainOnly.Id = "routed"
	nonDomainOnly.Name = "routed"
	nonDomainOnly.Enabled = true
	nonDomainOnly.Targets.DomainOnly = false

	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()

	if learnedIPAuthorizationAllowed(nil, &domainOnly) {
		t.Fatal("nil config must not authorize learned-IP evidence")
	}
	if learnedIPAuthorizationAllowed(&cfg, nil) {
		t.Fatal("nil set must not authorize learned-IP evidence")
	}

	tests := []struct {
		name   string
		mode   string
		set    *config.SetConfig
		policy config.DomainPolicy
		want   bool
	}{
		{name: "non domain-only set", mode: config.DomainLegacy, set: &nonDomainOnly, want: true},
		{name: "non domain-only strict global", mode: config.DomainStrict, set: &nonDomainOnly, want: true},
		{name: "legacy global inherit", mode: config.DomainLegacy, set: &domainOnly, want: true},
		{name: "strict explicit", mode: config.DomainLegacy, set: &domainOnly, policy: config.DomainPolicyStrict, want: false},
		{name: "scoped-hints explicit", mode: config.DomainLegacy, set: &domainOnly, policy: config.DomainPolicyScopedHints, want: false},
		{name: "disabled explicit", mode: config.DomainLegacy, set: &domainOnly, policy: config.DomainPolicyDisabled, want: false},
		{name: "strict global inherit", mode: config.DomainStrict, set: &domainOnly, want: false},
		{name: "scoped-hints global inherit", mode: config.DomainScopedHints, set: &domainOnly, want: false},
		{name: "disabled global inherit", mode: config.DomainDisabled, set: &domainOnly, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg.System.Classifier.DomainOnlyMode = tc.mode
			if tc.set != nil {
				tc.set.Targets.DomainPolicy = tc.policy
			}
			if got := learnedIPAuthorizationAllowed(&cfg, tc.set); got != tc.want {
				t.Fatalf("learnedIPAuthorizationAllowed(mode=%q policy=%q) = %v, want %v", tc.mode, tc.policy, got, tc.want)
			}
		})
	}
}

func TestLearnedIPAuthorizationGatesLegacyCacheDecision(t *testing.T) {
	// The legacy destination-keyed cache is a routing-learn store (DomainOnly
	// sets are rejected at LearnIPToDomain), so the authorization guard must
	// keep it available in pure legacy mode and refuse it whenever the v2
	// decision path or a non-legacy domain policy is in effect.
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.DomainOnlyMode = config.DomainLegacy

	set := config.NewSetConfig()
	set.Id = "cdn"
	set.Name = "cdn"
	set.Enabled = true
	cfg.Sets = []*config.SetConfig{&set}

	matcher := buildMatcher(&cfg)
	matcher.LearnIPToDomain(net.IPv4(203, 0, 113, 66), "cdn.example", &set)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 66), dst: net.IPv4(203, 0, 113, 66), srcMac: "aa:bb:cc:dd:ee:66"}

	mLearned, learnedSet, _ := matcher.MatchLearnedIPWithSource(pkt.dst, pkt.srcMac)
	if !mLearned || learnedSet == nil {
		t.Fatal("legacy learned-IP cache did not match for fixture")
	}

	if !learnedIPAuthorizationAllowed(&cfg, learnedSet) {
		t.Fatal("pure legacy mode must authorize routing-learn evidence")
	}

	// The moment a strict/scoped-hints policy exists anywhere in the effective
	// decision path, the legacy cache must not participate. The handler-level
	// gate (classifierDecisionEnabled) blocks the whole branch; this guard
	// additionally refuses a domain-only set with an explicit non-legacy
	// policy, which is the per-set escape hatch the audit demanded.
	domainOnly := config.NewSetConfig()
	domainOnly.Id = "cdn-do"
	domainOnly.Name = "cdn-do"
	domainOnly.Enabled = true
	domainOnly.Targets.DomainOnly = true
	domainOnly.Targets.DomainPolicy = config.DomainPolicyStrict
	if learnedIPAuthorizationAllowed(&cfg, &domainOnly) {
		t.Fatal("strict per-set policy must not authorize legacy learned-IP evidence")
	}
}

