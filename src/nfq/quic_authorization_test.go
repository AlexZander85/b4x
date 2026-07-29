package nfq

import (
	"net"
	"testing"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
)

func TestQUICGlobalFallbackRequiresExplicitDisabledDomainPolicy(t *testing.T) {
	cfg := config.NewConfig()
	set := config.NewSetConfig()
	set.Id = "youtube"
	set.Name = "youtube"
	set.Targets.DomainOnly = true
	set.Targets.DomainPolicy = config.DomainPolicyScopedHints
	cfg.Sets = []*config.SetConfig{&set}
	if quicSetCanUseGlobalFallback(&cfg, &set) {
		t.Fatal("domain-scoped set received IP-only QUIC fallback")
	}
	set.Targets.DomainPolicy = config.DomainPolicyDisabled
	if !quicSetCanUseGlobalFallback(&cfg, &set) {
		t.Fatal("explicit disabled policy did not retain global set semantics")
	}
}

func TestQUICActionGateIsFlowAndGenerationStable(t *testing.T) {
	cfg := config.NewConfig()
	cfg.RuntimeGeneration = "g1"
	set := config.NewSetConfig()
	set.Id = "youtube"
	set.Name = "youtube"
	pkt := &pktInfo{src: net.ParseIP("192.0.2.10"), dst: net.ParseIP("203.0.113.5"), srcMac: "aa:bb:cc:dd:ee:ff"}
	first := newQUICActionGate(&cfg, pkt, 40000, 443, &set, classifier.EvidenceQUICSNI, true, "test")
	second := newQUICActionGate(&cfg, pkt, 40000, 443, &set, classifier.EvidenceQUICSNI, true, "test")
	if !first.Authorized || first.ID == "" || first.ID != second.ID {
		t.Fatalf("unstable gate: first=%+v second=%+v", first, second)
	}
	cfg.RuntimeGeneration = "g2"
	third := newQUICActionGate(&cfg, pkt, 40000, 443, &set, classifier.EvidenceQUICSNI, true, "test")
	if third.ID == first.ID {
		t.Fatal("config generation did not scope QUIC authorization")
	}
}
