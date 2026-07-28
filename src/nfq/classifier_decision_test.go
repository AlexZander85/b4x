package nfq

import (
	"net"
	"testing"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
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
