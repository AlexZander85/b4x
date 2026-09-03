package nfq

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/sni"
)

func TestResolveAuthoritativeTLSObservationUsesCompleteReassembly(t *testing.T) {
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	result := classifier.TCPReassemblyResult{
		Status: classifier.ReassemblyComplete, Metadata: sni.ParseTLSClientHelloMetadata(hello),
		ClientHelloID: 17, ConfigGen: 9,
	}
	observation := resolveAuthoritativeTLSObservation(hello[:7], result)
	if observation.Host != "api.youtube.com" || observation.Source != classifier.EvidenceReassembledSNI || !observation.Complete {
		t.Fatalf("unexpected authoritative observation: %+v", observation)
	}
	if observation.ClientHelloID != 17 || observation.ConfigGen != 9 {
		t.Fatalf("scope lost: %+v", observation)
	}
}

func TestResolveAuthoritativeTLSObservationRejectsConflict(t *testing.T) {
	packet := fixtures.BuildTLSClientHello("mail.google.com", 0x0304, false, 0)
	reassembled := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	result := classifier.TCPReassemblyResult{Status: classifier.ReassemblyComplete, Metadata: sni.ParseTLSClientHelloMetadata(reassembled), ClientHelloID: 23}
	observation := resolveAuthoritativeTLSObservation(packet, result)
	if !observation.Conflict || observation.Host != "" {
		t.Fatalf("conflict did not fail closed for mutation: %+v", observation)
	}
}

func TestClientHelloDecisionClaimIsExactFlowAndGenerationScoped(t *testing.T) {
	store := newClientHelloDecisionClaimStore()
	client := classifier.ClientKey{SourceIP: netip.MustParseAddr("192.0.2.10")}
	first := classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.5"), 41000, 443, 6)
	second := classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.5"), 41001, 443, 6)
	now := time.Unix(100, 0)
	if !store.Claim(first, 77, 3, now) || store.Claim(first, 77, 3, now.Add(time.Millisecond)) {
		t.Fatal("logical ClientHello was not claimed exactly once")
	}
	if !store.Claim(second, 77, 3, now) {
		t.Fatal("another flow incorrectly reused the first flow claim")
	}
	if !store.Claim(first, 77, 4, now) {
		t.Fatal("new config generation incorrectly reused old claim")
	}
}

func TestReassembledSNIDecisionCarriesExactFlowAndLayoutParity(t *testing.T) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.ClassifierV2Enabled = true
	cfg.System.Classifier.DomainOnlyMode = config.DomainStrict
	set := config.NewSetConfig()
	set.Id = "youtube"
	set.Name = "youtube"
	set.Enabled = true
	set.Targets.DomainOnly = true
	cfg.Sets = []*config.SetConfig{&set}
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 77), dst: net.IPv4(203, 0, 113, 77), srcMac: "aa:bb:cc:dd:ee:77"}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		t.Fatal("client identity unavailable")
	}
	flow := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), 51177, 443, 6)
	generation := dnsHintConfigGeneration(&cfg)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 2048)

	complete := func(parts int) classifier.TCPReassemblyResult {
		store := classifier.NewTCPReassemblyStore(classifier.DefaultTCPReassemblyConfig())
		store.Start(flow, 15000, generation)
		step := (len(hello) + parts - 1) / parts
		var result classifier.TCPReassemblyResult
		for start := 0; start < len(hello); start += step {
			end := start + step
			if end > len(hello) {
				end = len(hello)
			}
			result = store.Observe(flow, 15000+uint32(start), hello[start:end], generation)
		}
		return result
	}
	gso := complete(1)
	mss := complete(5)
	if gso.ClientHelloID == 0 || gso.ClientHelloID != mss.ClientHelloID {
		t.Fatalf("logical ClientHello parity lost: gso=%+v mss=%+v", gso, mss)
	}

	decide := func(result classifier.TCPReassemblyResult) classifier.ClassificationDecision {
		observation := resolveAuthoritativeTLSObservation(nil, result)
		return worker.decideNFQEvidenceScoped(&cfg, pkt, 443, 6,
			classifier.TLSMetadata{Version: observation.TLSVersion, ClearSNI: true, HandshakeParsed: true},
			nfqDecisionScope{FlowKey: flow, ClientHelloID: observation.ClientHelloID, EvidenceConfigGen: observation.ConfigGen, CompleteClientHello: observation.Complete, TLSVersion: observation.TLSVersion},
			classifier.Evidence{Source: observation.Source, Domain: observation.Host, SetID: set.Id, DomainEvidence: true})
	}
	gsoDecision := decide(gso)
	mssDecision := decide(mss)
	if gsoDecision.Selected == nil || mssDecision.Selected == nil || gsoDecision.Selected.SetID != mssDecision.Selected.SetID || gsoDecision.ClientHelloID != mssDecision.ClientHelloID || gsoDecision.FlowKey != flow || !gsoDecision.Final || !mssDecision.Final {
		t.Fatalf("layout decision mismatch: gso=%+v mss=%+v", gsoDecision, mssDecision)
	}
	if gsoDecision.Selected.Source.String() != "reassembled-tcp-sni" {
		t.Fatalf("unexpected provenance: %q", gsoDecision.Selected.Source.String())
	}
}
