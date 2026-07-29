package nfq

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
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
