package providers

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/faultlab"
)

func TestUDPTruncationRequiresFallbackAndNeverResolvesAsComplete(t *testing.T) {
	fx, addr, err := faultlab.StartUDP(faultlab.ModeTruncation)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := NewUDPProvider(netip.MustParseAddr("127.0.0.1"), faultlab.PortOf(addr), 0, "lab")
	p.Timeout = time.Second
	prepared, err := p.Prepare(context.Background(), dnspath.DNSPrepareRequest{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class != dnspath.OutcomeTruncatedRequiresTCP {
		t.Fatalf("TC response class=%s", out.Class)
	}
	if _, err := p.Resolve(context.Background(), prepared, dnspath.DNSQuery{Name: "example.com", QType: 1, TxID: 1}); err == nil {
		t.Fatal("truncated UDP response must never be returned as a complete production answer")
	}
}

func TestUDPEarlyConflictingResponseIsInjectionEvidence(t *testing.T) {
	fx, addr, err := faultlab.StartUDP(faultlab.ModeEarlyInjection)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := NewUDPProvider(netip.MustParseAddr("127.0.0.1"), faultlab.PortOf(addr), 0, "lab")
	p.Timeout = time.Second
	p.RaceWindow = 150 * time.Millisecond
	prepared, err := p.Prepare(context.Background(), dnspath.DNSPrepareRequest{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{
		Name: "example.com", QType: 1, SuiteCase: "A", ObserveRace: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class != dnspath.OutcomeEarlyInjectionSuspected {
		t.Fatalf("conflicting early/later responses class=%s", out.Class)
	}
}

func TestSERVFAILIsNotCorrectnessEvidenceAndForcesProductionFallback(t *testing.T) {
	query := b4dns.BuildQuery("example.com", 0x1234, 1)
	resp := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8182) // QR,RD,RA,SERVFAIL
	obs, err := b4dns.ParseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	fp := dnspath.FingerprintObservation(obs)
	out := dnspath.DNSPathProbeOutcome{}
	completeProbeEvidence(&out, resp, dnspath.DNSProbeQuery{Name: "example.com", QType: 1, SuiteCase: "A"}, obs, fp)
	if out.Class.Pass() || out.Class != dnspath.OutcomeRCodeMismatch {
		t.Fatalf("SERVFAIL probe classification=%s", out.Class)
	}
	if err := validateProductionResponse(resp, obs); err == nil {
		t.Fatal("SERVFAIL must be a provider failure so Manager can try a validated fallback")
	}
}
