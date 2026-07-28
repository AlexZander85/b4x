package fixtures

import (
	"bytes"
	"net"
	"testing"

	"github.com/daniellavrushin/b4/dns"
	"github.com/daniellavrushin/b4/sni"
)

func TestTLSCorpusCoverageAndDeterminism(t *testing.T) {
	first := TLSCorpus()
	second := TLSCorpus()
	if len(first) != len(second) || len(first) < 15 {
		t.Fatalf("unexpected corpus size: %d/%d", len(first), len(second))
	}
	for i := range first {
		if first[i].Name != second[i].Name || !bytes.Equal(first[i].Record, second[i].Record) {
			t.Fatalf("fixture %q is not deterministic", first[i].Name)
		}
		if len(first[i].Segments) > 0 {
			var stream []byte
			for _, segment := range first[i].Segments {
				stream = append(stream, segment.Payload...)
			}
			if !bytes.Equal(stream, first[i].Record) {
				t.Errorf("fixture %q segments do not cover record", first[i].Name)
			}
		}
	}
}

func TestTLSParserBaselineCorpus(t *testing.T) {
	for _, fixture := range TLSCorpus() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			host, version, ok := sni.ParseTLSClientHelloSNI(fixture.Record)
			if fixture.Malformed || fixture.ECH {
				if ok || host != "" || version != 0 {
					t.Fatalf("expected no clear SNI for malformed/ECH fixture, got host=%q version=%#x ok=%v", host, version, ok)
				}
				return
			}
			if fixture.Host == "" {
				t.Fatalf("fixture has no expected host")
			}
			if !ok || host != fixture.Host || version != fixture.TLSVersion {
				t.Fatalf("got host=%q version=%#x ok=%v, want host=%q version=%#x", host, version, ok, fixture.Host, fixture.TLSVersion)
			}
		})
	}
}

func TestTLSCorpusRetransmissionAndOverlapMetadata(t *testing.T) {
	for _, fixture := range TLSCorpus() {
		switch fixture.Name {
		case "exact-retransmission":
			if len(fixture.Retransmit) != 2 || !bytes.Equal(fixture.Retransmit[0].Payload, fixture.Retransmit[1].Payload) || fixture.Retransmit[0].Seq != fixture.Retransmit[1].Seq {
				t.Fatalf("exact retransmission fixture is not exact: %+v", fixture.Retransmit)
			}
		case "identical-overlap", "conflicting-overlap":
			if fixture.Overlap == OverlapNone {
				t.Fatalf("fixture %q lacks overlap classification", fixture.Name)
			}
		}
	}
}

func TestDNSCorpusBaseline(t *testing.T) {
	for _, fixture := range DNSCorpus() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			ips := dns.ParseResponseIPs(fixture.Response)
			if fixture.RCode != 0 {
				if len(ips) != 0 {
					t.Fatalf("rcode=%d response returned IPs: %v", fixture.RCode, ips)
				}
				return
			}
			wantIPs := 0
			for _, answer := range fixture.Answers {
				if answer.Type == 1 || answer.Type == 28 {
					wantIPs++
				}
			}
			if len(ips) != wantIPs {
				t.Fatalf("got %d IPs, want %d", len(ips), wantIPs)
			}
			if fixture.Name == "a-and-aaaa" && (!ips[0].Equal(net.IPv4(142, 250, 72, 14)) || !ips[1].Equal(net.ParseIP("2001:db8::14"))) {
				t.Fatalf("unexpected A/AAAA result: %v", ips)
			}
		})
	}
}

func TestTCPCorpusCoverage(t *testing.T) {
	seen := map[string]bool{}
	for _, fixture := range TCPCorpus() {
		seen[fixture.Name] = true
	}
	for _, name := range []string{"clean-syn", "syn-explicit-fake", "syn-ack", "fin", "rst", "tfo-payload", "sequence-wrap", "retransmission-after-action", "serverhello-progress"} {
		if !seen[name] {
			t.Errorf("missing TCP fixture %q", name)
		}
	}
}

func TestAndroidCorpusMetadata(t *testing.T) {
	flows, err := AndroidCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 4 {
		t.Fatalf("got %d Android metadata flows, want 4", len(flows))
	}
	for _, flow := range flows {
		if flow.ID == "" || flow.Product == "" || flow.Domain == "" || flow.PayloadStatus != "sanitized-metadata-only" {
			t.Errorf("incomplete or unsafe Android metadata: %+v", flow)
		}
	}
}
