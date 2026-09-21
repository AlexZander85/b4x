package providers

import (
	"encoding/binary"
	"testing"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

func encodeTestName(name string) []byte {
	var out []byte
	label := ""
	for _, c := range name {
		if c == '.' {
			if label != "" {
				out = append(out, byte(len(label)))
				out = append(out, label...)
				label = ""
			}
			continue
		}
		label += string(c)
	}
	if label != "" {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// buildNODATA builds a NOERROR/NODATA response with an authority SOA (RFC 2308
// negative, no answer record) — the shape a special-use/wildcard zone returns
// for "nonexistent.<target>".
func buildNODATA(t *testing.T, name string) []byte {
	t.Helper()
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180) // response, RA, rcode 0
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // qd
	binary.BigEndian.PutUint16(hdr[8:10], 1)     // ns (authority SOA)
	b := append([]byte(nil), hdr...)
	b = append(b, encodeTestName(name)...)
	b = append(b, 0, 1, 0, 1) // QTYPE A, QCLASS IN

	rdata := encodeTestName("ns1.example.")
	rdata = append(rdata, encodeTestName("hostmaster.example.")...)
	tail := make([]byte, 20)
	binary.BigEndian.PutUint32(tail[0:4], 1)
	binary.BigEndian.PutUint32(tail[4:8], 3600)
	binary.BigEndian.PutUint32(tail[8:12], 600)
	binary.BigEndian.PutUint32(tail[12:16], 86400)
	binary.BigEndian.PutUint32(tail[16:20], 60)
	rdata = append(rdata, tail...)

	rr := []byte{0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 60, byte(len(rdata) >> 8), byte(len(rdata))}
	rr = append(rr, rdata...)
	return append(b, rr...)
}

func TestNODATANegativeIsAcceptedForNXDOMAINCase(t *testing.T) {
	payload := buildNODATA(t, "nonexistent.example.com")
	if _, err := b4dns.InspectResponseMetadata(payload); err != nil {
		t.Fatalf("fixture must parse: %v", err)
	}
	out := dnspath.DNSPathProbeOutcome{}
	completeProbeEvidence(&out, payload, dnspath.DNSProbeQuery{
		Name: "nonexistent.example.com", QType: 1, SuiteCase: "NXDOMAIN",
	}, b4dns.DNSObservation{RCode: 0}, dnspath.ResponseFingerprint{})
	if out.Class != dnspath.OutcomeInconclusive {
		t.Fatalf("proved NODATA negative must be Inconclusive, got class=%s failure=%s", out.Class, out.FailureCode)
	}
}

func TestBareNXDOMAINWithoutSOAIsStillRejected(t *testing.T) {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8183) // rcode 3 NXDOMAIN
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	b := append([]byte(nil), hdr...)
	b = append(b, encodeTestName("nonexistent.example.com")...)
	b = append(b, 0, 1, 0, 1)
	out := dnspath.DNSPathProbeOutcome{}
	completeProbeEvidence(&out, b, dnspath.DNSProbeQuery{
		Name: "nonexistent.example.com", QType: 1, SuiteCase: "NXDOMAIN",
	}, b4dns.DNSObservation{RCode: 3}, dnspath.ResponseFingerprint{})
	if out.Class == dnspath.OutcomeInconclusive {
		t.Fatalf("bare NXDOMAIN without SOA proof must not be accepted")
	}
}
