package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

func appendStructuredRR(body []byte, name []byte, typ, class uint16, ttl uint32, rdata []byte) []byte {
	body = append(body, name...)
	header := make([]byte, 10)
	binary.BigEndian.PutUint16(header[0:2], typ)
	binary.BigEndian.PutUint16(header[2:4], class)
	binary.BigEndian.PutUint32(header[4:8], ttl)
	binary.BigEndian.PutUint16(header[8:10], uint16(len(rdata)))
	body = append(body, header...)
	return append(body, rdata...)
}

func appendHTTPSRData(priority uint16, target string, params ...struct {
	key   uint16
	value []byte
}) []byte {
	rdata := make([]byte, 2)
	binary.BigEndian.PutUint16(rdata, priority)
	rdata = append(rdata, encodeDNSName(target)...)
	for _, param := range params {
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[0:2], param.key)
		binary.BigEndian.PutUint16(header[2:4], uint16(len(param.value)))
		rdata = append(rdata, header...)
		rdata = append(rdata, param.value...)
	}
	return rdata
}

func TestParseStructuredResponseAaaaCNAMEHTTPSAndSVCB(t *testing.T) {
	qname := encodeDNSName("alias.example.com")
	body := append([]byte{}, qname...)
	body = append(body, 0x00, 0x01, 0x00, 0x01) // question A/IN
	body = appendStructuredRR(body, []byte{0xc0, 0x0c}, 5, 1, 30, encodeDNSName("cdn.example.com"))
	body = appendStructuredRR(body, encodeDNSName("cdn.example.com"), 1, 1, 60, []byte{1, 2, 3, 4})
	ipv6 := netip.MustParseAddr("2001:db8::42").As16()
	body = appendStructuredRR(body, encodeDNSName("cdn.example.com"), 28, 1, 90, ipv6[:])
	echt := appendHTTPSRData(0, "svc.example.com",
		struct {
			key   uint16
			value []byte
		}{1, []byte("h2")},
		struct {
			key   uint16
			value []byte
		}{5, []byte{1, 2, 3, 4}},
	)
	body = appendStructuredRR(body, []byte{0xc0, 0x0c}, 65, 1, 120, echt)
	svcb := appendHTTPSRData(1, "svc.example.com",
		struct {
			key   uint16
			value []byte
		}{3, []byte{0x01, 0xbb}},
	)
	body = appendStructuredRR(body, []byte{0xc0, 0x0c}, 64, 1, 45, svcb)
	message := buildDNSResponse(1, 5, body)

	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.20"), VLAN: 10}
	now := time.Unix(1000, 0)
	observation, err := ParseStructuredResponse(message, client, "resolver-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if observation.TransactionID != 0x1234 || observation.QueryName != "alias.example.com" || observation.Canonical != "cdn.example.com" || observation.ResolverID != "resolver-a" || !observation.Timestamp.Equal(now) {
		t.Fatalf("observation metadata = %+v", observation)
	}
	if len(observation.Answers) != 2 || observation.Answers[0].IP != netip.MustParseAddr("1.2.3.4") || observation.Answers[0].CanonicalName != "cdn.example.com" || observation.Answers[0].TTLSeconds != 60 {
		t.Fatalf("address answers = %+v", observation.Answers)
	}
	if len(observation.HTTPSRecords) != 2 {
		t.Fatalf("HTTPS/SVCB records = %+v", observation.HTTPSRecords)
	}
	if !observation.HTTPSRecords[0].HasECHConfig || len(observation.HTTPSRecords[0].ECHConfig) != 4 || string(observation.HTTPSRecords[0].Params[1]) != "h2" {
		t.Fatalf("ECH/ALPN metadata = %+v", observation.HTTPSRecords[0])
	}
	if observation.HTTPSRecords[1].HasECHConfig || observation.HTTPSRecords[1].Priority != 1 || observation.HTTPSRecords[1].Target != "svc.example.com" {
		t.Fatalf("SVCB metadata = %+v", observation.HTTPSRecords[1])
	}
}

func TestParseStructuredResponseNegativeAndTruncatedMetadata(t *testing.T) {
	query := buildDNSQuery(0x5555, "missing.example", 1)
	nxdomain := append([]byte(nil), query...)
	// QR + RD + RA + NXDOMAIN, preserving the question section.
	binary.BigEndian.PutUint16(nxdomain[2:4], 0x8183)
	observation, err := ParseStructuredResponse(nxdomain, classifier.ClientKey{}, "resolver", time.Unix(1, 0))
	if err != nil || observation.RCode != 3 || len(observation.Answers) != 0 {
		t.Fatalf("NXDOMAIN = %+v err=%v", observation, err)
	}
	truncated := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(truncated[2:4], 0x8380) // QR + TC + RD + NOERROR
	observation, err = ParseStructuredResponse(truncated, classifier.ClientKey{}, "resolver", time.Unix(1, 0))
	if err != nil || !observation.Truncated {
		t.Fatalf("truncated metadata = %+v err=%v", observation, err)
	}
}

func TestParseStructuredResponseRejectsMalformedAndCNAMELoops(t *testing.T) {
	qname := encodeDNSName("loop.example")
	body := append([]byte{}, qname...)
	body = append(body, 0x00, 0x01, 0x00, 0x01)
	// Answer name pointer to itself. The answer starts at DNS header 12 + body question.
	answerOffset := 12 + len(body)
	body = appendStructuredRR(body, []byte{0xc0, byte(answerOffset)}, 5, 1, 10, encodeDNSName("loop.example"))
	message := buildDNSResponse(1, 1, body)
	if _, err := ParseStructuredResponse(message, classifier.ClientKey{}, "", time.Unix(1, 0)); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("CNAME pointer loop error = %v", err)
	}

	body = append([]byte{}, qname...)
	body = append(body, 0x00, 0x01, 0x00, 0x01)
	body = appendStructuredRR(body, []byte{0xc0, 0x0c}, 1, 1, 10, []byte{1, 2, 3})
	message = buildDNSResponse(1, 1, body)
	if _, err := ParseStructuredResponse(message, classifier.ClientKey{}, "", time.Unix(1, 0)); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("short A error = %v", err)
	}
}

func FuzzParseStructuredResponseNeverPanics(f *testing.F) {
	f.Add(buildDNSQuery(1, "example.com", 1))
	f.Add([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = ParseStructuredResponse(payload, classifier.ClientKey{}, "fuzz", time.Unix(2, 0))
	})
}
