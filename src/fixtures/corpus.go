// Package fixtures contains deterministic, sanitized regression material used
// by the classifier stages. It intentionally contains no live client data.
package fixtures

import (
	"bytes"
	"embed"
	"encoding/binary"
	"encoding/json"
	"net"
)

// Segment is a TCP stream fragment. Seq is relative to the beginning of the
// fixture stream so tests do not depend on a real connection tuple.
type Segment struct {
	Seq     uint32
	Payload []byte
}

type OverlapKind string

const (
	OverlapNone        OverlapKind = "none"
	OverlapIdentical   OverlapKind = "identical"
	OverlapConflicting OverlapKind = "conflicting"
)

type TLSFixture struct {
	Name          string
	Host          string
	TLSVersion    uint16
	Record        []byte
	Segments      []Segment
	OutOfOrder    []Segment
	Retransmit    []Segment
	Overlap       OverlapKind
	ECH           bool
	Malformed     bool
	TargetSegment int
}

type DNSAnswer struct {
	Type   uint16
	TTL    uint32
	IP     net.IP
	Target string
	Data   []byte
}

type DNSFixture struct {
	Name        string
	Domain      string
	Client      string
	SharedIP    string
	Transaction uint16
	Response    []byte
	RCode       uint8
	Answers     []DNSAnswer
}

type TCPFixture struct {
	Name                 string
	Seq                  uint32
	Ack                  uint32
	Flags                uint8
	Payload              []byte
	ExplicitSYNTechnique bool
}

type AndroidFlow struct {
	ID                string `json:"id"`
	Product           string `json:"product"`
	Domain            string `json:"domain"`
	Transport         string `json:"transport"`
	FirstVerdict      string `json:"first_verdict"`
	LaterClearSNI     bool   `json:"later_clear_sni"`
	QUICToTCPFallback bool   `json:"quic_to_tcp_fallback"`
	ECHOuterHello     bool   `json:"ech_outer_client_hello"`
	PayloadStatus     string `json:"payload_status"`
}

// The metadata is intentionally embedded so tests can verify the corpus
// without depending on the filesystem or an Android capture being present.
//
//go:embed android_corpus.json
var androidCorpus embed.FS

func AndroidCorpus() ([]AndroidFlow, error) {
	b, err := androidCorpus.ReadFile("android_corpus.json")
	if err != nil {
		return nil, err
	}
	var flows []AndroidFlow
	if err := json.Unmarshal(b, &flows); err != nil {
		return nil, err
	}
	return flows, nil
}

// BuildTLSClientHello builds a deterministic TLS record suitable for parser
// tests. targetSize adds a legal padding extension and is useful for the
// Android-sized 1.7–2.0 KiB cases.
func BuildTLSClientHello(host string, tlsVersion uint16, ech bool, targetSize int) []byte {
	if tlsVersion == 0 {
		tlsVersion = 0x0303
	}

	var extensions []byte
	if host != "" {
		name := make([]byte, 0, 5+len(host))
		serverNameListLen := 1 + 2 + len(host)
		name = appendU16(name, uint16(serverNameListLen))
		name = append(name, 0)
		name = appendU16(name, uint16(len(host)))
		name = append(name, host...)
		extensions = appendExtension(extensions, 0x0000, name)
	}

	versions := []byte{4, 0x03, 0x03, 0x03, 0x04}
	if tlsVersion == 0x0303 {
		versions = []byte{2, 0x03, 0x03}
	}
	extensions = appendExtension(extensions, 0x002b, versions)
	if ech {
		extensions = appendExtension(extensions, 0xfe0d, []byte{0, 1, 0, 0, 0, 0, 0, 0})
	}

	body := clientHelloBody(tlsVersion, extensions)
	record := tlsRecord(body)
	if targetSize > len(record)+4 {
		paddingLen := targetSize - len(record) - 4
		extensions = appendExtension(extensions, 0x0015, make([]byte, paddingLen))
		body = clientHelloBody(tlsVersion, extensions)
		record = tlsRecord(body)
	}
	return record
}

func appendU16(dst []byte, n uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	return append(dst, b[:]...)
}

func appendExtension(dst []byte, typ uint16, data []byte) []byte {
	dst = appendU16(dst, typ)
	dst = appendU16(dst, uint16(len(data)))
	return append(dst, data...)
}

func clientHelloBody(version uint16, extensions []byte) []byte {
	body := make([]byte, 0, 40+len(extensions))
	body = appendU16(body, version)
	for i := 0; i < 32; i++ {
		body = append(body, byte(i))
	}
	body = append(body, 0) // session ID length
	body = appendU16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 1, 0) // compression methods
	body = appendU16(body, uint16(len(extensions)))
	return append(body, extensions...)
}

func tlsRecord(body []byte) []byte {
	handshake := make([]byte, 4, 4+len(body))
	handshake[0] = 1
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	return append(record, handshake...)
}

func splitAt(data []byte, cuts ...int) []Segment {
	segments := make([]Segment, 0, len(cuts)+1)
	start := 0
	seq := uint32(0)
	for _, cut := range cuts {
		if cut <= start || cut >= len(data) {
			continue
		}
		part := append([]byte(nil), data[start:cut]...)
		segments = append(segments, Segment{Seq: seq, Payload: part})
		seq += uint32(len(part))
		start = cut
	}
	if start < len(data) {
		part := append([]byte(nil), data[start:]...)
		segments = append(segments, Segment{Seq: seq, Payload: part})
	}
	return segments
}

func reorder(segments []Segment, order ...int) []Segment {
	result := make([]Segment, 0, len(order))
	for _, index := range order {
		if index >= 0 && index < len(segments) {
			result = append(result, segments[index])
		}
	}
	return result
}

func cloneSegment(s Segment) Segment {
	return Segment{Seq: s.Seq, Payload: append([]byte(nil), s.Payload...)}
}

// TLSCorpus returns the complete deterministic TLS corpus required by Stage 2.
func TLSCorpus() []TLSFixture {
	clear := BuildTLSClientHello("youtubei.googleapis.com", 0x0304, false, 0)
	large := BuildTLSClientHello("r1---sn-4g5e6nzz.googlevideo.com", 0x0304, false, 1800)
	segments := splitAt(large, 1396)
	three := splitAt(clear, len(clear)/3, len(clear)*2/3)
	five := splitAt(clear, len(clear)/5, len(clear)*2/5, len(clear)*3/5, len(clear)*4/5)
	return []TLSFixture{
		{Name: "complete-clear-sni", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: clear, Segments: []Segment{{Seq: 0, Payload: append([]byte(nil), clear...)}}, TargetSegment: 1},
		{Name: "split-1396-remainder", Host: "r1---sn-4g5e6nzz.googlevideo.com", TLSVersion: 0x0304, Record: large, Segments: segments, TargetSegment: 2},
		{Name: "split-2-segments", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: clear, Segments: splitAt(clear, len(clear)/2), TargetSegment: 2},
		{Name: "split-3-segments", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: clear, Segments: three, TargetSegment: 3},
		{Name: "split-5-segments", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: clear, Segments: five, TargetSegment: 5},
		{Name: "out-of-order", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: clear, Segments: three, OutOfOrder: reorder(three, 2, 0, 1), TargetSegment: 3},
		{Name: "exact-retransmission", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: clear, Segments: three, Retransmit: []Segment{cloneSegment(three[0]), cloneSegment(three[0])}, TargetSegment: 3},
		{Name: "identical-overlap", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: clear, Segments: three, Overlap: OverlapIdentical, TargetSegment: 3},
		{Name: "conflicting-overlap", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: clear, Segments: three, Overlap: OverlapConflicting, TargetSegment: 3},
		{Name: "ech-without-clear-sni", TLSVersion: 0x0304, Record: BuildTLSClientHello("", 0x0304, true, 0), Segments: nil, ECH: true, TargetSegment: 1},
		{Name: "multiple-records", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: append([]byte{0x14, 0x03, 0x03, 0, 1, 0}, clear...), Segments: nil, TargetSegment: 1},
		{Name: "trailing-coalesced-data", Host: "youtubei.googleapis.com", TLSVersion: 0x0304, Record: append(append([]byte(nil), clear...), 0x17, 0x03, 0x03, 0, 1, 0), Segments: nil, TargetSegment: 1},
		{Name: "malformed-nested-lengths", Record: []byte{0x16, 0x03, 0x03, 0, 4, 1, 0, 0, 0xff}, Segments: nil, Malformed: true, TargetSegment: 1},
		{Name: "tls12-compact", Host: "www.youtube.com", TLSVersion: 0x0303, Record: BuildTLSClientHello("www.youtube.com", 0x0303, false, 0), Segments: nil, TargetSegment: 1},
		{Name: "tls13-large", Host: "r1.googlevideo.com", TLSVersion: 0x0304, Record: BuildTLSClientHello("r1.googlevideo.com", 0x0304, false, 1900), Segments: nil, TargetSegment: 1},
	}
}

// BuildDNSQuery makes a standard IN query with one question.
func BuildDNSQuery(domain string, txid, qtype uint16) []byte {
	msg := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(msg[0:2], txid)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, dnsName(domain)...)
	msg = appendU16(msg, qtype)
	return appendU16(msg, 1)
}

// BuildDNSResponse makes a response preserving the question and supporting
// A/AAAA/CNAME/HTTPS/SVCB-shaped answer records.
func BuildDNSResponse(domain string, txid uint16, rcode uint8, answers []DNSAnswer) []byte {
	msg := BuildDNSQuery(domain, txid, 1)
	msg[2] = 0x81
	msg[3] = 0x80 | (rcode & 0x0f)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(answers)))
	for _, answer := range answers {
		msg = append(msg, 0xc0, 0x0c)
		msg = appendU16(msg, answer.Type)
		msg = appendU16(msg, 1)
		var ttl [4]byte
		binary.BigEndian.PutUint32(ttl[:], answer.TTL)
		msg = append(msg, ttl[:]...)
		rdata := answer.Data
		if answer.IP != nil {
			if answer.Type == 1 {
				rdata = []byte(answer.IP.To4())
			} else if answer.Type == 28 {
				rdata = []byte(answer.IP.To16())
			} else {
				rdata = []byte(answer.IP)
			}
		} else if answer.Target != "" {
			rdata = dnsName(answer.Target)
		}
		msg = appendU16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
	}
	return msg
}

func dnsName(domain string) []byte {
	var out []byte
	for _, label := range splitLabels(domain) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func splitLabels(domain string) [][]byte {
	var labels [][]byte
	for _, label := range bytes.FieldsFunc([]byte(domain), func(r rune) bool { return r == '.' }) {
		labels = append(labels, append([]byte(nil), label...))
	}
	return labels
}

// DNSCorpus includes ordinary A/AAAA, CNAME, TTL extremes, HTTPS/SVCB-shaped
// metadata, errors and the shared-IP two-client collision case.
func DNSCorpus() []DNSFixture {
	shared := net.ParseIP("142.250.72.14").To4()
	return []DNSFixture{
		{Name: "a-and-aaaa", Domain: "youtubei.googleapis.com", Client: "192.0.2.10", Transaction: 1, Answers: []DNSAnswer{{Type: 1, TTL: 60, IP: net.IPv4(142, 250, 72, 14)}, {Type: 28, TTL: 60, IP: net.ParseIP("2001:db8::14").To16()}}, Response: BuildDNSResponse("youtubei.googleapis.com", 1, 0, []DNSAnswer{{Type: 1, TTL: 60, IP: net.IPv4(142, 250, 72, 14)}, {Type: 28, TTL: 60, IP: net.ParseIP("2001:db8::14").To16()}})},
		{Name: "multiple-a-answers", Domain: "www.youtube.com", Client: "192.0.2.10", Transaction: 2, Answers: []DNSAnswer{{Type: 1, TTL: 120, IP: net.IPv4(142, 250, 72, 1)}, {Type: 1, TTL: 120, IP: net.IPv4(142, 250, 72, 2)}}, Response: BuildDNSResponse("www.youtube.com", 2, 0, []DNSAnswer{{Type: 1, TTL: 120, IP: net.IPv4(142, 250, 72, 1)}, {Type: 1, TTL: 120, IP: net.IPv4(142, 250, 72, 2)}})},
		{Name: "cname-chain", Domain: "m.youtube.com", Client: "192.0.2.10", Transaction: 3, Answers: []DNSAnswer{{Type: 5, TTL: 30, Target: "youtube-ui.example."}, {Type: 1, TTL: 30, IP: net.IPv4(142, 250, 72, 3)}}, Response: BuildDNSResponse("m.youtube.com", 3, 0, []DNSAnswer{{Type: 5, TTL: 30, Target: "youtube-ui.example."}, {Type: 1, TTL: 30, IP: net.IPv4(142, 250, 72, 3)}})},
		{Name: "ttl-zero", Domain: "zero.example", Client: "192.0.2.10", Transaction: 4, Answers: []DNSAnswer{{Type: 1, TTL: 0, IP: net.IPv4(192, 0, 2, 44)}}, Response: BuildDNSResponse("zero.example", 4, 0, []DNSAnswer{{Type: 1, TTL: 0, IP: net.IPv4(192, 0, 2, 44)}})},
		{Name: "ttl-large", Domain: "long.example", Client: "192.0.2.10", Transaction: 5, Answers: []DNSAnswer{{Type: 1, TTL: 86400, IP: net.IPv4(192, 0, 2, 45)}}, Response: BuildDNSResponse("long.example", 5, 0, []DNSAnswer{{Type: 1, TTL: 86400, IP: net.IPv4(192, 0, 2, 45)}})},
		{Name: "https-with-echconfig", Domain: "googlevideo.com", Client: "192.0.2.10", Transaction: 6,
			Answers:  []DNSAnswer{{Type: 65, TTL: 60, Data: []byte{0, 1, 0, 0, 0xfe, 0x0d, 0, 2, 0xaa, 0xbb}}},
			Response: BuildDNSResponse("googlevideo.com", 6, 0, []DNSAnswer{{Type: 65, TTL: 60, Data: []byte{0, 1, 0, 0, 0xfe, 0x0d, 0, 2, 0xaa, 0xbb}}})},
		{Name: "https-without-echconfig", Domain: "youtube.com", Client: "192.0.2.10", Transaction: 7,
			Answers:  []DNSAnswer{{Type: 65, TTL: 60, Data: []byte{0, 1, 0, 0}}},
			Response: BuildDNSResponse("youtube.com", 7, 0, []DNSAnswer{{Type: 65, TTL: 60, Data: []byte{0, 1, 0, 0}}})},
		{Name: "nxdomain", Domain: "missing.youtube.com", Client: "192.0.2.10", Transaction: 8, RCode: 3, Response: BuildDNSResponse("missing.youtube.com", 8, 3, nil)},
		{Name: "servfail", Domain: "unstable.youtube.com", Client: "192.0.2.10", Transaction: 9, RCode: 2, Response: BuildDNSResponse("unstable.youtube.com", 9, 2, nil)},
		{Name: "shared-ip-client-a", Domain: "youtubei.googleapis.com", Client: "192.0.2.10", SharedIP: shared.String(), Transaction: 10, Answers: []DNSAnswer{{Type: 1, TTL: 30, IP: shared}}, Response: BuildDNSResponse("youtubei.googleapis.com", 10, 0, []DNSAnswer{{Type: 1, TTL: 30, IP: shared}})},
		{Name: "shared-ip-client-b", Domain: "r1---sn.googlevideo.com", Client: "192.0.2.11", SharedIP: shared.String(), Transaction: 11, Answers: []DNSAnswer{{Type: 1, TTL: 30, IP: shared}}, Response: BuildDNSResponse("r1---sn.googlevideo.com", 11, 0, []DNSAnswer{{Type: 1, TTL: 30, IP: shared}})},
	}
}

func TCPCorpus() []TCPFixture {
	return []TCPFixture{
		{Name: "clean-syn", Seq: 100, Flags: 0x02},
		{Name: "syn-explicit-fake", Seq: 200, Flags: 0x02, ExplicitSYNTechnique: true},
		{Name: "syn-ack", Seq: 300, Ack: 101, Flags: 0x12},
		{Name: "fin", Seq: 400, Ack: 501, Flags: 0x11},
		{Name: "rst", Seq: 500, Ack: 601, Flags: 0x14},
		{Name: "tfo-payload", Seq: 600, Flags: 0x02, Payload: []byte("GET / HTTP/1.1\r\n\r\n")},
		{Name: "sequence-wrap", Seq: ^uint32(0) - 3, Flags: 0x18, Payload: []byte("wrap")},
		{Name: "retransmission-after-action", Seq: 700, Flags: 0x18, Payload: []byte("clienthello")},
		{Name: "serverhello-progress", Seq: 800, Ack: 701, Flags: 0x18, Payload: []byte{0x16, 0x03, 0x03, 0, 4, 0x02, 0, 0, 0}},
	}
}
