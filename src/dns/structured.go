package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

const (
	dnsClassIN       uint16 = 1
	dnsTypeA         uint16 = 1
	dnsTypeCNAME     uint16 = 5
	dnsTypeAAAA      uint16 = 28
	dnsTypeSVCB      uint16 = 64
	dnsTypeHTTPS     uint16 = 65
	dnsParamECH      uint16 = 5
	maxDNSQuestions         = 64
	maxDNSRecords           = 1024
	maxDNSNameJumps         = 32
	maxDNSNameLength        = 255
)

var ErrMalformedResponse = errors.New("malformed DNS response")

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSAddress struct {
	Name          string
	CanonicalName string
	IP            netip.Addr
	TTL           time.Duration
	TTLSeconds    uint32
}

type DNSCNAME struct {
	Name       string
	Target     string
	TTL        time.Duration
	TTLSeconds uint32
}

type HTTPSRecord struct {
	Name         string
	Priority     uint16
	Target       string
	Params       map[uint16][]byte
	ECHConfig    []byte
	HasECHConfig bool
	TTL          time.Duration
	TTLSeconds   uint32
}

type DNSObservation struct {
	Client        classifier.ClientKey
	TransactionID uint16
	QueryName     string
	Canonical     string
	Questions     []DNSQuestion
	Answers       []DNSAddress
	CNAMEs        []DNSCNAME
	HTTPSRecords  []HTTPSRecord
	RCode         int
	ResolverID    string
	Timestamp     time.Time
	Truncated     bool
}

// ParseStructuredResponse parses a complete DNS message into bounded,
// source-agnostic metadata. It does not create hints itself; callers decide
// whether RCODE, truncation, client identity, and config generation permit a
// positive evidence observation.
func ParseStructuredResponse(payload []byte, client classifier.ClientKey, resolverID string, timestamp time.Time) (DNSObservation, error) {
	if len(payload) < 12 {
		return DNSObservation{}, fmt.Errorf("%w: header truncated", ErrMalformedResponse)
	}
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 {
		return DNSObservation{}, fmt.Errorf("%w: message is not a response", ErrMalformedResponse)
	}
	qdCount := int(binary.BigEndian.Uint16(payload[4:6]))
	anCount := int(binary.BigEndian.Uint16(payload[6:8]))
	nsCount := int(binary.BigEndian.Uint16(payload[8:10]))
	arCount := int(binary.BigEndian.Uint16(payload[10:12]))
	if qdCount > maxDNSQuestions || anCount+nsCount+arCount > maxDNSRecords {
		return DNSObservation{}, fmt.Errorf("%w: record count exceeds bound", ErrMalformedResponse)
	}

	observation := DNSObservation{
		Client:        client,
		TransactionID: binary.BigEndian.Uint16(payload[:2]),
		Questions:     make([]DNSQuestion, 0, qdCount),
		Answers:       make([]DNSAddress, 0, anCount),
		CNAMEs:        make([]DNSCNAME, 0),
		HTTPSRecords:  make([]HTTPSRecord, 0),
		RCode:         int(flags & 0x000f),
		ResolverID:    strings.TrimSpace(resolverID),
		Timestamp:     timestamp,
		Truncated:     flags&0x0200 != 0,
	}

	offset := 12
	for i := 0; i < qdCount; i++ {
		name, next, err := readDNSName(payload, offset)
		if err != nil || next+4 > len(payload) {
			return DNSObservation{}, malformedDNS("question", err)
		}
		question := DNSQuestion{
			Name:  name,
			Type:  binary.BigEndian.Uint16(payload[next : next+2]),
			Class: binary.BigEndian.Uint16(payload[next+2 : next+4]),
		}
		observation.Questions = append(observation.Questions, question)
		if observation.QueryName == "" {
			observation.QueryName = name
		}
		offset = next + 4
	}

	for i := 0; i < anCount+nsCount+arCount; i++ {
		rr, next, err := readResourceRecord(payload, offset)
		if err != nil {
			return DNSObservation{}, malformedDNS("resource record", err)
		}
		offset = next
		if err := observation.addRecord(rr); err != nil {
			return DNSObservation{}, err
		}
	}

	if observation.QueryName != "" {
		canonical, err := resolveCanonicalName(observation.QueryName, observation.CNAMEs)
		if err != nil {
			return DNSObservation{}, err
		}
		observation.Canonical = canonical
		for i := range observation.Answers {
			observation.Answers[i].CanonicalName, err = resolveCanonicalName(observation.Answers[i].Name, observation.CNAMEs)
			if err != nil {
				return DNSObservation{}, err
			}
		}
	}
	return observation, nil
}

// ParseResponse is the convenience API for callers that do not yet have
// client/resolver context. Correlation paths should use ParseStructuredResponse.
func ParseResponse(payload []byte) (DNSObservation, error) {
	return ParseStructuredResponse(payload, classifier.ClientKey{}, "", time.Time{})
}

func (o *DNSObservation) addRecord(rr dnsResourceRecord) error {
	ttl := time.Duration(rr.ttl) * time.Second
	switch rr.typ {
	case dnsTypeA:
		if rr.class == dnsClassIN {
			if len(rr.rdata) != 4 {
				return fmt.Errorf("%w: A record has length %d", ErrMalformedResponse, len(rr.rdata))
			}
			ip := netip.AddrFrom4([4]byte{rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3]})
			o.Answers = append(o.Answers, DNSAddress{Name: rr.name, IP: ip, TTL: ttl, TTLSeconds: rr.ttl})
		}
	case dnsTypeAAAA:
		if rr.class == dnsClassIN {
			if len(rr.rdata) != 16 {
				return fmt.Errorf("%w: AAAA record has length %d", ErrMalformedResponse, len(rr.rdata))
			}
			var raw [16]byte
			copy(raw[:], rr.rdata)
			ip := netip.AddrFrom16(raw)
			o.Answers = append(o.Answers, DNSAddress{Name: rr.name, IP: ip, TTL: ttl, TTLSeconds: rr.ttl})
		}
	case dnsTypeCNAME:
		if rr.class != dnsClassIN {
			return nil
		}
		target, next, err := readDNSName(rr.message, rr.rdataStart)
		if err != nil || next != rr.rdataEnd {
			return malformedDNS("CNAME rdata", err)
		}
		o.CNAMEs = append(o.CNAMEs, DNSCNAME{Name: rr.name, Target: target, TTL: ttl, TTLSeconds: rr.ttl})
	case dnsTypeSVCB, dnsTypeHTTPS:
		if rr.class != dnsClassIN {
			return nil
		}
		record, err := parseHTTPSRecord(rr)
		if err != nil {
			return err
		}
		o.HTTPSRecords = append(o.HTTPSRecords, record)
	}
	return nil
}

type dnsResourceRecord struct {
	message    []byte
	name       string
	typ        uint16
	class      uint16
	ttl        uint32
	rdata      []byte
	rdataStart int
	rdataEnd   int
}

func readResourceRecord(message []byte, offset int) (dnsResourceRecord, int, error) {
	name, next, err := readDNSName(message, offset)
	if err != nil {
		return dnsResourceRecord{}, 0, err
	}
	if next+10 > len(message) {
		return dnsResourceRecord{}, 0, errors.New("resource record header truncated")
	}
	typ := binary.BigEndian.Uint16(message[next : next+2])
	class := binary.BigEndian.Uint16(message[next+2 : next+4])
	ttl := binary.BigEndian.Uint32(message[next+4 : next+8])
	rdLen := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
	rdataStart := next + 10
	rdataEnd := rdataStart + rdLen
	if rdataEnd < rdataStart || rdataEnd > len(message) {
		return dnsResourceRecord{}, 0, errors.New("resource record rdata truncated")
	}
	return dnsResourceRecord{
		message: message, name: name, typ: typ, class: class, ttl: ttl,
		rdata: message[rdataStart:rdataEnd], rdataStart: rdataStart, rdataEnd: rdataEnd,
	}, rdataEnd, nil
}

func parseHTTPSRecord(rr dnsResourceRecord) (HTTPSRecord, error) {
	if len(rr.rdata) < 2 {
		return HTTPSRecord{}, fmt.Errorf("%w: HTTPS priority truncated", ErrMalformedResponse)
	}
	record := HTTPSRecord{
		Name:       rr.name,
		Priority:   binary.BigEndian.Uint16(rr.rdata[:2]),
		Params:     make(map[uint16][]byte),
		TTL:        time.Duration(rr.ttl) * time.Second,
		TTLSeconds: rr.ttl,
	}
	target, next, err := readDNSName(rr.message, rr.rdataStart+2)
	if err != nil || next > rr.rdataEnd {
		return HTTPSRecord{}, malformedDNS("HTTPS target", err)
	}
	record.Target = target
	lastKey := uint16(0)
	haveKey := false
	for next < rr.rdataEnd {
		if next+4 > rr.rdataEnd {
			return HTTPSRecord{}, fmt.Errorf("%w: HTTPS parameter header truncated", ErrMalformedResponse)
		}
		key := binary.BigEndian.Uint16(rr.message[next : next+2])
		valueLen := int(binary.BigEndian.Uint16(rr.message[next+2 : next+4]))
		next += 4
		if next+valueLen > rr.rdataEnd {
			return HTTPSRecord{}, fmt.Errorf("%w: HTTPS parameter value truncated", ErrMalformedResponse)
		}
		if haveKey && key <= lastKey {
			return HTTPSRecord{}, fmt.Errorf("%w: HTTPS parameters are not strictly ordered", ErrMalformedResponse)
		}
		if _, exists := record.Params[key]; exists {
			return HTTPSRecord{}, fmt.Errorf("%w: duplicate HTTPS parameter", ErrMalformedResponse)
		}
		value := append([]byte(nil), rr.message[next:next+valueLen]...)
		record.Params[key] = value
		if key == dnsParamECH {
			if len(value) == 0 {
				return HTTPSRecord{}, fmt.Errorf("%w: empty ECHConfig", ErrMalformedResponse)
			}
			record.HasECHConfig = true
			record.ECHConfig = value
		}
		next += valueLen
		lastKey = key
		haveKey = true
	}
	return record, nil
}

func resolveCanonicalName(query string, cnames []DNSCNAME) (string, error) {
	current := normalizeDNSName(query)
	links := make(map[string]string, len(cnames))
	for _, cname := range cnames {
		links[normalizeDNSName(cname.Name)] = normalizeDNSName(cname.Target)
	}
	visited := make(map[string]struct{}, len(links)+1)
	for i := 0; i <= len(links); i++ {
		target, ok := links[current]
		if !ok {
			return current, nil
		}
		if _, seen := visited[current]; seen {
			return "", fmt.Errorf("%w: CNAME loop", ErrMalformedResponse)
		}
		visited[current] = struct{}{}
		current = target
	}
	return "", fmt.Errorf("%w: CNAME chain exceeds bound", ErrMalformedResponse)
}

func readDNSName(message []byte, start int) (string, int, error) {
	if start < 0 || start >= len(message) {
		return "", 0, errors.New("DNS name offset out of bounds")
	}
	labels := make([]string, 0, 4)
	visited := make(map[int]struct{}, 4)
	pos := start
	next := 0
	jumped := false
	nameLen := 0
	for jumps := 0; ; jumps++ {
		if pos < 0 || pos >= len(message) {
			return "", 0, errors.New("DNS name truncated")
		}
		if jumps > maxDNSNameJumps {
			return "", 0, errors.New("DNS name pointer jump limit exceeded")
		}
		length := message[pos]
		switch {
		case length == 0:
			if !jumped {
				next = pos + 1
			}
			return strings.Join(labels, "."), next, nil
		case length&0xC0 == 0xC0:
			if pos+1 >= len(message) {
				return "", 0, errors.New("DNS pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16(message[pos:pos+2]) & 0x3FFF)
			if ptr >= len(message) {
				return "", 0, errors.New("DNS pointer out of bounds")
			}
			if !jumped {
				next = pos + 2
			}
			if _, seen := visited[ptr]; seen {
				return "", 0, errors.New("DNS pointer loop")
			}
			visited[ptr] = struct{}{}
			pos = ptr
			jumped = true
		case length&0xC0 != 0:
			return "", 0, errors.New("invalid DNS label type")
		default:
			labelLen := int(length)
			if labelLen > 63 || pos+1+labelLen > len(message) {
				return "", 0, errors.New("DNS label truncated")
			}
			nameLen += labelLen + 1
			if nameLen > maxDNSNameLength {
				return "", 0, errors.New("DNS name length exceeds bound")
			}
			labels = append(labels, strings.ToLower(string(message[pos+1:pos+1+labelLen])))
			pos += 1 + labelLen
			if !jumped {
				next = pos
			}
		}
	}
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func malformedDNS(section string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrMalformedResponse, section)
	}
	return fmt.Errorf("%w: %s: %v", ErrMalformedResponse, section, err)
}
