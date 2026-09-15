package dns

import (
	"encoding/binary"
	"fmt"
	"time"
)

const dnsTypeSOA uint16 = 6

// DNSResponseMetadata keeps the response/header and negative-proof metadata
// that must not be inferred from the answer section alone. In particular,
// NXDOMAIN/NODATA is only considered cacheable/usable when an SOA exists in
// the authority section (RFC 2308 style negative proof).
type DNSResponseMetadata struct {
	RCode              int
	Truncated          bool
	Authoritative      bool
	RecursionAvailable bool
	AuthenticatedData  bool
	CheckingDisabled   bool
	AnswerCount        int
	AuthorityCount     int
	AdditionalCount    int
	AuthoritySOACount  int
	NegativeTTL        time.Duration
}

// HasNegativeProof reports whether this response carries an authority SOA
// suitable for an NXDOMAIN/NODATA decision. It does not claim DNSSEC
// authenticity; it only proves that the negative answer is structurally
// authoritative enough to avoid accepting bare injected NXDOMAIN replies.
func (m DNSResponseMetadata) HasNegativeProof() bool {
	return m.AuthoritySOACount > 0
}

// InspectResponseMetadata parses header flags and walks DNS sections without
// folding authority/additional records into the answer set.
func InspectResponseMetadata(payload []byte) (DNSResponseMetadata, error) {
	if len(payload) < 12 {
		return DNSResponseMetadata{}, fmt.Errorf("%w: header truncated", ErrMalformedResponse)
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 {
		return DNSResponseMetadata{}, fmt.Errorf("%w: message is not a response", ErrMalformedResponse)
	}
	qd := int(binary.BigEndian.Uint16(payload[4:6]))
	an := int(binary.BigEndian.Uint16(payload[6:8]))
	ns := int(binary.BigEndian.Uint16(payload[8:10]))
	ar := int(binary.BigEndian.Uint16(payload[10:12]))
	if qd > maxDNSQuestions || an+ns+ar > maxDNSRecords {
		return DNSResponseMetadata{}, fmt.Errorf("%w: record count exceeds bound", ErrMalformedResponse)
	}
	meta := DNSResponseMetadata{
		RCode:              int(flags & 0x000f),
		Truncated:          flags&0x0200 != 0,
		Authoritative:      flags&0x0400 != 0,
		RecursionAvailable: flags&0x0080 != 0,
		AuthenticatedData:  flags&0x0020 != 0,
		CheckingDisabled:   flags&0x0010 != 0,
		AnswerCount:        an,
		AuthorityCount:     ns,
		AdditionalCount:    ar,
	}

	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := readDNSName(payload, off)
		if err != nil || next+4 > len(payload) {
			return DNSResponseMetadata{}, malformedDNS("question", err)
		}
		off = next + 4
	}
	for i := 0; i < an; i++ {
		_, next, err := readResourceRecord(payload, off)
		if err != nil {
			return DNSResponseMetadata{}, malformedDNS("answer", err)
		}
		off = next
	}
	for i := 0; i < ns; i++ {
		rr, next, err := readResourceRecord(payload, off)
		if err != nil {
			return DNSResponseMetadata{}, malformedDNS("authority", err)
		}
		off = next
		if rr.typ != dnsTypeSOA || rr.class != dnsClassIN {
			continue
		}
		negTTL, err := parseSOANegativeTTL(rr)
		if err != nil {
			return DNSResponseMetadata{}, err
		}
		meta.AuthoritySOACount++
		if meta.NegativeTTL == 0 || negTTL < meta.NegativeTTL {
			meta.NegativeTTL = negTTL
		}
	}
	for i := 0; i < ar; i++ {
		_, next, err := readResourceRecord(payload, off)
		if err != nil {
			return DNSResponseMetadata{}, malformedDNS("additional", err)
		}
		off = next
	}
	if off != len(payload) {
		// Extra trailing bytes are legal for some transports only outside the
		// DNS message. Providers pass the DNS message itself here, so retain a
		// strict boundary to reject injected garbage.
		return DNSResponseMetadata{}, fmt.Errorf("%w: trailing bytes after DNS message", ErrMalformedResponse)
	}
	return meta, nil
}

func parseSOANegativeTTL(rr dnsResourceRecord) (time.Duration, error) {
	_, off, err := readDNSName(rr.message, rr.rdataStart) // MNAME
	if err != nil || off > rr.rdataEnd {
		return 0, malformedDNS("SOA mname", err)
	}
	_, off, err = readDNSName(rr.message, off) // RNAME
	if err != nil || off+20 != rr.rdataEnd {
		return 0, malformedDNS("SOA rname/tail", err)
	}
	minimum := binary.BigEndian.Uint32(rr.message[off+16 : off+20])
	ttl := rr.ttl
	if minimum < ttl {
		ttl = minimum
	}
	return time.Duration(ttl) * time.Second, nil
}
