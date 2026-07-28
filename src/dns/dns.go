package dns

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

func ParseQueryDomain(payload []byte) (string, bool) {
	if len(payload) < 12 {
		return "", false
	}

	pos := 12
	var domain []byte

	for pos < len(payload) {
		length := int(payload[pos])
		if length == 0 {
			break
		}
		if pos+1+length > len(payload) {
			return "", false
		}
		if len(domain) > 0 {
			domain = append(domain, '.')
		}
		domain = append(domain, payload[pos+1:pos+1+length]...)
		pos += 1 + length
	}

	if len(domain) == 0 {
		return "", false
	}
	return string(domain), true
}

func ParseTransactionID(payload []byte) (uint16, bool) {
	if len(payload) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(payload[:2]), true
}

func BuildBlockResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	qend, ok := skipDNSName(query, 12)
	if !ok || qend+4 > len(query) {
		return nil
	}
	questionEnd := qend + 4 // QTYPE + QCLASS

	resp := make([]byte, questionEnd)
	copy(resp, query[:questionEnd])

	resp[2] = 0x80 | (query[2] & 0x79)
	resp[3] = 0x83

	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)

	return resp
}

func BuildServfailResponse(query []byte) []byte {
	resp := BuildBlockResponse(query)
	if resp == nil {
		return nil
	}
	// Set only the RCODE nibble to SERVFAIL (2); preserve the upper flag bits.
	resp[3] = (resp[3] & 0xF0) | 0x02
	return resp
}

func ParseResponseIPs(payload []byte) []net.IP {
	observation, err := ParseStructuredResponse(payload, classifier.ClientKey{}, "", time.Time{})
	if err != nil {
		return nil
	}
	ips := make([]net.IP, 0, len(observation.Answers))
	for _, answer := range observation.Answers {
		if !answer.IP.IsValid() {
			continue
		}
		ips = append(ips, net.IP(answer.IP.AsSlice()))
	}
	return ips
}

func skipDNSName(payload []byte, start int) (int, bool) {
	if start >= len(payload) {
		return 0, false
	}
	pos := start
	jumps := 0
	jumped := false
	next := start

	for {
		if pos >= len(payload) {
			return 0, false
		}
		l := payload[pos]
		if l == 0 {
			if !jumped {
				next = pos + 1
			}
			return next, true
		}
		// compressed pointer
		if l&0xC0 == 0xC0 {
			if pos+1 >= len(payload) {
				return 0, false
			}
			ptr := int(binary.BigEndian.Uint16(payload[pos:pos+2]) & 0x3FFF)
			if ptr >= len(payload) {
				return 0, false
			}
			if !jumped {
				next = pos + 2
			}
			pos = ptr
			jumped = true
			jumps++
			if jumps > 16 {
				return 0, false
			}
			continue
		}

		pos++
		if pos+int(l) > len(payload) {
			return 0, false
		}
		pos += int(l)
		if !jumped {
			next = pos
		}
	}
}
