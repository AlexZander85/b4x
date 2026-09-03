// IPv4/UDP datagram crafting for datagram-mode carriers (M+W): inner WG
// datagrams ride inside the MASQUE CONNECT-IP capsule stream as plain IP
// packets, exactly like dns_tunnel.go ships DNS. Checksums are fully
// computed (probe.go discipline) so packets survive real edge forwarding.
package nested

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	ipv4HeaderLen = 20
	udpHeaderLen  = 8
	// UDPDatagramOverhead is the exact wire cost of one carried datagram.
	UDPDatagramOverhead = ipv4HeaderLen + udpHeaderLen
)

var (
	// ErrNotV4: the datagram plane is IPv4-only by scope (addendum 46:
	// IPv6 disabled for this phase); fail structurally, never silently.
	ErrNotV4 = errors.New("nested: datagram plane is ipv4-only")
	// ErrDatagramMalformed: inbound packet failed structural parse.
	ErrDatagramMalformed = errors.New("nested: malformed udp datagram")
)

// BuildUDPDatagram renders one full IPv4+UDP packet carrying payload.
// Checksums are computed end-to-end (pseudo-header for UDP, header for IP).
func BuildUDPDatagram(src, dst netip.Addr, sport, dport uint16, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, ErrNotV4
	}
	total := UDPDatagramOverhead + len(payload)
	if total > 0xffff {
		return nil, fmt.Errorf("nested: datagram too large: %d", total)
	}
	pkt := make([]byte, total)

	// UDP header (+payload).
	u := pkt[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[udpHeaderLen:], payload)

	// IPv4 header.
	ip := pkt[:ipv4HeaderLen]
	ip[0] = 0x45 // v4, ihl=5
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	binary.BigEndian.PutUint16(ip[6:], 0x4000) // DF
	ip[8] = 64                                 // TTL
	ip[9] = 17                                 // proto UDP
	src4 := src.As4()
	dst4 := dst.As4()
	copy(ip[12:16], src4[:])
	copy(ip[16:20], dst4[:])

	// UDP checksum over the pseudo-header (src, dst, zero, proto, udplen).
	var pseudo [12]byte
	copy(pseudo[0:4], src4[:])
	copy(pseudo[4:8], dst4[:])
	pseudo[9] = 17
	sumUDP := finalize(sum32(append(pseudo[:], u...)))
	binary.BigEndian.PutUint16(u[6:], sumUDP)

	// IP header checksum over the 20 header bytes.
	binary.BigEndian.PutUint16(ip[10:], finalize(sum32(ip)))
	return pkt, nil
}

// UDPTuple identifies both ends of one carried datagram exchange.
type UDPTuple struct {
	SrcIP, DstIP     netip.Addr
	SrcPort, DstPort uint16
}

// SplitUDPDatagram parses one full IPv4+UDP packet produced by BuildUDPDatagram
// (or an equivalent wire packet). Payload aliases the input slice.
func SplitUDPDatagram(pkt []byte) (t UDPTuple, payload []byte, err error) {
	if len(pkt) < ipv4HeaderLen+udpHeaderLen {
		return t, nil, fmt.Errorf("%w: short packet %d", ErrDatagramMalformed, len(pkt))
	}
	if pkt[0]>>4 != 4 || pkt[0]&0x0f != 5 {
		return t, nil, fmt.Errorf("%w: not plain ipv4", ErrDatagramMalformed)
	}
	if pkt[9] != 17 {
		return t, nil, fmt.Errorf("%w: proto %d != udp", ErrDatagramMalformed, pkt[9])
	}
	tot := int(binary.BigEndian.Uint16(pkt[2:4]))
	if tot > len(pkt) {
		return t, nil, fmt.Errorf("%w: truncated %d/%d", ErrDatagramMalformed, tot, len(pkt))
	}
	t.SrcIP = netip.AddrFrom4([4]byte(pkt[12:16]))
	t.DstIP = netip.AddrFrom4([4]byte(pkt[16:20]))
	u := pkt[ipv4HeaderLen:tot]
	t.SrcPort = binary.BigEndian.Uint16(u[0:2])
	t.DstPort = binary.BigEndian.Uint16(u[2:4])
	// PATCH-24/E20: the UDP length is checked against the IP total-length
	// field (tot), NOT the slice length — a datagram padded past tot must
	// not let its payload grow into the padding. Inbound CHECKSUMS are
	// deliberately NOT verified: integrity is guaranteed by the QUIC-AEAD
	// outer plane; the demux only needs the tuple and payload geometry.
	ulen := int(binary.BigEndian.Uint16(u[4:6]))
	if ulen < udpHeaderLen || ipv4HeaderLen+ulen > tot {
		return t, nil, fmt.Errorf("%w: bad udp length %d", ErrDatagramMalformed, ulen)
	}
	return t, u[udpHeaderLen:ulen], nil
}

// sum32 / finalize mirror transportwarp probe.go checksum math (one fact,
// one source: identical algorithm, verified against its test vectors).
func sum32(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func finalize(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
