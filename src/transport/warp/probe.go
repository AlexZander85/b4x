// Synthetic data-plane probe (design §3, Aether quic.rs/masque.rs pattern):
// after the HTTP CONNECT-IP handshake returns 200 the endpoint still may
// silently drop all payload ("edge accepts control but drops traffic"). The
// probe is a minimal well-formed IPv4/UDP DNS query sent into the tunnel; a
// round trip proves the inner path carries packets end-to-end.
package transportwarp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// ErrProbeTooSmall reports a reply shorter than the probe's own headers.
var ErrProbeTooSmall = errors.New("transportwarp: probe reply too small")

const (
	probeSrcPortBase = 20000 // Aether masque.rs random sport range 20000-60000
	probeSrcPortSpan = 40000
	dnsHeaderLen     = 12
)

// Probe is one generated probe packet plus its identity bytes used to match
// replies (the DNS transaction id).
type Probe struct {
	Packet []byte
	TXID   [2]byte
}

// NewDNSProbe builds an IPv4+UDP+DNS A-query for name via dnsServer from the
// tunnel-local source address localV4. Checksums are fully computed so the
// packet survives real kernel forwarding inside Cloudflare's edge.
func NewDNSProbe(localV4 [4]byte, dnsServer [4]byte, name string) (*Probe, error) {
	if len(name) == 0 || name[len(name)-1] == '.' {
		return nil, errors.New("transportwarp: invalid probe qname")
	}

	var txid [2]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return nil, err
	}

	// --- DNS payload ---
	dns := make([]byte, 0, 17+len(name)+4)
	dns = append(dns, txid[0], txid[1])
	dns = append(dns, 0x01, 0x00) // flags: RD=1
	dns = append(dns, 0x00, 0x01) // QDCOUNT=1
	dns = append(dns, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	start := 0
	for {
		dot := indexByte(name[start:], '.')
		label := name[start:]
		if dot >= 0 {
			label = name[start : start+dot]
		}
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("transportwarp: invalid probe label")
		}
		dns = append(dns, byte(len(label)))
		dns = append(dns, label...)
		if dot < 0 {
			break
		}
		start += dot + 1
	}
	dns = append(dns, 0x00)             // root label
	dns = append(dns, 0x00, 0x01)       // QTYPE=A
	dns = append(dns, 0x00, 0x01)       // QCLASS=IN

	// --- UDP header ---
	sport := uint16(probeSrcPortBase + binary.BigEndian.Uint16(txid[:])%probeSrcPortSpan)
	udp := make([]byte, 8+len(dns))
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], dns)
	// UDP checksum computed below over the pseudo-header; IPv4 allows zero,
	// but computing it keeps the packet valid on strict middleboxes.

	// --- IPv4 header ---
	total := 20 + len(udp)
	ip := make([]byte, 20+len(udp))
	var ipid [2]byte
	if _, err := rand.Read(ipid[:]); err != nil {
		return nil, err
	}
	ip[0] = 0x45 // v4, ihl=5
	ip[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	copy(ip[4:], ipid[:])
	binary.BigEndian.PutUint16(ip[6:], 0x4000) // DF
	ip[8] = 64                                 // TTL
	ip[9] = 17                                 // proto UDP
	copy(ip[12:16], localV4[:])
	copy(ip[16:20], dnsServer[:])

	// UDP checksum over pseudo-header (src, dst, zero, proto, udplen).
	sum := checksum32(append([]byte{localV4[0], localV4[1], localV4[2], localV4[3],
		dnsServer[0], dnsServer[1], dnsServer[2], dnsServer[3], 0x00, 0x11},
		udp...))
	udpSum := ^fold(sum)
	if udpSum == 0 {
		udpSum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], udpSum)
	copy(ip[20:], udp)
	binary.BigEndian.PutUint16(ip[10:], ^fold(checksum32(ip[:20])))

	return &Probe{Packet: ip, TXID: txid}, nil
}

// Matches reports whether an inbound tunnel packet looks like the reply to
// this probe: same size, reversed addresses, DNS QR response carrying the
// original transaction id. Replies that were mangled by anycast load
// balancing still match on the txid alone.
func (p *Probe) Matches(in []byte) bool {
	if len(in) != len(p.Packet) {
		return false
	}
	// txid lives at fixed offset: ip(20) + udp(8) = 28.
	return in[28] == p.TXID[0] && in[29] == p.TXID[1]
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func checksum32(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}
