// ICMPv6 Packet Too Big synthesis (PATCH-18, M-7 / B-H6): the v6 recipe of
// design §3 next to the field-proven v4 path. The tunnel scope is v4-only
// today (addendum §46), so the v6 branch stays latent until the IPv6 scope
// opens — but the recipe is a pure byte function, fully verifiable offline.
package transportwarp

import "encoding/binary"

// BuildICMPv6TooBig synthesizes an ICMPv6 Packet Too Big message (type 2,
// RFC 4443) advertising mtu (clamped to the 1232 QUIC v6 floor per design
// §3), embedding the original IPv6 header plus the first 8 payload bytes.
// The checksum is computed over the IPv6 pseudo-header (invoking src, dst,
// upper-layer packet length, next header 58). The outer IPv6 header follows
// ICMP error semantics: source = the entity reporting (original destination),
// destination = the original sender (original source). Returns nil for
// non-IPv6 or truncated input.
func BuildICMPv6TooBig(orig []byte, mtu int) []byte {
	const (
		hdrLen     = 40 // fixed IPv6 header length
		typePTB    = 2  // ICMPv6 Packet Too Big
		nexthdrV6  = 58 // ICMPv6
		mtuFloorV6 = 1232
	)
	if len(orig) < hdrLen+8 || orig[0]>>4 != 6 {
		return nil
	}
	if mtu > mtuFloorV6 {
		mtu = mtuFloorV6
	}

	const embedded = hdrLen + 8
	msg := make([]byte, 0, 8+embedded)
	msg = append(msg, typePTB, 0, 0, 0) // type, code, checksum placeholder
	msg = append(msg, byte(mtu>>24), byte(mtu>>16), byte(mtu>>8), byte(mtu))
	msg = append(msg, orig[:embedded]...)

	// Checksum over the IPv6 pseudo-header + ICMPv6 message (RFC 4443 §2.3).
	// The pseudo-header addresses are the INVOKING packet's src/dst as they
	// appear in the embedded header.
	plen := len(msg)
	pseudo := make([]byte, 0, hdrLen+plen)
	pseudo = append(pseudo, orig[8:24]...)   // invoking packet src
	pseudo = append(pseudo, orig[24:40]...)  // invoking packet dst
	pseudo = append(pseudo, byte(plen>>24), byte(plen>>16), byte(plen>>8), byte(plen))
	pseudo = append(pseudo, 0, 0, 0, nexthdrV6)
	pseudo = append(pseudo, msg...)
	sum := ^fold(checksum32(pseudo))
	binary.BigEndian.PutUint16(msg[2:4], sum)

	// Outer IPv6 header: version 6, no flow label, next header 58, hop 64.
	total := hdrLen + len(msg)
	ip := make([]byte, total)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(msg))) // payload length
	ip[6] = nexthdrV6
	ip[7] = 64 // hop limit
	copy(ip[8:24], orig[24:40])  // src <- original dst (reporting entity)
	copy(ip[24:40], orig[8:24])  // dst <- original src (the sender to inform)
	copy(ip[40:], msg)
	return ip
}
