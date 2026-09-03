package nfq

import (
	"encoding/binary"

	"github.com/daniellavrushin/b4/sock"
)

// applyInWindowBadsumV4 puts the fake ClientHello in the real TCP window
// (same seq/TTL as the original) and breaks the TCP checksum. TSPU can
// parse the SNI; the server NIC should drop the segment. Replaces AutoTTL
// and default pastseq−10000 (pcap 19:56: fake left WAN at seq−10000).
func applyInWindowBadsumV4(fake, original []byte) {
	if len(fake) < 40 || len(original) < 40 || fake[0]>>4 != 4 || original[0]>>4 != 4 {
		return
	}
	ipHdrLen := int((fake[0] & 0x0F) * 4)
	oIP := int((original[0] & 0x0F) * 4)
	if ipHdrLen < 20 || oIP < 20 || len(fake) < ipHdrLen+20 || len(original) < oIP+20 {
		return
	}
	fake[8] = original[8]
	copy(fake[ipHdrLen+4:ipHdrLen+8], original[oIP+4:oIP+8])
	sock.FixIPv4Checksum(fake[:ipHdrLen])
	sock.FixTCPChecksum(fake)
	fake[ipHdrLen+16] ^= 0xFF
	fake[ipHdrLen+17] ^= 0xFF
}

func applyInWindowBadsumV6(fake, original []byte) {
	if len(fake) < 60 || len(original) < 60 || fake[0]>>4 != 6 || original[0]>>4 != 6 {
		return
	}
	const ip6 = 40
	fake[7] = original[7]
	copy(fake[ip6+4:ip6+8], original[ip6+4:ip6+8])
	sock.FixTCPChecksumV6(fake)
	fake[ip6+16] ^= 0xFF
	fake[ip6+17] ^= 0xFF
}

func tcpChecksumLooksValidV4(pkt []byte) bool {
	if len(pkt) < 40 || pkt[0]>>4 != 4 {
		return false
	}
	ipHdrLen := int((pkt[0] & 0x0F) * 4)
	if len(pkt) < ipHdrLen+20 {
		return false
	}
	got := binary.BigEndian.Uint16(pkt[ipHdrLen+16 : ipHdrLen+18])
	tmp := append([]byte(nil), pkt...)
	sock.FixTCPChecksum(tmp)
	want := binary.BigEndian.Uint16(tmp[ipHdrLen+16 : ipHdrLen+18])
	return got == want
}
