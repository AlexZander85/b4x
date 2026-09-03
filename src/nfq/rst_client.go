package nfq

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sock"
)

// buildRSTToClientV4 forges an IPv4 TCP RST that terminates the LAN
// client's connection as if it came from the real server: the 5-tuple is
// mirrored (the wire packet's src becomes the RST's dst and vice versa) and
// SEQ carries the client's current ACK number — a sequence value the server
// is legitimately allowed to use, which established TCP stacks accept
// instantly. A wrong SEQ would make the client silently ignore the reset,
// so byte-level correctness is pinned by unit tests. Checksums are fixed
// via sock.FixIPv4Checksum/FixTCPChecksum.
func buildRSTToClientV4(raw []byte, ihl int, srcIP, dstIP net.IP) []byte {
	if ihl < 20 || len(raw) < ihl+20 {
		return nil
	}
	tcp := raw[ihl:]

	clientPort := binary.BigEndian.Uint16(tcp[0:2])
	serverPort := binary.BigEndian.Uint16(tcp[2:4])
	clientAck := binary.BigEndian.Uint32(tcp[8:12])

	rst := make([]byte, 40)

	rst[0] = 0x45
	binary.BigEndian.PutUint16(rst[2:4], 40)
	binary.BigEndian.PutUint16(rst[4:6], uint16(time.Now().UnixNano()&0xFFFF))
	rst[8] = 64
	rst[9] = 6
	copy(rst[12:16], dstIP.To4())
	copy(rst[16:20], srcIP.To4())

	binary.BigEndian.PutUint16(rst[20:22], serverPort)
	binary.BigEndian.PutUint16(rst[22:24], clientPort)
	binary.BigEndian.PutUint32(rst[24:28], clientAck)
	rst[32] = 0x50
	rst[33] = 0x04

	sock.FixIPv4Checksum(rst[:20])
	sock.FixTCPChecksum(rst)
	return rst
}

// buildRSTToClientV6 is the IPv6 twin of buildRSTToClientV4 (fixed 40-byte
// fixed header + 20-byte TCP header).
func buildRSTToClientV6(raw []byte, srcIP, dstIP net.IP) []byte {
	const ipv6HdrLen = 40
	if len(raw) < ipv6HdrLen+20 {
		return nil
	}
	tcp := raw[ipv6HdrLen:]

	clientPort := binary.BigEndian.Uint16(tcp[0:2])
	serverPort := binary.BigEndian.Uint16(tcp[2:4])
	clientAck := binary.BigEndian.Uint32(tcp[8:12])

	rst := make([]byte, 60)

	rst[0] = 0x60
	binary.BigEndian.PutUint16(rst[4:6], 20)
	rst[6] = 6
	rst[7] = 64
	copy(rst[8:24], dstIP.To16())
	copy(rst[24:40], srcIP.To16())

	binary.BigEndian.PutUint16(rst[40:42], serverPort)
	binary.BigEndian.PutUint16(rst[42:44], clientPort)
	binary.BigEndian.PutUint32(rst[44:48], clientAck)
	rst[52] = 0x50
	rst[53] = 0x04

	sock.FixTCPChecksumV6(rst)
	return rst
}

// rstSink resolves where forged client-bound packets go. Production leaves
// clientInjector nil and packets flow through the real raw-socket sender;
// tests substitute a fake (same discipline as actionSender). Returns nil
// when no sender exists (early-boot/lab workers) — callers skip silently.
func (w *Worker) rstSink() packetInjector {
	if w.clientInjector != nil {
		return w.clientInjector
	}
	if cs := w.clientSender(); cs != nil {
		return cs
	}
	return nil
}

func (w *Worker) sendRSTToClientV4(raw []byte, ihl int, srcIP, dstIP net.IP) {
	rst := buildRSTToClientV4(raw, ihl, srcIP, dstIP)
	if rst == nil {
		return
	}
	sink := w.rstSink()
	if sink == nil {
		return
	}
	if err := sink.SendIPv4(rst, srcIP); err != nil {
		log.Tracef("ip-block: failed to send RST to client %s:%d: %v", srcIP, binary.BigEndian.Uint16(raw[ihl:ihl+2]), err)
	}
}

func (w *Worker) sendRSTToClientV6(raw []byte, srcIP, dstIP net.IP) {
	rst := buildRSTToClientV6(raw, srcIP, dstIP)
	if rst == nil {
		return
	}
	sink := w.rstSink()
	if sink == nil {
		return
	}
	if err := sink.SendIPv6(rst, srcIP); err != nil {
		log.Tracef("ip-block: failed to send RST to client %s (v6): %v", srcIP, err)
	}
}

// adblockOnBlockAction applies the configured AdBlock action to a just-
// blocked TCP flow and returns the connection-log metadata tag.
//
//   - "drop" (default): silent drop only; metadata "adblock".
//   - "rst": additionally forge a TCP RST toward the LAN client so it fails
//     instantly instead of waiting for a timeout; metadata "adblock-rst".
//
// QUIC flows never reach this path: UDP has no reset primitive, so QUIC
// keeps the silent timeout-drop regardless of the configured action.
func (w *Worker) adblockOnBlockAction(cfg *config.Config, pkt *pktInfo) string {
	if cfg == nil || cfg.AdBlock.Action != config.AdBlockActionRST {
		return "adblock"
	}
	switch pkt.ver {
	case IPv4:
		w.sendRSTToClientV4(pkt.raw, pkt.ihl, pkt.src, pkt.dst)
	case IPv6:
		w.sendRSTToClientV6(pkt.raw, pkt.src, pkt.dst)
	}
	return "adblock-rst"
}
