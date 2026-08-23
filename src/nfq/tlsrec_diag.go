package nfq

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/metrics"
	"github.com/daniellavrushin/b4/sni"
	"github.com/daniellavrushin/b4/sock"
)

// tlsrec-diagnostic layer (bd b4x-z1h). Scope, limits and the owner decision
// behind it are documented in tlsrec_diag_off.go and
// .ag/findings/tlsrec-step0-seq-consistency-2026-08-23.md.
//
// Mechanic: when an ASSEMBLED ClientHello record (hold machine output or a
// complete single-record CH) resolves to the youtube-video set and carries an
// ECH extension, re-frame the SAME handshake bytes into two TLS records split
// immediately before the ECH extension header and inject them as plain
// MSS-sized segments. Only +5 bytes of record framing are added; the
// handshake transcript is untouched (RFC 8446 §5.1 mandates acceptance of
// fragmented handshakes). No fake SNI / combo / headmss / seqovl accompany
// the probe: the pcap question this layer answers is exactly "does TSPU
// glue multi-record ClientHellos or choke on them".

const (
	// tlsrecDiagSegMax mirrors the phone MSS observed on GGC flows
	// (1396-byte first segments in every field log).
	tlsrecDiagSegMax = 1396
	// tlsrecDiagSegDelayMs paces segment emission like C5 did (2 ms).
	tlsrecDiagSegDelayMs = 2
)

// findECHExtensionOffset walks a full TLS record holding one ClientHello and
// returns the absolute payload offset of the first ECH-family extension
// header (type 0xFE0D, GREASE variants 0xFE0E/0xFE0F), or -1 when absent or
// malformed. Offsets are relative to the START OF THE RECORD (payload[0] is
// 0x16), matching findPreSNIExtensionPoint conventions.
func findECHExtensionOffset(payload []byte) int {
	if len(payload) < 5 || payload[0] != 0x16 {
		return -1
	}

	pos := 5
	if pos+4 > len(payload) || payload[pos] != 0x01 {
		return -1
	}
	pos += 4

	if pos+34 > len(payload) {
		return -1
	}
	pos += 34 // legacy_version(2) + random(32)

	if pos >= len(payload) {
		return -1
	}
	sidLen := int(payload[pos])
	pos++
	pos += sidLen

	if pos+2 > len(payload) {
		return -1
	}
	csLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + csLen

	if pos >= len(payload) {
		return -1
	}
	compLen := int(payload[pos])
	pos++
	pos += compLen

	if pos+2 > len(payload) {
		return -1
	}
	extLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	extEnd := pos + extLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))

		switch extType {
		case 0xfe0d, 0xfe0e, 0xfe0f:
			return pos
		}

		pos += 4 + extDataLen
	}

	return -1
}

// reframeTLSRecordAt splits the single complete record in payload into two
// records whose union preserves every original byte: record A keeps the
// original header with length adjusted to cover payload[5:at], record B
// repeats type/version with length len-at and carries payload[at:]. The
// result is len(payload)+5 bytes; handshake-message bytes are untouched.
func reframeTLSRecordAt(payload []byte, at int) ([]byte, bool) {
	if at <= 5 || at >= len(payload) {
		return nil, false
	}
	lenA := at - 5
	lenB := len(payload) - at
	if lenA <= 0 || lenA > 0xFFFF || lenB > 0xFFFF {
		return nil, false
	}

	out := make([]byte, 0, len(payload)+5)
	out = append(out, payload[:at]...)
	out[3] = byte(lenA >> 8)
	out[4] = byte(lenA)
	out = append(out, payload[0], payload[1], payload[2])
	out = append(out, byte(lenB>>8), byte(lenB))
	out = append(out, payload[at:]...)
	return out, true
}

// maybeTLSRecDiagnose intercepts the inject funnel for the diagnostic build.
// Guards: youtube-video set ONLY, IPv4 ONLY, complete single-record CH,
// ECH extension present, sane split point. Returns true when the packet was
// consumed (dropped and reframed segments scheduled).
func (w *Worker) maybeTLSRecDiagnose(vc *verdictCtx, pkt *pktInfo, set *config.SetConfig, raw []byte, replay bool) bool {
	if !tlsrecDiagEnabled || vc == nil || pkt == nil || set == nil || len(raw) == 0 {
		return false
	}
	if pkt.ver != IPv4 { // QUIC/UDP and IPv6 untouched per spec
		return false
	}
	if !isYouTubeVideoSet(set) {
		return false
	}

	pi, ok := ExtractPacketInfoV4(raw)
	if !ok {
		return false
	}
	payload := pi.Payload
	total := tlsHandshakeRecordTotal(payload)
	if total == 0 || total != len(payload) { // need ONE complete record
		return false
	}
	meta := sni.ParseTLSClientHelloMetadata(payload)
	if !meta.ECHPresent {
		return false
	}

	split := findECHExtensionOffset(payload)
	if split < 14 || split >= len(payload)-4 {
		log.Tracef("tlsrec-diag: no usable ECH split offset (%d) for %dB CH to %s", split, len(payload), pkt.dstStr)
		return false
	}

	reframed, ok := reframeTLSRecordAt(payload, split)
	if !ok {
		return false
	}

	host := meta.ECHOuterName
	if host == "" {
		host = meta.SNI
	}
	cfg := w.getConfig()
	if cfg == nil || !cfg.Queue.IsDiscovery {
		log.LogConnection("TCP", setName(set), host, pkt.srcStr,
			binary.BigEndian.Uint16(raw[pi.IPHdrLen:pi.IPHdrLen+2]),
			setName(set), pkt.dstStr,
			binary.BigEndian.Uint16(raw[pi.IPHdrLen+2:pi.IPHdrLen+4]),
			pkt.srcMac, config.TLSVersionString(meta.MaxVersion), "tlsrec")
		log.Warnf("tlsrec-diag: reframed CH %dB -> records %d+%d (echext@%d) dst=%s replay=%v",
			len(payload), split-5, len(payload)-split, split, pkt.dstStr, replay)
	}

	m := metrics.GetMetricsCollector()
	m.RecordConnection("TCP", host, pkt.srcStr, pkt.dstStr, true, pkt.srcMac, setName(set),
		config.TLSVersionString(meta.MaxVersion))
	m.RecordPacket(uint64(len(reframed)))

	if !vc.drop() {
		return true
	}

	dstCopy := append(net.IP(nil), pkt.dst...)
	reframedCopy := append([]byte(nil), reframed...)
	rawCopy := append([]byte(nil), raw...)
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.sendTLSRecDiagSegments(rawCopy, pi, reframedCopy, dstCopy)
	}()
	return true
}

// sendTLSRecDiagSegments emits the reframed payload as in-order MSS-sized
// segments built from the held packet template. Forward order, no shuffle,
// no fakes: minimal-variable probe.
func (w *Worker) sendTLSRecDiagSegments(template []byte, pi PacketInfo, reframed []byte, dst net.IP) {
	if w == nil || w.sock == nil || len(reframed) == 0 {
		return
	}

	segs := make([][]byte, 0, 2)
	for off := 0; off < len(reframed); {
		end := off + tlsrecDiagSegMax
		if end > len(reframed) {
			end = len(reframed)
		}
		seg := BuildSegmentV4(template, pi, reframed[off:end], uint32(off), uint16(len(segs)))
		if end < len(reframed) {
			ClearPSH(seg, pi.IPHdrLen)
		} else {
			SetPSH(seg, pi.IPHdrLen)
		}
		sock.FixTCPChecksum(seg) // PSH mutation invalidates the checksum
		segs = append(segs, seg)
		off = end
	}

	for i, seg := range segs {
		_ = w.sock.SendIPv4(seg, dst)
		if i < len(segs)-1 && tlsrecDiagSegDelayMs > 0 {
			time.Sleep(time.Duration(tlsrecDiagSegDelayMs) * time.Millisecond)
		}
	}
	log.Tracef("tlsrec-diag: sent %d segment(s), %dB reframed payload to %s",
		len(segs), len(reframed), dst.String())
}
