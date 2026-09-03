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

// ipfrag2-diagnostic layer (Часть 2 промта NEXT_SESSION_TLSREC_IPFRAG2.md).
// Scope: see ipfrag2_diag_off.go.
//
// Mechanic: the assembled youtube-video ECH ClientHello is re-sent as ONE
// TCP segment cut into TWO IPv4 fragments. The TCP header (with its
// checksum over the whole segment) lives only in the offset-0 fragment;
// the continuation fragment carries raw L4 bytes at an 8-byte-aligned
// offset. DF is cleared (DF+MF is illegal), MF set on the head, both
// fragments share the original IP ID so any reassembler — TSPU's or
// Google's kernel — sees one datagram. No fakes accompany the probe.

const (
	// ipfragDiagSendGapMs paces the two fragments like prior layers.
	ipfragDiagSendGapMs = 2
)

// buildIPFragmentsV4 cuts one raw IPv4/TCP packet into two IPv4 fragments.
// The split point is the multiple-of-8 nearest half of the L4 payload so
// that the full TCP header stays inside the first fragment. Returns
// (headFragment, continuationFragment, ok).
func buildIPFragmentsV4(raw []byte) ([]byte, []byte, bool) {
	pi, ok := ExtractPacketInfoV4(raw)
	if !ok {
		return nil, nil, false
	}
	ihl := pi.IPHdrLen
	l4 := raw[ihl:]
	l4len := len(l4)
	if l4len < 40 || pi.TCPHdrLen < 20 || pi.TCPHdrLen > l4len {
		return nil, nil, false
	}

	k := ((l4len / 2) / 8) * 8 // 8-byte aligned split near half
	if k <= pi.TCPHdrLen || k >= l4len {
		return nil, nil, false
	}

	mkFrag := func(part []byte, mf bool, offUnits uint16) []byte {
		frag := make([]byte, ihl+len(part))
		copy(frag[:ihl], raw[:ihl])
		copy(frag[ihl:], part)
		binary.BigEndian.PutUint16(frag[2:4], uint16(len(frag)))
		ff := offUnits & 0x1FFF
		if mf {
			ff |= 0x2000 // MF set; DF deliberately cleared
		}
		binary.BigEndian.PutUint16(frag[6:8], ff)
		sock.FixIPv4Checksum(frag[:ihl])
		return frag
	}

	f1 := mkFrag(l4[:k], true, 0)
	f2 := mkFrag(l4[k:], false, uint16(k/8))
	return f1, f2, true
}

// maybeIPFrag2Diagnose intercepts the inject funnel for the ipfragdiag
// build. Guards: youtube-video set ONLY, IPv4 ONLY, complete single-record
// CH, ECH extension present. Returns true when the packet was consumed.
func (w *Worker) maybeIPFrag2Diagnose(vc *verdictCtx, pkt *pktInfo, set *config.SetConfig, raw []byte, replay bool) bool {
	if !ipfragDiagEnabled || vc == nil || pkt == nil || set == nil || len(raw) == 0 {
		return false
	}
	if pkt.ver != IPv4 {
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
	if total == 0 || total != len(payload) { // ONE complete record only
		return false
	}
	meta := sni.ParseTLSClientHelloMetadata(payload)
	if !meta.ECHPresent {
		return false
	}

	f1, f2, ok := buildIPFragmentsV4(raw)
	if !ok {
		log.Tracef("ipfrag2-diag: cannot fragment %dB packet to %s", len(raw), pkt.dstStr)
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
			pkt.srcMac, config.TLSVersionString(meta.MaxVersion), "ipfrag2")
		log.Warnf("ipfrag2-diag: fragmented CH %dB -> frags %d+%d (off=%d, reverse=%v) dst=%s replay=%v",
			len(raw), len(f1), len(f2), (len(raw)-pi.IPHdrLen)/2, ipfragDiagReverse, pkt.dstStr, replay)
	}

	m := metrics.GetMetricsCollector()
	m.RecordConnection("TCP", host, pkt.srcStr, pkt.dstStr, true, pkt.srcMac, setName(set),
		config.TLSVersionString(meta.MaxVersion))
	m.RecordPacket(uint64(len(f1)))
	m.RecordPacket(uint64(len(f2)))

	if !vc.drop() {
		return true
	}

	dstCopy := append(net.IP(nil), pkt.dst...)
	f1Copy := append([]byte(nil), f1...)
	f2Copy := append([]byte(nil), f2...)
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.sendIPFrag2Diag(dstCopy, f1Copy, f2Copy)
	}()
	return true
}

// sendIPFrag2Diag emits the two fragments, disordered per experiment spec
// (continuation first), with a small gap between them.
func (w *Worker) sendIPFrag2Diag(dst net.IP, head, cont []byte) {
	if w == nil || w.sock == nil {
		return
	}
	first, second := head, cont
	if ipfragDiagReverse {
		first, second = cont, head
		log.Tracef("ipfrag2-diag: sending continuation fragment first to %s", dst.String())
	}
	_ = w.sock.SendIPv4(first, dst)
	time.Sleep(time.Duration(ipfragDiagSendGapMs) * time.Millisecond)
	_ = w.sock.SendIPv4(second, dst)
	log.Tracef("ipfrag2-diag: sent %d+%d byte fragments to %s", len(head), len(cont), dst.String())
}
