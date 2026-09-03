package nfq

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/sock"
)

const (
	assembledECHMin = 800
	// Field phone first-segment size on GGC ECH (1396+tail). Cap for C body.
	cHeadMSS   = 1396
	cHeadPos   = 1
	cSeqovlLen = 681 // zapret2 / z2k gv_tcp: pos=1:seqovl=681
)

// TLS-looking filler if the set has no seq_overlap_pattern. DPI may parse
// the rewound prefix as a ClientHello; the server trims seq < Seq0.
var cSeqovlDefaultPattern = []byte{0x16, 0x03, 0x01, 0x02, 0xa5, 0x01, 0x00, 0x02, 0xa1, 0x03, 0x03}

func cSeqovlPattern(cfg *config.SetConfig) []byte {
	if cfg != nil && len(cfg.Fragmentation.SeqOverlapBytes) > 0 {
		return cfg.Fragmentation.SeqOverlapBytes
	}
	return cSeqovlDefaultPattern
}

func isYouTubeVideoSet(set *config.SetConfig) bool {
	if set == nil {
		return false
	}
	if set.Name == "youtube-video" {
		return true
	}
	return set.Id == "9b31cb9b-2bdc-4435-bfd6-f7977dca4876"
}

func shouldInjectHeadMSS(set *config.SetConfig, payloadLen int) bool {
	return payloadLen >= assembledECHMin && isYouTubeVideoSet(set)
}

func handshakePayloadLen(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	switch raw[0] >> 4 {
	case IPv4:
		pi, ok := ExtractPacketInfoV4(raw)
		if ok {
			return pi.PayloadLen
		}
	case IPv6:
		pi, ok := ExtractPacketInfoV6(raw)
		if ok {
			return pi.PayloadLen
		}
	}
	return 0
}

// headMSSSplits: one desync cut at pos=1, then body in chunks <= cHeadMSS.
// 1890 → [1, 1397] → payloads 1 + 1396 + 493.
func headMSSSplits(n int) []int {
	if n <= cHeadPos {
		return nil
	}
	cuts := []int{cHeadPos}
	off := cHeadPos
	for off+cHeadMSS < n {
		off += cHeadMSS
		cuts = append(cuts, off)
	}
	return cuts
}

func tcpFlowFromRaw(raw []byte) string {
	if len(raw) < 40 {
		return "?"
	}
	switch raw[0] >> 4 {
	case IPv4:
		pi, ok := ExtractPacketInfoV4(raw)
		if !ok {
			return "?"
		}
		src := net.IP(raw[12:16]).String()
		dst := net.IP(raw[16:20]).String()
		sport := binary.BigEndian.Uint16(raw[pi.IPHdrLen : pi.IPHdrLen+2])
		dport := binary.BigEndian.Uint16(raw[pi.IPHdrLen+2 : pi.IPHdrLen+4])
		return fmt.Sprintf(connKeyFormat, src, sport, dst, dport)
	case IPv6:
		pi, ok := ExtractPacketInfoV6(raw)
		if !ok {
			return "?"
		}
		src := net.IP(raw[8:24]).String()
		dst := net.IP(raw[24:40]).String()
		sport := binary.BigEndian.Uint16(raw[pi.IPHdrLen : pi.IPHdrLen+2])
		dport := binary.BigEndian.Uint16(raw[pi.IPHdrLen+2 : pi.IPHdrLen+4])
		return fmt.Sprintf(connKeyFormat, src, sport, dst, dport)
	default:
		return "?"
	}
}

func setName(set *config.SetConfig) string {
	if set == nil {
		return ""
	}
	if set.Name != "" {
		return set.Name
	}
	return set.Id
}

func (w *Worker) injectCSeqovl(cfg *config.SetConfig, raw []byte, dst net.IP, replay bool) {
	flow := tcpFlowFromRaw(raw)
	if cfg != nil && cfg.Faking.SNI && cfg.Faking.SNISeqLength > 0 {
		w.sendFakeSNISequence(cfg, raw, dst)
	}
	pi, ok := ExtractPacketInfoV4(raw)
	if !ok || pi.PayloadLen < 16 {
		log.Tracef("C-seqovl skipped: flow=%s reason=extract", flow)
		_ = w.sock.SendIPv4(raw, dst)
		return
	}
	segs, lens, deltas := buildHeadMSSSegmentsV4(raw, pi)
	if len(segs) < 2 {
		log.Tracef("C-seqovl skipped: flow=%s reason=segments", flow)
		_ = w.sock.SendIPv4(raw, dst)
		return
	}
	segs, lens, deltas = applyCSeqovlFirstV4(raw, pi, segs, lens, deltas, cSeqovlPattern(cfg))
	if replay {
		log.Tracef("C-seqovl replay: flow=%s total_len=%d", flow, pi.PayloadLen)
	}
	log.Tracef("C-seqovl start: flow=%s dst=%s set=%s total_len=%d segment_count=%d seqovl=%d",
		flow, dst, setName(cfg), pi.PayloadLen, len(segs), cSeqovlLen)
	for i, seg := range segs {
		log.Tracef("C-seqovl segment: index=%d payload_len=%d seq_delta=%d", i, lens[i], deltas[i])
		_ = w.sock.SendIPv4(seg, dst)
	}
}

func (w *Worker) injectCSeqovlv6(cfg *config.SetConfig, raw []byte, dst net.IP, replay bool) {
	flow := tcpFlowFromRaw(raw)
	if cfg != nil && cfg.Faking.SNI && cfg.Faking.SNISeqLength > 0 {
		w.sendFakeSNISequencev6(cfg, raw, dst)
	}
	pi, ok := ExtractPacketInfoV6(raw)
	if !ok || pi.PayloadLen < 16 {
		log.Tracef("C-seqovl skipped: flow=%s reason=extract", flow)
		_ = w.sock.SendIPv6(raw, dst)
		return
	}
	segs, lens, deltas := buildHeadMSSSegmentsV6(raw, pi)
	if len(segs) < 2 {
		log.Tracef("C-seqovl skipped: flow=%s reason=segments", flow)
		_ = w.sock.SendIPv6(raw, dst)
		return
	}
	segs, lens, deltas = applyCSeqovlFirstV6(raw, pi, segs, lens, deltas, cSeqovlPattern(cfg))
	if replay {
		log.Tracef("C-seqovl replay: flow=%s total_len=%d", flow, pi.PayloadLen)
	}
	log.Tracef("C-seqovl start: flow=%s dst=%s set=%s total_len=%d segment_count=%d seqovl=%d",
		flow, dst, setName(cfg), pi.PayloadLen, len(segs), cSeqovlLen)
	for i, seg := range segs {
		log.Tracef("C-seqovl segment: index=%d payload_len=%d seq_delta=%d", i, lens[i], deltas[i])
		_ = w.sock.SendIPv6(seg, dst)
	}
}

func buildHeadMSSSegmentsV4(raw []byte, pi PacketInfo) (segs [][]byte, lens []int, deltas []int) {
	return cutHeadMSS(pi.PayloadLen, func(prev, next, idx int, last bool) []byte {
		seg := BuildSegmentV4(raw, pi, pi.Payload[prev:next], uint32(prev), uint16(idx))
		if last {
			SetPSH(seg, pi.IPHdrLen)
		} else {
			ClearPSH(seg, pi.IPHdrLen)
		}
		sock.FixIPv4Checksum(seg[:pi.IPHdrLen])
		sock.FixTCPChecksum(seg)
		return seg
	})
}

func buildHeadMSSSegmentsV6(raw []byte, pi PacketInfo) (segs [][]byte, lens []int, deltas []int) {
	return cutHeadMSS(pi.PayloadLen, func(prev, next, idx int, last bool) []byte {
		seg := BuildSegmentV6(raw, pi, pi.Payload[prev:next], uint32(prev))
		if last {
			SetPSH(seg, pi.IPHdrLen)
		} else {
			ClearPSH(seg, pi.IPHdrLen)
		}
		sock.FixTCPChecksumV6(seg)
		return seg
	})
}

func applyCSeqovlFirstV4(raw []byte, pi PacketInfo, segs [][]byte, lens, deltas []int, pattern []byte) ([][]byte, []int, []int) {
	if len(segs) == 0 || len(lens) == 0 || cSeqovlLen <= 0 || lens[0] < 1 {
		return segs, lens, deltas
	}
	first := pi.Payload[deltas[0] : deltas[0]+lens[0]]
	seg := BuildSeqOverlapSegmentV4(raw, pi, first, deltas[0], cSeqovlLen, pattern, 0)
	ClearPSH(seg, pi.IPHdrLen)
	sock.FixIPv4Checksum(seg[:pi.IPHdrLen])
	sock.FixTCPChecksum(seg)
	segs[0] = seg
	lens[0] = cSeqovlLen + lens[0]
	deltas[0] = deltas[0] - cSeqovlLen
	return segs, lens, deltas
}

func applyCSeqovlFirstV6(raw []byte, pi PacketInfo, segs [][]byte, lens, deltas []int, pattern []byte) ([][]byte, []int, []int) {
	if len(segs) == 0 || len(lens) == 0 || cSeqovlLen <= 0 || lens[0] < 1 {
		return segs, lens, deltas
	}
	first := pi.Payload[deltas[0] : deltas[0]+lens[0]]
	seg := BuildSeqOverlapSegmentV6(raw, pi, first, deltas[0], cSeqovlLen, pattern)
	ClearPSH(seg, pi.IPHdrLen)
	sock.FixTCPChecksumV6(seg)
	segs[0] = seg
	lens[0] = cSeqovlLen + lens[0]
	deltas[0] = deltas[0] - cSeqovlLen
	return segs, lens, deltas
}

func cutHeadMSS(n int, build func(prev, next, idx int, last bool) []byte) (segs [][]byte, lens []int, deltas []int) {
	cuts := headMSSSplits(n)
	if len(cuts) == 0 {
		return nil, nil, nil
	}
	bounds := append(append([]int{0}, cuts...), n)
	for i := 0; i < len(bounds)-1; i++ {
		prev, next := bounds[i], bounds[i+1]
		if next <= prev {
			continue
		}
		last := i == len(bounds)-2
		segs = append(segs, build(prev, next, i, last))
		lens = append(lens, next-prev)
		deltas = append(deltas, prev)
	}
	return segs, lens, deltas
}
