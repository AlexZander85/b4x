package nfq

import (
	"encoding/binary"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestHeadMSSSplits1890(t *testing.T) {
	cuts := headMSSSplits(1890)
	if len(cuts) != 2 || cuts[0] != 1 || cuts[1] != 1397 {
		t.Fatalf("cuts %v want [1 1397]", cuts)
	}
}

func TestHeadMSSPayloads1890(t *testing.T) {
	pay := make([]byte, 1890)
	pay[0], pay[1], pay[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(pay[3:5], uint16(1885))
	for i := 5; i < len(pay); i++ {
		pay[i] = byte(i)
	}
	raw := ipv4TCPPacket(1000, pay)
	pi, ok := ExtractPacketInfoV4(raw)
	if !ok {
		t.Fatal("extract")
	}
	segs, lens, deltas := buildHeadMSSSegmentsV4(raw, pi)
	if len(segs) != 3 {
		t.Fatalf("segs %d", len(segs))
	}
	wantLen := []int{1, 1396, 493}
	wantDelta := []int{0, 1, 1397}
	var got []byte
	var seq uint32 = 1000
	for i, s := range segs {
		if lens[i] != wantLen[i] || deltas[i] != wantDelta[i] {
			t.Fatalf("seg %d len=%d delta=%d", i, lens[i], deltas[i])
		}
		if lens[i] > cHeadMSS {
			t.Fatalf("seg %d > MSS", i)
		}
		spi, ok := ExtractPacketInfoV4(s)
		if !ok {
			t.Fatal("seg extract")
		}
		if spi.Seq0 != seq {
			t.Fatalf("seg %d seq %d want %d", i, spi.Seq0, seq)
		}
		psh := s[spi.IPHdrLen+13]&0x08 != 0
		if i < 2 && psh {
			t.Fatalf("seg %d PSH", i)
		}
		if i == 2 && !psh {
			t.Fatal("last needs PSH")
		}
		got = append(got, spi.Payload...)
		seq += uint32(spi.PayloadLen)
	}
	if len(got) != 1890 {
		t.Fatalf("covered %d", len(got))
	}
	for i := range pay {
		if got[i] != pay[i] {
			t.Fatalf("byte %d changed", i)
		}
	}
}

func TestHeadMSSNoPayloadOverMSS(t *testing.T) {
	for _, n := range []int{800, 1396, 1397, 1748, 1781, 1795, 1845, 1891, 2100} {
		cuts := headMSSSplits(n)
		prev := 0
		for _, cut := range append(append([]int{}, cuts...), n) {
			sz := cut - prev
			if sz > cHeadMSS {
				t.Fatalf("n=%d piece %d > MSS", n, sz)
			}
			if sz < 1 {
				t.Fatalf("n=%d empty piece", n)
			}
			prev = cut
		}
	}
}

func TestShouldInjectHeadMSSOnlyYouTubeVideo(t *testing.T) {
	video := &config.SetConfig{Name: "youtube-video", Id: "9b31cb9b-2bdc-4435-bfd6-f7977dca4876"}
	ui := &config.SetConfig{Name: "youtube-ui"}
	api := &config.SetConfig{Name: "combo-timestamp"}
	if !shouldInjectHeadMSS(video, 1890) {
		t.Fatal("video long ECH")
	}
	if shouldInjectHeadMSS(video, 189) {
		t.Fatal("short CH is tactic B")
	}
	if shouldInjectHeadMSS(ui, 1837) || shouldInjectHeadMSS(api, 1817) || shouldInjectHeadMSS(nil, 1800) {
		t.Fatal("C must not hit UI/API")
	}
}

func TestHandshakePayloadLenV4(t *testing.T) {
	raw := ipv4TCPPacket(1, make([]byte, 900))
	if handshakePayloadLen(raw) != 900 {
		t.Fatalf("len %d", handshakePayloadLen(raw))
	}
}

func TestTCPFlowFromRawV4(t *testing.T) {
	raw := ipv4TCPPacket(1, make([]byte, 100))
	got := tcpFlowFromRaw(raw)
	if got != "192.168.1.152:41436->173.194.6.6:443" {
		t.Fatalf("flow %q", got)
	}
}

func TestCSeqovlFirstRewindsAndKeepsRealBytes(t *testing.T) {
	pay := make([]byte, 1890)
	pay[0], pay[1], pay[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(pay[3:5], uint16(1885))
	for i := 5; i < len(pay); i++ {
		pay[i] = byte(i)
	}
	raw := ipv4TCPPacket(1000, pay)
	pi, ok := ExtractPacketInfoV4(raw)
	if !ok {
		t.Fatal("extract")
	}
	segs, lens, deltas := buildHeadMSSSegmentsV4(raw, pi)
	segs, lens, deltas = applyCSeqovlFirstV4(raw, pi, segs, lens, deltas, cSeqovlDefaultPattern)
	if lens[0] != cSeqovlLen+1 || deltas[0] != -cSeqovlLen {
		t.Fatalf("first on-wire len=%d delta=%d", lens[0], deltas[0])
	}
	if lens[0] > cHeadMSS || lens[1] > cHeadMSS || lens[2] > cHeadMSS {
		t.Fatalf("on-wire > MSS %v", lens)
	}
	s0, ok := ExtractPacketInfoV4(segs[0])
	if !ok {
		t.Fatal("seg0")
	}
	if s0.Seq0 != 1000-uint32(cSeqovlLen) {
		t.Fatalf("seq0 %d", s0.Seq0)
	}
	if s0.Payload[cSeqovlLen] != 0x16 {
		t.Fatal("real 0x16 must sit at seq0")
	}
	s1, _ := ExtractPacketInfoV4(segs[1])
	if s1.Seq0 != 1001 {
		t.Fatalf("seg1 seq %d", s1.Seq0)
	}
	got := []byte{s0.Payload[cSeqovlLen]}
	got = append(got, s1.Payload...)
	s2, _ := ExtractPacketInfoV4(segs[2])
	got = append(got, s2.Payload...)
	if len(got) != 1890 {
		t.Fatalf("real cover %d", len(got))
	}
	for i := range pay {
		if got[i] != pay[i] {
			t.Fatalf("real byte %d", i)
		}
	}
}
