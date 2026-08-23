package nfq

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sock"
)

func echPrefixAndTail(recordBody int, firstLen int) (first, tail []byte) {
	total := 5 + recordBody
	full := make([]byte, total)
	full[0], full[1], full[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(full[3:5], uint16(recordBody))
	for i := 5; i < total; i++ {
		full[i] = byte(i)
	}
	if firstLen >= total {
		return full, nil
	}
	return full[:firstLen], full[firstLen:]
}

func ipv4TCPPacket(seq uint32, payload []byte) []byte {
	ipHdrLen, tcpHdrLen := 20, 20
	pkt := make([]byte, ipHdrLen+tcpHdrLen+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 168, 1, 152})
	copy(pkt[16:20], []byte{173, 194, 6, 6})
	binary.BigEndian.PutUint16(pkt[ipHdrLen:], 41436)
	binary.BigEndian.PutUint16(pkt[ipHdrLen+2:], 443)
	binary.BigEndian.PutUint32(pkt[ipHdrLen+4:], seq)
	pkt[ipHdrLen+12] = 0x50
	pkt[ipHdrLen+13] = 0x18
	copy(pkt[ipHdrLen+tcpHdrLen:], payload)
	sock.FixIPv4Checksum(pkt[:ipHdrLen])
	sock.FixTCPChecksum(pkt)
	return pkt
}

func TestCHHoldAssemblesECHPrefixAndTail(t *testing.T) {
	firstPay, tailPay := echPrefixAndTail(1776, 1396)
	if len(tailPay) != 385 {
		t.Fatalf("tail %d", len(tailPay))
	}
	first := ipv4TCPPacket(1000, firstPay)
	store := newCHHoldStore()
	pkt := &pktInfo{raw: first, ver: IPv4, dst: first[16:20], dstStr: "173.194.6.6"}
	if _, ok := store.start("f", 1000, pkt, firstPay, &config.SetConfig{}); !ok {
		t.Fatal("start")
	}
	assembled, _, ok := store.append("f", 1000+uint32(len(firstPay)), tailPay)
	if !ok || assembled == nil {
		t.Fatalf("append ok=%v assembled=%v", ok, assembled != nil)
	}
	pi, ok := ExtractPacketInfoV4(assembled)
	if !ok {
		t.Fatal("extract")
	}
	if pi.PayloadLen != 5+1776 {
		t.Fatalf("assembled payload %d", pi.PayloadLen)
	}
	if pi.Seq0 != 1000 {
		t.Fatalf("seq %d", pi.Seq0)
	}
	if tlsHandshakeRecordIncomplete(pi.Payload) {
		t.Fatal("assembled still incomplete")
	}
	if cached := store.cached("f", 1000); len(cached) != len(assembled) {
		t.Fatalf("cache %d", len(cached))
	}
}

func TestCHHoldIgnoresPrefixRetransmitUntilTail(t *testing.T) {
	firstPay, tailPay := echPrefixAndTail(1776, 1396)
	first := ipv4TCPPacket(50, firstPay)
	store := newCHHoldStore()
	pkt := &pktInfo{raw: first, ver: IPv4, dst: first[16:20]}
	store.start("f", 50, pkt, firstPay, nil)
	assembled, _, ok := store.append("f", 50, firstPay)
	if !ok || assembled != nil {
		t.Fatalf("retransmit should stay waiting, assembled=%v ok=%v", assembled != nil, ok)
	}
	assembled, _, ok = store.append("f", 50+uint32(len(firstPay)), tailPay)
	if !ok || assembled == nil {
		t.Fatal("tail after retransmit")
	}
}

func TestCHHoldTimeoutTakeOnlyMatchingGen(t *testing.T) {
	firstPay, tailPay := echPrefixAndTail(1776, 1396)
	first := ipv4TCPPacket(1, firstPay)
	store := newCHHoldStore()
	pkt := &pktInfo{raw: first, ver: IPv4, dst: first[16:20]}
	gen, _ := store.start("f", 1, pkt, firstPay, nil)
	_, newGen, ok := store.append("f", 1+uint32(len(firstPay)), tailPay[:10])
	if !ok || newGen == gen {
		t.Fatalf("gen should bump, ok=%v gen=%d new=%d", ok, gen, newGen)
	}
	if e := store.takeInProgress("f", gen); e != nil {
		t.Fatal("stale timer must not steal")
	}
	if e := store.takeInProgress("f", newGen); e == nil {
		t.Fatal("current gen take")
	}
}

func TestRebuildHeldHandshakeV4(t *testing.T) {
	firstPay, tailPay := echPrefixAndTail(1776, 1396)
	first := ipv4TCPPacket(9, firstPay)
	full := append(append([]byte{}, firstPay...), tailPay...)
	got, ok := rebuildHeldHandshake(first, full)
	if !ok {
		t.Fatal("rebuild")
	}
	pi, ok := ExtractPacketInfoV4(got)
	if !ok || pi.PayloadLen != len(full) || pi.Seq0 != 9 {
		t.Fatalf("pi len=%d seq=%d ok=%v", pi.PayloadLen, pi.Seq0, ok)
	}
}

func TestConsiderCHHoldAssemblesAndReplays(t *testing.T) {
	firstPay, tailPay := echPrefixAndTail(1776, 1396)
	first := ipv4TCPPacket(1000, firstPay)
	tail := ipv4TCPPacket(1000+uint32(len(firstPay)), tailPay)
	ctx, cancel := context.WithCancel(context.Background())
	w := &Worker{chHold: newCHHoldStore(), ctx: ctx, cancel: cancel}
	defer cancel()

	firstPkt := &pktInfo{raw: first, ver: IPv4, dst: first[16:20], dstStr: "173.194.6.6"}
	dec, assembled, isReplay := w.considerCHHold("k", 1000, firstPkt, firstPay, &config.SetConfig{})
	if dec != chHoldWaiting || assembled != nil || isReplay {
		t.Fatalf("first dec=%d replay=%v", dec, isReplay)
	}
	tailPkt := &pktInfo{raw: tail, ver: IPv4, dst: tail[16:20], dstStr: "173.194.6.6"}
	dec, assembled, isReplay = w.considerCHHold("k", 1000+uint32(len(firstPay)), tailPkt, tailPay, &config.SetConfig{})
	if dec != chHoldReady || assembled == nil || isReplay {
		t.Fatalf("tail dec=%d replay=%v", dec, isReplay)
	}
	dec, replayPkt, isReplay := w.considerCHHold("k", 1000, firstPkt, firstPay, &config.SetConfig{})
	if dec != chHoldReady || len(replayPkt) != len(assembled) || !isReplay {
		t.Fatalf("replay dec=%d len=%d isReplay=%v", dec, len(replayPkt), isReplay)
	}
	dec, extra, isReplay := w.considerCHHold("k", 1000+uint32(len(firstPay)), tailPkt, tailPay, &config.SetConfig{})
	if dec != chHoldWaiting || extra != nil || isReplay {
		t.Fatalf("post-assemble tail must drop, dec=%d", dec)
	}
}

func TestContinueCHHoldAssemblesUnmatchedTail(t *testing.T) {
	firstPay, tailPay := echPrefixAndTail(1776, 1396)
	first := ipv4TCPPacket(1000, firstPay)
	set := &config.SetConfig{}
	set.Faking.SNI = true
	w := &Worker{chHold: newCHHoldStore(), ctx: context.Background()}
	firstPkt := &pktInfo{raw: first, ver: IPv4, dst: first[16:20], dstStr: "74.125.110.168"}
	if dec, _, replay := w.considerCHHold("k", 1000, firstPkt, firstPay, set); dec != chHoldWaiting || replay {
		t.Fatalf("start dec=%d replay=%v", dec, replay)
	}
	dec, assembled, gotSet, replay := w.continueCHHold("k", 1000+uint32(len(firstPay)), tailPay, "74.125.110.168")
	if dec != chHoldReady || assembled == nil || gotSet != set || replay {
		t.Fatalf("unmatched tail dec=%d assembled=%v set=%v replay=%v", dec, assembled != nil, gotSet == set, replay)
	}
}

func TestCHHoldWaitTimerDoesNotFlushAfterAssemble(t *testing.T) {
	firstPay, tailPay := echPrefixAndTail(1776, 1396)
	first := ipv4TCPPacket(7, firstPay)
	store := newCHHoldStore()
	pkt := &pktInfo{raw: first, ver: IPv4, dst: first[16:20]}
	gen, _ := store.start("f", 7, pkt, firstPay, nil)
	assembled, _, ok := store.append("f", 7+uint32(len(firstPay)), tailPay)
	if !ok || assembled == nil {
		t.Fatal("assemble")
	}
	time.Sleep(5 * time.Millisecond)
	if e := store.takeInProgress("f", gen); e != nil {
		t.Fatal("assembled flow still waiting")
	}
	if store.cached("f", 7) == nil {
		t.Fatal("cache lost")
	}
}