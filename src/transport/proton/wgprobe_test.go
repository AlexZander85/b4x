package proton

import (
	"context"
	"encoding/base64"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/transport/wgprobe/wgprobetest"
)

// udpFakeEdge — loopback-«узел», отвечающий на WG-initiation аутентичным
// type-2 (резспондер-дабл wgprobetest); прелюдию (I1/джанк) отбрасывает,
// как это делает стоковый WireGuard.
type udpFakeEdge struct {
	listen    *net.UDPConn
	sender    uint32
	responder *wgprobetest.Responder
}

func startUDPFakeEdge(t *testing.T, sender uint32) *udpFakeEdge {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake edge listen: %v", err)
	}
	e := &udpFakeEdge{listen: pc.(*net.UDPConn), sender: sender}
	go e.serve()
	t.Cleanup(func() { _ = pc.Close() })
	return e
}

func (e *udpFakeEdge) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := e.listen.ReadFromUDP(buf)
		if err != nil {
			return
		}
		packet := buf[:n]
		if len(packet) != 148 { // wgprobe.InitiationSize
			continue // прелюдия отбрасывается
		}
		resp, err := e.responder.Respond(packet, e.sender)
		if err != nil {
			continue
		}
		if _, err := e.listen.WriteToUDP(resp, from); err != nil {
			return
		}
	}
}

func TestProbeHandshakeRTTAgainstFakeEdge(t *testing.T) {
	edge := &udpFakeEdge{responder: wgprobetest.NewResponder(), sender: 0xCAFEBABE}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	edge.listen = pc.(*net.UDPConn)
	go edge.serve()
	defer pc.Close()

	privB64 := base64.StdEncoding.EncodeToString(mustHexBytes(t,
		"a01010101010101010101010101010101010101010101010101010101010101f"))
	peerPub := edge.responder.PublicKey()
	peerB64 := base64.StdEncoding.EncodeToString(peerPub[:])

	// Без прелюдии (vanilla-семейство): ответ аутентичен, RTT >= floor.
	res := ProbeHandshakeRTT(context.Background(), privB64, peerB64,
		edge.listen.LocalAddr().(*net.UDPAddr), ProbeHandshakeConfig{Timeout: 2 * time.Second})
	if !res.OK {
		t.Fatalf("probe failed: ok=false cookie=%v err=%v", res.CookieSeen, res.Err)
	}
	if res.RTT < ProbeRTTFloor {
		t.Fatalf("rtt %v < floor", res.RTT)
	}

	// С прелюдией I1 + джанк (профиль вида proton-quic-j40): фейк-эдж
	// отбрасывает прелюдию и отвечает на initiation.
	res = ProbeHandshakeRTT(context.Background(), privB64, peerB64,
		edge.listen.LocalAddr().(*net.UDPAddr), ProbeHandshakeConfig{
			Timeout:   2 * time.Second,
			I1:        "<b 0x" + strings.Repeat("c0", 64) + ">",
			JunkCount: 4, JunkMin: 40, JunkMax: 70,
			Rand: rand.New(rand.NewSource(1)),
		})
	if !res.OK {
		t.Fatalf("probe with prelude failed: ok=false cookie=%v err=%v", res.CookieSeen, res.Err)
	}
}

func TestProbeHandshakeRTTSilentNode(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("silent node: %v", err)
	}
	defer pc.Close()

	privB64 := base64.StdEncoding.EncodeToString(mustHexBytes(t,
		"a01010101010101010101010101010101010101010101010101010101010101f"))
	// Валидный (но молчащий) peer-ключ: нулевой был бы low-order точкой,
	// которую X25519 отвергает ещё до отправки пакета.
	validPeer := wgprobetest.NewResponder().PublicKey()
	peerB64 := base64.StdEncoding.EncodeToString(validPeer[:])
	started := time.Now()
	res := ProbeHandshakeRTT(context.Background(), privB64, peerB64,
		pc.LocalAddr().(*net.UDPAddr), ProbeHandshakeConfig{Timeout: 300 * time.Millisecond})
	if res.OK || res.RTT != 0 || res.Err != nil {
		t.Fatalf("silent node must yield ok=false, got %+v", res)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("silent probe took %v, want bounded", elapsed)
	}
}

func TestProbeHandshakeRTTBadKeys(t *testing.T) {
	edge := &udpFakeEdge{responder: wgprobetest.NewResponder(), sender: 1}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	edge.listen = pc.(*net.UDPConn)
	go edge.serve()
	defer pc.Close()

	privB64 := base64.StdEncoding.EncodeToString(mustHexBytes(t,
		"a01010101010101010101010101010101010101010101010101010101010101f"))
	peerPub := edge.responder.PublicKey()
	peerB64 := base64.StdEncoding.EncodeToString(peerPub[:])

	res := ProbeHandshakeRTT(context.Background(), "!!!not-base64!!!", peerB64,
		edge.listen.LocalAddr().(*net.UDPAddr), ProbeHandshakeConfig{})
	if res.OK || res.Err == nil {
		t.Fatalf("bad private key must error, got %+v", res)
	}
	res = ProbeHandshakeRTT(context.Background(), privB64, "short",
		edge.listen.LocalAddr().(*net.UDPAddr), ProbeHandshakeConfig{})
	if res.OK || res.Err == nil {
		t.Fatalf("bad peer key must error, got %+v", res)
	}
}

func TestDecodeI1Hex(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"", nil},
		{"<b 0xdeadbeef>", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"deadbeef", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"<b 0xde ad be ef>", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"b 0x0102", []byte{0x01, 0x02}},
		{"<b 0xzz>", nil},
		{"<b 0xabc>", nil},
	}
	for _, c := range cases {
		got := decodeI1Hex(c.in)
		if string(got) != string(c.want) {
			t.Errorf("decodeI1Hex(%q) = %x, want %x", c.in, got, c.want)
		}
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		t.Fatalf("odd hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexVal(s[2*i])
		lo := hexVal(s[2*i+1])
		if hi < 0 || lo < 0 {
			t.Fatalf("bad hex %q", s)
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
