// BLK-6 verification: byte-exactness of the forged client RST (a wrong SEQ
// would be silently ignored by the client, so the bytes are pinned by unit
// tests), the drop/rst action gate, and a smoke run of the exact BLK-2
// sequence (real SNI decision → forged RST through an intercepted sender).
package nfq

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/daniellavrushin/b4/adblock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sock"
)

func TestBuildRSTToClientV4Bytes(t *testing.T) {
	raw := buildTestIPv4TCPPacket(t, []byte{0x16, 0x03}, 1000, 51000, 443)
	const clientAck = 0x51525354
	binary.BigEndian.PutUint32(raw[28:32], clientAck)

	client := net.IPv4(192, 0, 2, 1)
	server := net.IPv4(203, 0, 113, 10)
	rst := buildRSTToClientV4(raw, 20, client, server)

	if len(rst) != 40 {
		t.Fatalf("len=%d want 40", len(rst))
	}
	if rst[0] != 0x45 {
		t.Fatalf("ihl/version %#x", rst[0])
	}
	if binary.BigEndian.Uint16(rst[2:4]) != 40 {
		t.Fatalf("total length %d", binary.BigEndian.Uint16(rst[2:4]))
	}
	if rst[9] != 6 {
		t.Fatalf("proto %#x", rst[9])
	}
	// Mirrored addresses: RST src = packet dst (server), RST dst = packet src (client).
	if !net.IP(rst[12:16]).Equal(server) || !net.IP(rst[16:20]).Equal(client) {
		t.Fatalf("addresses not mirrored: src=%v dst=%v", net.IP(rst[12:16]), net.IP(rst[16:20]))
	}
	// Mirrored ports: sport=server(443), dport=client(51000).
	if got := binary.BigEndian.Uint16(rst[20:22]); got != 443 {
		t.Fatalf("rst sport=%d want 443 (server)", got)
	}
	if got := binary.BigEndian.Uint16(rst[22:24]); got != 51000 {
		t.Fatalf("rst dport=%d want 51000 (client)", got)
	}
	// SEQ == client's current ACK; ACK field stays zero.
	if got := binary.BigEndian.Uint32(rst[24:28]); got != clientAck {
		t.Fatalf("seq=%#x want clientACK %#x", got, uint32(clientAck))
	}
	if got := binary.BigEndian.Uint32(rst[28:32]); got != 0 {
		t.Fatalf("ack=%#x want 0", got)
	}
	if rst[32] != 0x50 {
		t.Fatalf("data offset %#x", rst[32])
	}
	if rst[33] != 0x04 {
		t.Fatalf("flags %#x want RST-only 0x04", rst[33])
	}

	// Checksum validity: recomputing over zeroed fields must reproduce the
	// built bytes exactly.
	re := append([]byte(nil), rst...)
	re[10], re[11] = 0, 0 // IPv4 header checksum
	re[36], re[37] = 0, 0 // TCP checksum
	sock.FixIPv4Checksum(re[:20])
	sock.FixTCPChecksum(re)
	for i := range re {
		if re[i] != rst[i] {
			t.Fatalf("checksum mismatch at byte %d (built %02x recomputed %02x)", i, rst[i], re[i])
		}
	}
}

func TestBuildRSTToClientV6Bytes(t *testing.T) {
	raw := buildTestIPv6TCPPacket(t, nil, 7, 40000, 443)
	const clientAck = 0x01020304
	binary.BigEndian.PutUint32(raw[48:52], clientAck) // input ACK field (IPv6 hdr 40 + TCP offset 8)

	client := net.ParseIP("2001:db8::1")
	server := net.ParseIP("2001:db8::2")
	rst := buildRSTToClientV6(raw, client, server)

	if len(rst) != 60 {
		t.Fatalf("len=%d want 60", len(rst))
	}
	if rst[0] != 0x60 {
		t.Fatalf("version nibble %#x", rst[0])
	}
	if binary.BigEndian.Uint16(rst[4:6]) != 20 {
		t.Fatalf("payload length %d", binary.BigEndian.Uint16(rst[4:6]))
	}
	if rst[6] != 6 {
		t.Fatalf("next header %#x", rst[6])
	}
	if !net.IP(rst[8:24]).Equal(server) || !net.IP(rst[24:40]).Equal(client) {
		t.Fatal("v6 addresses not mirrored")
	}
	if got := binary.BigEndian.Uint16(rst[40:42]); got != 443 {
		t.Fatalf("sport=%d want 443", got)
	}
	if got := binary.BigEndian.Uint16(rst[42:44]); got != 40000 {
		t.Fatalf("dport=%d want 40000", got)
	}
	if got := binary.BigEndian.Uint32(rst[44:48]); got != clientAck {
		t.Fatalf("seq=%#x want %#x", got, uint32(clientAck))
	}
	if rst[52] != 0x50 || rst[53] != 0x04 {
		t.Fatalf("tcp ctl %#x %#x", rst[52], rst[53])
	}

	re := append([]byte(nil), rst...)
	re[56], re[57] = 0, 0
	sock.FixTCPChecksumV6(re)
	for i := range re {
		if re[i] != rst[i] {
			t.Fatalf("checksum mismatch at byte %d", i)
		}
	}
}

func TestAdblockOnBlockActionGate(t *testing.T) {
	fake := &fakePacketInjector{}
	w := &Worker{}
	w.clientInjector = fake

	hello := buildClientHelloPacket(t, "ads.example.com")
	wk := &Worker{}
	pkt, ok := wk.parseIPHeaders(hello)
	if !ok || pkt.ver != IPv4 {
		t.Fatalf("parse ver=%d ok=%v", pkt.ver, ok)
	}

	rstCfg := config.NewConfig()
	rstCfg.AdBlock.Action = config.AdBlockActionRST

	if meta := w.adblockOnBlockAction(&rstCfg, pkt); meta != "adblock-rst" {
		t.Fatalf("metadata=%q want adblock-rst", meta)
	}
	if fake.sent4 != 1 || fake.sent6 != 0 {
		t.Fatalf("v4 flow must send exactly one RST: v4=%d v6=%d", fake.sent4, fake.sent6)
	}
	want := buildRSTToClientV4(pkt.raw, pkt.ihl, pkt.src, pkt.dst)
	// The builder stamps time.Now() into the IPv4 Identification field and
	// the header checksum covers that ID — normalise both by zeroing the ID
	// and recomputing the header checksum, then every other byte must match
	// exactly (the TCP checksum is ID-independent via the pseudo-header).
	normalise := func(p []byte) []byte {
		q := append([]byte(nil), p...)
		q[4], q[5] = 0, 0
		q[10], q[11] = 0, 0
		sock.FixIPv4Checksum(q[:20])
		return q
	}
	if string(normalise(fake.last4)) != string(normalise(want)) {
		t.Fatal("sent RST bytes must equal the builder output (modulo IP-ID)")
	}

	dropCfg := config.NewConfig()
	dropCfg.AdBlock.Action = config.AdBlockActionDrop
	before := fake.sent4
	if meta := w.adblockOnBlockAction(&dropCfg, pkt); meta != "adblock" {
		t.Fatalf("drop metadata=%q want adblock", meta)
	}
	if fake.sent4 != before {
		t.Fatal("drop action must not send anything")
	}

	// IPv6 flow routes to the v6 sender.
	v6raw := buildTestIPv6TCPPacket(t, nil, 7, 40001, 443)
	v6pkt := &pktInfo{raw: v6raw, ver: IPv6, proto: 6,
		src: net.ParseIP("2001:db8::1"), dst: net.ParseIP("2001:db8::2"), ihl: 0}
	if meta := w.adblockOnBlockAction(&rstCfg, v6pkt); meta != "adblock-rst" {
		t.Fatalf("v6 metadata=%q", meta)
	}
	if fake.sent6 != 1 {
		t.Fatalf("v6 flow must send one RST: %d", fake.sent6)
	}

	// Production safety: no real socket and no injector ⇒ gate must stay
	// silent instead of panicking (lab/tests/early-boot workers).
	bare := &Worker{}
	if meta := bare.adblockOnBlockAction(&rstCfg, pkt); meta != "adblock-rst" {
		t.Fatalf("bare worker metadata=%q", meta)
	}
}

func TestAdblockRSTSmokeBlockedClientHello(t *testing.T) {
	listPath := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(listPath, []byte("ads.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	adblock.Reload(config.AdBlockConfig{
		Enabled: true,
		Action:  config.AdBlockActionRST,
		Lists:   []config.AdBlockList{{Source: listPath, Enabled: true}},
	})
	t.Cleanup(func() {
		adblock.Reload(config.AdBlockConfig{Enabled: false})
	})

	fake := &fakePacketInjector{}
	w := &Worker{}
	w.clientInjector = fake

	cfg := config.NewConfig()
	cfg.AdBlock.Enabled = true
	cfg.AdBlock.Action = config.AdBlockActionRST

	raw := buildClientHelloPacket(t, "ads.example.com")
	wk := &Worker{}
	pkt, ok := wk.parseIPHeaders(raw)
	if !ok {
		t.Fatal("parse")
	}
	host := "ads.example.com"
	if d, _ := adblock.Decide(host); d != adblock.DecisionBlock {
		t.Fatalf("precondition: matcher must block %s (got %v)", host, d)
	}

	// The exact BLK-2 sequence: decision → action gate → verdict handled by
	// the caller (vc.drop(); return 0 — covered by the compile-time suite).
	meta := w.adblockOnBlockAction(&cfg, pkt)
	if meta != "adblock-rst" {
		t.Fatalf("metadata=%q", meta)
	}
	if fake.sent4 != 1 {
		t.Fatalf("RST must leave toward the client: sent=%d", fake.sent4)
	}
	// The forged RST's SEQ must equal the ClientHello packet's ACK number
	// (buildClientHelloPacket sets ack=1) — otherwise the client would
	// silently ignore it.
	rstAckOfInput := binary.BigEndian.Uint32(raw[pkt.ihl+8 : pkt.ihl+12])
	if got := binary.BigEndian.Uint32(fake.last4[24:28]); got != rstAckOfInput {
		t.Fatalf("forged seq=%#x want input ack %#x", got, rstAckOfInput)
	}
}
