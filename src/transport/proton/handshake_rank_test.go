package proton

import (
	"context"
	"encoding/base64"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/transport/wgprobe/wgprobetest"
)

// fakeProtonNode — loopback WG-«узел» с фиксированной парой ключей.
type fakeProtonNode struct {
	responder *wgprobetest.Responder
	conn      *net.UDPConn
}

func startFakeProtonNode(t *testing.T) *fakeProtonNode {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	n := &fakeProtonNode{responder: wgprobetest.NewResponder(), conn: pc}
	go func() {
		buf := make([]byte, 2048)
		for {
			rlen, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if rlen != 148 {
				continue
			}
			resp, err := n.responder.Respond(buf[:rlen], 0x55667788)
			if err != nil {
				continue
			}
			if _, err := pc.WriteToUDP(resp, from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return n
}

func fakeNodeFrom(t *testing.T, n *fakeProtonNode, name string, load int) Node {
	t.Helper()
	pub := n.responder.PublicKey()
	return Node{
		Name:       name,
		Country:    "TST",
		EntryIP:    n.conn.LocalAddr().(*net.UDPAddr).IP.String(),
		PeerPubKey: base64.StdEncoding.EncodeToString(pub[:]),
		Load:       load,
	}
}

// TestProbeHandshakeBatchDedupByPair: две пары одного адреса (port-fallback)
// пробуются ОБЕ; одинаковые пары — один раз.
func TestProbeHandshakeBatchDedupByPair(t *testing.T) {
	node := startFakeProtonNode(t)
	n1 := fakeNodeFrom(t, node, "A", 10)
	priv := privKeyB64(t)

	// Порты кандидатов — фактические порты слушающих fake-узлов (два
	// независимых слушателя на одном адресе имитируют port-fallback).
	nodeB := startFakeProtonNode(t)
	n2 := fakeNodeFrom(t, nodeB, "A2", 10)
	portA := node.conn.LocalAddr().(*net.UDPAddr).Port
	portB := nodeB.conn.LocalAddr().(*net.UDPAddr).Port
	cands := []Candidate{
		{Node: n1, Port: uint16(portA)},
		{Node: n1, Port: uint16(portA)}, // дубль пары — должен схлопнуться
		{Node: n2, Port: uint16(portB)}, // второй порт того же адреса — отдельная проба
	}
	samples := ProbeHandshakeBatch(context.Background(), priv, cands,
		ProbeHandshakeConfig{Timeout: time.Second})
	if len(samples) != 2 {
		t.Fatalf("samples = %d (keys %v), want 2 (dedup by pair, both ports probed)",
			len(samples), sampleKeys(samples))
	}
	for key, s := range samples {
		if !s.OK {
			t.Fatalf("sample %s: ok=false (fake node must answer)", key)
		}
	}
}

// TestMergeProbeRankingTiers: handshake-сэмпл бьёт TCP, TCP бьёт ничего;
// RTT разных видов не смешиваются.
func TestMergeProbeRankingTiers(t *testing.T) {
	nodes := []Node{
		{Name: "hs", Country: "TST", EntryIP: "1.1.1.1", Load: 50},
		{Name: "tcp", Country: "TST", EntryIP: "2.2.2.2", Load: 10},
		{Name: "none", Country: "TST", EntryIP: "3.3.3.3", Load: 20},
		{Name: "tcp-slow", Country: "TST", EntryIP: "4.4.4.4", Load: 30},
	}
	hs := map[string]HandshakeSample{
		"1.1.1.1:443": {RTT: 250 * time.Millisecond, OK: true},
		// 2.2.2.2 медленный handshake → не OK, остаётся на TCP-ярусе
		"2.2.2.2:443": {RTT: 0, OK: false},
	}
	tcp := map[string]time.Duration{
		"2.2.2.2": 20 * time.Millisecond,
		"4.4.4.4": 900 * time.Millisecond,
	}
	out := MergeProbeRanking(nodes, hs, tcp, []uint16{443})
	byName := map[string]Node{}
	for _, n := range out {
		byName[n.Name] = n
	}
	if byName["hs"].RTTSource != RTTSourceHandshake || byName["hs"].RTT != 250*time.Millisecond {
		t.Fatalf("hs = %+v", byName["hs"])
	}
	if byName["tcp"].RTTSource != RTTSourceTCP || byName["tcp"].RTT != 20*time.Millisecond {
		t.Fatalf("tcp = %+v", byName["tcp"])
	}
	if byName["none"].RTTSource != "" || byName["none"].RTT != 0 {
		t.Fatalf("none = %+v", byName["none"])
	}
	if byName["tcp-slow"].RTTSource != RTTSourceTCP {
		t.Fatalf("tcp-slow = %+v", byName["tcp-slow"])
	}

	// Ярусный порядок: handshake < tcp < none; внутри tcp-яруса по RTT.
	ordered := SortCandidatesByProbeTiers(out)
	var seq []string
	for _, n := range ordered {
		seq = append(seq, n.Name)
	}
	// tcp(20ms) раньше tcp-slow(900ms); hs — первым; none — последним.
	want := []string{"hs", "tcp", "tcp-slow", "none"}
	for i := range want {
		if seq[i] != want[i] {
			t.Fatalf("order = %v, want %v", seq, want)
		}
	}
}

// TestQueueSortForQueueTiers: очередь сортирует по ярусам с сохранением
// странового чередования.
func TestQueueSortForQueueTiers(t *testing.T) {
	q := NewQueue([]Node{
		{Name: "tcpCA", Country: "CA", EntryIP: "1.1.1.1", Load: 10, RTT: 30 * time.Millisecond, RTTSource: RTTSourceTCP},
		{Name: "hsUS", Country: "US", EntryIP: "2.2.2.2", Load: 90, RTT: 200 * time.Millisecond, RTTSource: RTTSourceHandshake},
		{Name: "noneCA", Country: "CA", EntryIP: "3.3.3.3", Load: 20},
	}, 0)
	// hsUS обязан возглавить очередь несмотря на Load=90 и RTT больше
	// TCP-сэмпла: ярус старше числа.
	if q.nodes[0].Name != "hsUS" {
		t.Fatalf("head = %s, want hsUS (handshake tier outranks TCP)", q.nodes[0].Name)
	}
}

// TestRankCurrentHandshakeIntegration: serverlist-слой гоняет ОБЕ пробы
// и публикует сэмплы с источником.
func TestRankCurrentHandshakeIntegration(t *testing.T) {
	node := startFakeProtonNode(t)
	n1 := fakeNodeFrom(t, node, "A", 10)
	n2 := Node{Name: "B", Country: "TST", EntryIP: "127.0.0.2", PeerPubKey: "AAAA", Load: 5}
	// n2: ключ-мусор → handshake не взлетит, TCP на несуществующий адрес
	// тоже; остаётся неизмеренным.

	priv := privKeyB64(t)
	sc := &ServerlistCache{
		Client: &Client{},
		cur: &cachedServerlist{
			FetchedAt: time.Now(),
			Source:    "live",
			Nodes:     []Node{n1, n2},
		},
		HandshakeKey: func() (string, string, bool) {
			return priv, "", true
		},
		RankPorts: []uint16{uint16(node.conn.LocalAddr().(*net.UDPAddr).Port)},
		RTTDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errFakeDial
		},
	}
	// Конвенция *Locked: вызывающий держит мьютекс (метод снимает его на
	// время сетевых проб и возвращает обратно захваченным).
	sc.mu.Lock()
	sc.rankCurrentLocked(context.Background())
	sc.mu.Unlock()

	if sc.rttRankedAt.IsZero() {
		t.Fatalf("ranking not stamped")
	}
	var a, b Node
	for _, n := range sc.cur.Nodes {
		switch n.Name {
		case "A":
			a = n
		case "B":
			b = n
		}
	}
	if a.RTTSource != RTTSourceHandshake || a.RTT <= 0 {
		t.Fatalf("A = %+v, want handshake sample", a)
	}
	if b.RTTSource != "" || b.RTT != 0 {
		t.Fatalf("B = %+v, want unmeasured", b)
	}
}

var errFakeDial = &net.OpError{Op: "dial", Err: errTestUnreachable}

var errTestUnreachable = errUnreachable{}

type errUnreachable struct{}

func (errUnreachable) Error() string { return "test unreachable" }

func privKeyB64(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(mustHexBytes(t,
		"a01010101010101010101010101010101010101010101010101010101010101f"))
}

func sampleKeys(m map[string]HandshakeSample) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

var _ = rand.New // keep import if helpers change
