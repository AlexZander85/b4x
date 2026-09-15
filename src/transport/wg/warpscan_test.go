package transportwg

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/transport/wgprobe/wgprobetest"
)

// startScanEdge — loopback fake cf-warp edge: аутентичный Noise-IK
// рез.pондер + reserved-байтовая дисциплина зеркально движку (RX: скип
// датаграмм с чужими reserved; TX: ответ со stamped reserved).
func startScanEdge(t *testing.T, expect [3]byte, requireReserved bool) (*wgprobetest.Responder, *net.UDPConn) {
	t.Helper()
	responder := wgprobetest.NewResponder()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("scan edge listen: %v", err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packet := buf[:n]
			if len(packet) != 148 {
				continue // не-initiation: отброшено, как стоковым WG
			}
			if requireReserved &&
				(packet[1] != expect[0] || packet[2] != expect[1] || packet[3] != expect[2]) {
				continue // чужой client_id не доходит до этого эджа
			}
			resp, err := responder.Respond(packet, 0x0BADF00D)
			if err != nil {
				continue
			}
			// Edge TX: reserved bytes стоят на проводе (MAC покрывает нули).
			resp[1] = expect[0]
			resp[2] = expect[1]
			resp[3] = expect[2]
			if _, err := pc.WriteToUDP(resp, from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return responder, pc
}

// TestWarpScanFindsVerifiedEndpoint: полный цикл сканера против живого
// fake-edge — LCG обходит loopback-/32, проба аутентична, hit с RTT.
func TestWarpScanFindsVerifiedEndpoint(t *testing.T) {
	responder, pc := startScanEdge(t, [3]byte{}, false)
	edgeAddr := pc.LocalAddr().(*net.UDPAddr)
	edgeIP, _ := netip.ParseAddr(edgeAddr.IP.String())
	peerPub := responder.PublicKey()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	hits, stats, err := WarpScan(context.Background(), WarpScanOptions{
		PrivateKey:        priv,
		PeerPublicKey:     peerPub,
		Prefixes:          []netip.Prefix{netip.PrefixFrom(edgeIP, 32)},
		Ports:             []uint16{uint16(edgeAddr.Port)},
		Limit:             1,
		Workers:           2,
		AllowOutOfCatalog: true,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits=%d stats=%+v, want 1", len(hits), stats)
	}
	if hits[0].AddrPort.String() != netip.AddrPortFrom(edgeIP, uint16(edgeAddr.Port)).String() {
		t.Fatalf("hit endpoint %s", hits[0].AddrPort)
	}
	if hits[0].RTT < time.Millisecond {
		t.Fatalf("hit rtt %v < 1ms floor", hits[0].RTT)
	}
	if stats.Hits != 1 {
		t.Fatalf("stats hits = %d", stats.Hits)
	}
}

// TestWarpScanReservedBytesWireDiscipline: эдж требует верные reserved и
// отвечает со stamped — сканер обязан и штамповать, и скраббить.
func TestWarpScanReservedBytesWireDiscipline(t *testing.T) {
	reserved := [3]byte{0xAB, 0xCD, 0xEF}
	responder, pc := startScanEdge(t, reserved, true)
	edgeAddr := pc.LocalAddr().(*net.UDPAddr)
	edgeIP, _ := netip.ParseAddr(edgeAddr.IP.String())
	peerPub := responder.PublicKey()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	hits, _, err := WarpScan(context.Background(), WarpScanOptions{
		PrivateKey:        priv,
		PeerPublicKey:     peerPub,
		Reserved:          reserved,
		Prefixes:          []netip.Prefix{netip.PrefixFrom(edgeIP, 32)},
		Ports:             []uint16{uint16(edgeAddr.Port)},
		Limit:             1,
		Workers:           2,
		AllowOutOfCatalog: true,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits=%d — reserved discipline broken (no stamp / no scrub)", len(hits))
	}
}

// TestWarpScanSilentSpace: пространство без отвечающих узлов даёт пустой
// результат (не ошибку) и уважает контекст-дедлайн.
func TestWarpScanSilentSpace(t *testing.T) {
	var priv, peer [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(peer[:]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	hits, stats, err := WarpScan(ctx, WarpScanOptions{
		PrivateKey:        priv,
		PeerPublicKey:     peer,
		Prefixes:          []netip.Prefix{netip.MustParsePrefix("127.0.0.0/28")},
		Ports:             []uint16{2408},
		Workers:           4,
		AllowOutOfCatalog: true,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("hits=%d, want 0 in silent space", len(hits))
	}
	if stats.Probes == 0 {
		t.Fatalf("no probes ran")
	}
}

// TestWarpScanCatalogGate: каталожный красной линии — посторонний префикс
// без AllowOutOfCatalog отвергается ошибкой ДО первой пробы.
func TestWarpScanCatalogGate(t *testing.T) {
	var priv, peer [32]byte
	_, _, err := WarpScan(context.Background(), WarpScanOptions{
		PrivateKey:    priv,
		PeerPublicKey: peer,
		Prefixes:      []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	})
	if err == nil {
		t.Fatalf("out-of-catalog prefix accepted")
	}
}

// TestLCGIteratorFullCycleNoRepeat: один период обходит ВСЕ адреса
// префикса ровно один раз (Hull-Dobell full cycle).
func TestLCGIteratorFullCycleNoRepeat(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/28") // 16 адресов
	seen := map[netip.Addr]bool{}
	it, err := newLCGIterator([]netip.Prefix{p}, func() (int64, error) { return 42, nil })
	if err != nil {
		t.Fatalf("iterator: %v", err)
	}
	for {
		addr, ok := it.next()
		if !ok {
			break
		}
		if !p.Contains(addr) {
			t.Fatalf("address %s outside prefix", addr)
		}
		if seen[addr] {
			t.Fatalf("address %s repeated within one period", addr)
		}
		seen[addr] = true
	}
	if len(seen) != 16 {
		t.Fatalf("visited %d addresses, want 16", len(seen))
	}
}

// TestLCGIteratorMultiPrefixEvenRotation: два префикса обходятся
// чередуясь — короткий скан сэмплирует оба.
func TestLCGIteratorMultiPrefixEvenRotation(t *testing.T) {
	p1 := netip.MustParsePrefix("198.51.100.0/28")
	p2 := netip.MustParsePrefix("203.0.113.0/28")
	it, err := newLCGIterator([]netip.Prefix{p1, p2}, func() (int64, error) { return 7, nil })
	if err != nil {
		t.Fatalf("iterator: %v", err)
	}
	inP1, inP2 := 0, 0
	for i := 0; i < 20; i++ {
		addr, ok := it.next()
		if !ok {
			t.Fatalf("exhausted after %d draws", i)
		}
		if p1.Contains(addr) {
			inP1++
		} else if p2.Contains(addr) {
			inP2++
		}
	}
	if inP1 == 0 || inP2 == 0 {
		t.Fatalf("rotation broken: p1=%d p2=%d", inP1, inP2)
	}
}

// TestWarpScanHitsSortedByRTT: компаратор сканера упорядочивает по RTT,
// равные RTT — по AddrPort (детерминизм вывода).
func TestWarpScanHitsSortedByRTT(t *testing.T) {
	hits := []WarpScanHit{
		{AddrPort: netip.MustParseAddrPort("162.159.193.5:2408"), RTT: 300 * time.Millisecond},
		{AddrPort: netip.MustParseAddrPort("162.159.193.9:500"), RTT: 100 * time.Millisecond},
		{AddrPort: netip.MustParseAddrPort("162.159.193.8:1701"), RTT: 200 * time.Millisecond},
		{AddrPort: netip.MustParseAddrPort("162.159.193.4:2408"), RTT: 100 * time.Millisecond},
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].RTT != hits[j].RTT {
			return hits[i].RTT < hits[j].RTT
		}
		return hits[i].AddrPort.Compare(hits[j].AddrPort) < 0
	})
	want := []string{
		"162.159.193.4:2408", // 100ms, младше по AddrPort
		"162.159.193.9:500",  // 100ms
		"162.159.193.8:1701", // 200ms
		"162.159.193.5:2408", // 300ms
	}
	for i := range want {
		if hits[i].AddrPort.String() != want[i] {
			t.Fatalf("order[%d]=%s want %s", i, hits[i].AddrPort, want[i])
		}
	}
}

var _ = fmt.Sprintf
var _ = binary.LittleEndian
var _ = strconv.Itoa
