// P3 invariant red test (review §4.2/§6): two consecutive handshake
// initiations of one device must NEVER carry byte-identical InitPacket[0]
// datagrams. With the InitPacketSpecFunc seam the I1 is re-materialized per
// handshake (fresh bytes on the wire); without it the static chain resends
// the identical datagram — the replay signature DPI tables classify.
//
// The test drives a REAL vendored amneziawg-go device over a capturing
// bind (no responder needed: the initiation path builds the Noise message
// and ships I-packets + junk + init through conn.Bind.Send in order).
package transportwg

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// stubTUN is the minimal tun.Device the device accepts (nothing rides the
// TUN in this test — only the handshake send path is exercised).
type stubTUN struct {
	events chan tun.Event
}

func newStubTUN() *stubTUN { return &stubTUN{events: make(chan tun.Event)} }

func (s *stubTUN) File() *os.File { return nil }
func (s *stubTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-s.events // block forever: no data-plane traffic in this test
	return 0, net.ErrClosed
}
func (s *stubTUN) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (s *stubTUN) MTU() (int, error)                            { return 1280, nil }
func (s *stubTUN) Name() (string, error)                        { return "stubTUN", nil }
func (s *stubTUN) Events() <-chan tun.Event                     { return s.events }
func (s *stubTUN) BatchSize() int                               { return 1 }
func (s *stubTUN) Close() error { close(s.events); return nil }

// i1capturingBind records every datagram handed to Send, in order, and
// blocks the receive path until Close (nothing comes back in this test).
type i1capturingBind struct {
	mu   sync.Mutex
	dgs  [][]byte
	dead chan struct{}
	once sync.Once
}

func (b *i1capturingBind) BatchSize() int       { return 1 }
func (b *i1capturingBind) SetMark(uint32) error { return nil }
func (b *i1capturingBind) Close() error {
	b.once.Do(func() { close(b.dead) })
	return nil
}
func (b *i1capturingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}
func (b *i1capturingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range bufs {
		b.dgs = append(b.dgs, append([]byte(nil), bufs[i]...))
	}
	return nil
}
func (b *i1capturingBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		<-b.dead
		return 0, net.ErrClosed
	}}, 51820, nil
}

var _ conn.Bind = (*i1capturingBind)(nil)

// captureI1Datagrams drives TWO consecutive handshake initiations of one
// device (rekey_timeout=1-1 gates the second) and returns the first two
// 8-byte I1 datagrams captured off the bind.
func captureI1Datagrams(t *testing.T, withRegen bool) [][]byte {
	t.Helper()

	bind := &i1capturingBind{dead: make(chan struct{})}
	dev := device.NewDevice(newStubTUN(), bind, DeviceLogger(nil))
	t.Cleanup(dev.Close)

	const pubHex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	ipc := "private_key=" + stringsRepeat("ab", 32) + "\n" +
		"i1=<b 0x0011223344556677>\n" +
		"rekey_timeout=1-1\n" +
		"public_key=" + pubHex + "\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"endpoint=127.0.0.1:51820\n"
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}

	if withRegen {
		var step int
		dev.InitPacketSpecFunc = func(slot int) string {
			if slot != 0 {
				return "" // other slots keep their static chains
			}
			step++
			return fmt.Sprintf("<b 0x%016x>", step) // fresh valid hex per call
		}
	}

	var pub device.NoisePublicKey
	if err := pub.FromHex(pubHex); err != nil {
		t.Fatal(err)
	}
	peer := dev.LookupPeer(pub)
	if peer == nil {
		t.Fatal("peer not found after IpcSet")
	}
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("first initiation: %v", err)
	}
	time.Sleep(1200 * time.Millisecond) // rekey_timeout=1-1
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("second initiation: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	bind.mu.Lock()
	defer bind.mu.Unlock()
	// The I1 datagram leads each SendBuffers batch: the 8-byte datagrams.
	var i1s [][]byte
	for _, dg := range bind.dgs {
		if len(dg) == 8 {
			i1s = append(i1s, dg)
		}
	}
	if len(i1s) < 2 {
		t.Fatalf("captured %d I1 datagrams of %d total, want 2", len(i1s), len(bind.dgs))
	}
	return i1s[:2]
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// TestI1RegeneratedPerHandshake is the review §6 red test: with the seam
// the two consecutive I1 datagrams DIFFER and carry the FRESH specs (the
// static 0x00112233… blob never reaches the wire).
func TestI1RegeneratedPerHandshake(t *testing.T) {
	i1s := captureI1Datagrams(t, true)
	if string(i1s[0]) == string(i1s[1]) {
		t.Fatalf("two handshakes carried identical InitPacket[0]: % x", i1s[0])
	}
	static := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	if string(i1s[0]) == string(static) || string(i1s[1]) == string(static) {
		t.Fatal("the static IpcSet chain went on the wire despite the regen seam")
	}
	if i1s[0][7] != 0x01 || i1s[1][7] != 0x02 {
		t.Fatalf("fresh specs out of order: first % x second % x", i1s[0], i1s[1])
	}
}

// TestI1StaticWithoutRegen documents the pre-P3 baseline: without the seam
// the static chain re-sends the IDENTICAL datagram — the exact regression
// the review flags, kept unchanged for every non-proton target.
func TestI1StaticWithoutRegen(t *testing.T) {
	i1s := captureI1Datagrams(t, false)
	if string(i1s[0]) != string(i1s[1]) {
		t.Fatal("static chains must stay byte-identical (default behavior)")
	}
	static := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	if string(i1s[0]) != string(static) {
		t.Fatalf("unexpected static I1 bytes: % x", i1s[0])
	}
}
