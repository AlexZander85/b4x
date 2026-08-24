// Fake Cloudflare WG edge (fakeserver_test.go culture): a REAL amneziawg-go
// device configured as the vanilla WARP peer, fronted by an instrumented UDP
// bind that reproduces the edge's reserved-bytes discipline:
//
//   - RX (client->edge): every datagram's [1:4] is recorded; datagrams whose
//     bytes do not match the expected identity are DROPPED when
//     requireReserved is set (anycast routes by client_id — a wrong id never
//     reaches this edge at all); matching datagrams are zeroed before the
//     device verifies the MAC.
//   - TX (edge->client): responses are STAMPED with the expected reserved
//     bytes when stampTX is set (the real edge sends them SET while the MAC
//     covers zeros).
//
// This makes "handshake completes" PROOF of correct client-side stamping and
// scrubbing, and makes wrong-client_id scenarios fail exactly like the field.
package transportwg

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// wireDump prints first bytes around the next hook (DEBUG aid, -v only).
// TX logs AFTER the wrapped hook (post-stamp truth); RX logs BEFORE it
// (pre-scrub wire truth). nil next = pure observation.
type chainedDump struct {
	t    *testing.T
	next DatagramHook
}

func (w chainedDump) PatchOutbound(buf []byte) {
	if w.next != nil {
		w.next.PatchOutbound(buf)
	}
	n := 12
	if len(buf) < n {
		n = len(buf)
	}
	w.t.Logf("WIRE TX %3d: % x", len(buf), buf[:n])
}

func (w chainedDump) AdjustInbound(buf []byte) {
	n := 12
	if len(buf) < n {
		n = len(buf)
	}
	w.t.Logf("WIRE RX %3d: % x", len(buf), buf[:n])
	if w.next != nil {
		w.next.AdjustInbound(buf)
	}
}

type edgeBind struct {
	mu      sync.Mutex
	conn    *net.UDPConn
	expect  [3]byte
	require bool // true = drop non-matching reserved (CF routing discipline)
	stampTX bool // true = stamp outbound types 1..4 (real CF behavior)
	seen    [][3]byte
	dropped int
	closed  chan struct{}
}

func newEdgeBind(conn *net.UDPConn, expect [3]byte, require, stampTX bool) *edgeBind {
	return &edgeBind{conn: conn, expect: expect, require: require, stampTX: stampTX, closed: make(chan struct{})}
}

func (b *edgeBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	// BindUpdate calls Close() before EVERY Open(); recreate the stop
	// signal and clear the shutdown read-deadline exactly like upstream
	// ChannelBind.Open recreates closeSignal.
	b.closed = make(chan struct{})
	_ = b.conn.SetReadDeadline(time.Time{})
	return []conn.ReceiveFunc{b.receive}, uint16(b.conn.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *edgeBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	for {
		select {
		case <-b.closed:
			return 0, net.ErrClosed
		default:
		}
		n, _, _, addr, err := b.conn.ReadMsgUDPAddrPort(bufs[0], nil)
		if err != nil {
			// Shutdown path: Close() arms a read deadline to unblock us.
			select {
			case <-b.closed:
				return 0, net.ErrClosed
			default:
			}
			return 0, err
		}
		pkt := bufs[0][:n]
		var seen [3]byte
		if n >= 4 {
			copy(seen[:], pkt[1:4])
		}
		b.mu.Lock()
		b.seen = append(b.seen, seen)
		mismatch := b.require && seen != b.expect
		if mismatch {
			b.dropped++
		}
		b.mu.Unlock()
		if mismatch {
			continue // routing discipline: a foreign identity never lands here
		}
		if n >= 4 {
			pkt[1], pkt[2], pkt[3] = 0, 0, 0 // the MAC covers zeroed reserved
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: addr}
		return 1, nil
	}
}

func (b *edgeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	endp, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	stamp := b.stampTX
	res := b.expect
	b.mu.Unlock()
	for i := range bufs {
		if stamp && len(bufs[i]) >= 4 {
			switch bufs[i][0] {
			case 1, 2, 3, 4:
				bufs[i][1], bufs[i][2], bufs[i][3] = res[0], res[1], res[2]
			}
		}
		if _, _, err := b.conn.WriteMsgUDPAddrPort(bufs[i], nil, endp.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

func (b *edgeBind) Close() error {
	// Signal + unblock the pending Read via an immediate read deadline.
	// Ownership of the conn stays with the fixture (BindUpdate calls
	// Close() before EVERY Open(), so closing the socket here would kill
	// the endpoint for good — our Open() clears the deadline instead).
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	_ = b.conn.SetReadDeadline(time.Now())
	return nil
}

func (b *edgeBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return &conn.StdNetEndpoint{AddrPort: ap}, err
}

func (b *edgeBind) BatchSize() int       { return 1 }
func (b *edgeBind) SetMark(uint32) error { return nil }

func (b *edgeBind) stats() (seen [][3]byte, dropped int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][3]byte(nil), b.seen...), b.dropped
}

var _ conn.Bind = (*edgeBind)(nil)

// fakeEdge bundles the responder device with its instrumented bind.
type fakeEdge struct {
	tun  *tuntest.ChannelTUN
	dev  *device.Device
	bind *edgeBind
	ip   [4]byte
}

// startFakeEdge brings up the vanilla-profile responder on loopback UDP.
func startFakeEdge(t *testing.T, expect [3]byte, requireReserved, stampTX bool) (*fakeEdge, error) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = pc.Close() })

	e := &fakeEdge{
		tun:  tuntest.NewChannelTUN(),
		bind: newEdgeBind(pc.(*net.UDPConn), expect, requireReserved, stampTX),
		ip:   [4]byte{10, 9, 9, 1},
	}
	e.dev = device.NewDevice(e.tun.TUN(), e.bind, edgeLogger(t))
	t.Cleanup(e.dev.Close)
	return e, nil
}

// edgeLogger gives -v runs full responder diagnostics.
func edgeLogger(t *testing.T) *device.Logger {
	if testing.Verbose() {
		return device.NewLogger(device.LogLevelVerbose, "edge: ")
	}
	return DeviceLogger(nil)
}

// Configure sets the edge private key and expects the given client public
// key. Allowed IPs: the client's tunnel /32 plus the edge inner IP so a
// client ping addressed to the edge lands on the TUN.
func (e *fakeEdge) Configure(edgePriv Key, clientPub Key, clientTunnelIP netip.Addr) error {
	c := Config{
		PrivateKey: edgePriv,
		Peers: []PeerConfig{{
			PublicKey: clientPub,
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(clientTunnelIP, 32),
				netip.PrefixFrom(ip4(e.ip), 32),
			},
		}},
	}
	ipc, err := c.IPCString()
	if err != nil {
		return err
	}
	if err := e.dev.IpcSet(ipc); err != nil {
		return err
	}
	return e.dev.Up()
}

// addr returns the loopback UDP address of the edge.
func (e *fakeEdge) addr() string {
	return "127.0.0.1:" + itoaPort(uint16(e.bind.conn.LocalAddr().(*net.UDPAddr).Port))
}

// handshakeEstablished reads the responder's IpcGet state.
func (e *fakeEdge) handshakeEstablished() bool {
	state, err := e.dev.IpcGet()
	if err != nil {
		return false
	}
	return strings.Contains(state, "last_handshake_time_sec=") &&
		!strings.Contains(state, "last_handshake_time_sec=0")
}

func clientHandshakeEstablished(dev *device.Device) bool {
	state, err := dev.IpcGet()
	if err != nil {
		return false
	}
	return strings.Contains(state, "last_handshake_time_sec=") &&
		!strings.Contains(state, "last_handshake_time_sec=0")
}

func waitCondition(deadline time.Duration, cond func() bool) bool {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	for {
		if cond() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitHandshake(t *testing.T, e *fakeEdge, deadline time.Duration) {
	t.Helper()
	if !waitCondition(deadline, e.handshakeEstablished) {
		t.Fatal("fake edge never saw a completed handshake")
	}
}
