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
	"encoding/binary"
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

// edgeRXKind classifies one captured datagram at the wire layer.
type edgeRXKind string

const (
	rxInit    edgeRXKind = "init"   // vanilla handshake initiation (type 1)
	rxResp    edgeRXKind = "resp"   // vanilla handshake response (type 2)
	rxCookie  edgeRXKind = "cookie" // type 3
	rxData    edgeRXKind = "data"   // vanilla transport (type 4)
	rxUnknown edgeRXKind = "unknown"
)

// edgeRX is one captured datagram with its wire classification.
type edgeRX struct {
	Res   [3]byte
	Kind  edgeRXKind
	Bytes int
}

type edgeBind struct {
	mu      sync.Mutex
	conn    *net.UDPConn
	expect  [3]byte
	require bool // true = drop non-matching reserved (CF routing discipline)
	stampTX bool // true = stamp outbound types 1..4 (real CF behavior)
	scrubRX bool // true = zero [1:4] inbound before MAC (CF stamps; generic AWG servers do NOT)
	seen    []edgeRX
	dropped int
	closed  chan struct{}
}

func newEdgeBind(conn *net.UDPConn, expect [3]byte, require, stampTX, scrubRX bool) *edgeBind {
	return &edgeBind{conn: conn, expect: expect, require: require, stampTX: stampTX, scrubRX: scrubRX, closed: make(chan struct{})}
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
		rec := edgeRX{Bytes: n}
		if n >= 4 {
			copy(rec.Res[:], pkt[1:4])
		}
		switch {
		case n >= 1 && pkt[0] == 1:
			rec.Kind = rxInit
		case n >= 1 && pkt[0] == 2:
			rec.Kind = rxResp
		case n >= 1 && pkt[0] == 3:
			rec.Kind = rxCookie
		case n >= 1 && pkt[0] == 4:
			rec.Kind = rxData
		default:
			rec.Kind = rxUnknown
		}
		b.mu.Lock()
		b.seen = append(b.seen, rec)
		mismatch := b.require && rec.Res != b.expect
		if mismatch {
			b.dropped++
		}
		b.mu.Unlock()
		if mismatch {
			continue // routing discipline: a foreign identity never lands here
		}
		if n >= 4 && b.scrubRX {
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

func (b *edgeBind) stats() (seen []edgeRX, dropped int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]edgeRX(nil), b.seen...), b.dropped
}

var _ conn.Bind = (*edgeBind)(nil)

// fakeEdge bundles the responder device with its instrumented bind.
type fakeEdge struct {
	mu       sync.Mutex
	tun      *tuntest.ChannelTUN
	dev      *device.Device
	bind     *edgeBind
	ip       [4]byte
	stopResp chan struct{}
	respMode ResponderMode
	inner    []innerRX

	// remembered keying material for live reconfiguration (tests).
	edgePriv   Key
	clientPub  Key
	clientAddr netip.Addr
}

// startFakeEdge brings up the responder on loopback UDP. scrubRX must be
// true ONLY for Cloudflare-mode fixtures (the real edge stamps reserved and
// expects the client MAC over zeroed bytes).
func startFakeEdge(t *testing.T, expect [3]byte, requireReserved, stampTX, scrubRX bool) (*fakeEdge, error) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = pc.Close() })

	e := &fakeEdge{
		tun:  tuntest.NewChannelTUN(),
		bind: newEdgeBind(pc.(*net.UDPConn), expect, requireReserved, stampTX, scrubRX),
		ip:   [4]byte{10, 9, 9, 1},
	}
	e.dev = device.NewDevice(&onceCloseTUN{Device: e.tun.TUN()}, e.bind, edgeLogger(t))
	t.Cleanup(e.dev.Close)
	// PATCH-16 (B8) finding: the responder goroutine leaked past every test
	// (nothing ever closed its stop channel). The cleanup below stops it —
	// goleak's first unknown leak, now fixed at the fixture level.
	t.Cleanup(e.StopResponder)
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
// key. Allowed IPs: the client's tunnel /32, the edge inner IP, and the DNS
// resolver the trust gate probes (8.8.8.8) so decrypted gate queries route
// to the TUN. The edge runs with a VANILLA profile.
func (e *fakeEdge) Configure(edgePriv Key, clientPub Key, clientTunnelIP netip.Addr) error {
	return e.ConfigureProfile(edgePriv, clientPub, clientTunnelIP, Profile{})
}

// ConfigureProfile is the AWG-generation variant: the edge runs the given
// obfuscation profile (matching S/H required on both ends; I-chains are
// client-side only and irrelevant to the edge).
func (e *fakeEdge) ConfigureProfile(edgePriv Key, clientPub Key, clientTunnelIP netip.Addr, prof Profile) error {
	e.mu.Lock()
	e.edgePriv = edgePriv
	e.clientPub = clientPub
	e.clientAddr = clientTunnelIP
	e.mu.Unlock()
	c := Config{
		PrivateKey: edgePriv,
		Profile:    prof,
		Peers: []PeerConfig{{
			PublicKey: clientPub,
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(clientTunnelIP, 32),
				netip.PrefixFrom(ip4(e.ip), 32),
				netip.PrefixFrom(netip.MustParseAddr("8.8.8.8"), 32),
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

// ResponderMode controls the edge's data-plane behavior for session tests.
type ResponderMode int

const (
	// ResponderNormal answers UDP/53 queries with a crafted A reply.
	ResponderNormal ResponderMode = iota
	// ResponderSilent swallows everything (silent-DPI fixture).
	ResponderSilent
)

// innerRX is one decrypted packet observed at the edge TUN.
type innerRX struct {
	Kind  string // "dns-boot" | "dns-gate" | "icmp" | "other"
	QName string
}

// classifyInner decodes a decrypted IP packet at the edge TUN.
func classifyInner(pkt []byte) innerRX {
	if len(pkt) >= 20 && pkt[0]>>4 == 4 {
		switch pkt[9] {
		case 1:
			if len(pkt) >= 28 {
				return innerRX{Kind: "icmp"}
			}
		case 17:
			ihl := int(pkt[0]&0x0f) * 4
			u := pkt[ihl:]
			if len(u) >= 8+12 {
				dport := int(u[2])<<8 | int(u[3])
				if dport == 53 {
					dns := u[8:]
					qname := parseQName(dns[12:])
					kind := "dns-gate"
					if strings.HasPrefix(qname, bootstrapQNameLabel) {
						kind = "dns-boot"
					}
					return innerRX{Kind: kind, QName: qname}
				}
			}
		}
	}
	return innerRX{Kind: "other"}
}

// parseQName reads a dotted DNS name starting at the question section.
func parseQName(b []byte) string {
	var sb strings.Builder
	pos := 0
	for pos < len(b) {
		l := int(b[pos])
		if l == 0 {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		if pos+1+l > len(b) {
			return sb.String()
		}
		sb.Write(b[pos+1 : pos+1+l])
		pos += 1 + l
	}
	return sb.String()
}

// StopResponder terminates the responder goroutine (PATCH-16 goleak
// hygiene). Safe to call multiple times and when not running.
func (e *fakeEdge) StopResponder() {
	e.mu.Lock()
	stop := e.stopResp
	e.stopResp = nil
	e.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

// StartResponder pumps decrypted packets back into the tunnel: UDP/53 gets
// a crafted reply (unless silent mode), everything else is dropped. Every
// decrypted packet is classified into the inner log for ordering tests.
func (e *fakeEdge) StartResponder(mode ResponderMode) {
	stop := make(chan struct{})
	e.mu.Lock()
	if e.stopResp != nil {
		e.mu.Unlock()
		return // already running; call StopResponder first
	}
	e.stopResp = stop
	e.respMode = mode
	e.mu.Unlock()
	go func() {
		for {
			select {
			case <-stop:
				return
			case pkt := <-e.tun.Inbound:
				e.mu.Lock()
				e.inner = append(e.inner, classifyInner(pkt))
				silent := e.respMode == ResponderSilent
				e.mu.Unlock()
				if silent {
					continue
				}
				reply := dnsReplyPacket(pkt)
				if reply == nil {
					continue
				}
				select {
				case e.tun.Outbound <- reply:
				default:
				}
			}
		}
	}()
}

// SetResponderMode flips behavior on a live responder (mid-session drop).
func (e *fakeEdge) SetResponderMode(m ResponderMode) {
	e.mu.Lock()
	e.respMode = m
	e.mu.Unlock()
}

// Reconfigure flips the edge's AWG parameters mid-session (refused-identity
// fixture): re-renders IPC with remembered keying material.
func (e *fakeEdge) Reconfigure(prof Profile) error {
	e.mu.Lock()
	priv, pub, ip := e.edgePriv, e.clientPub, e.clientAddr
	e.mu.Unlock()
	return e.ConfigureProfile(priv, pub, ip, prof)
}

// innerStats returns a copy of the decrypted-packet log.
func (e *fakeEdge) innerStats() []innerRX {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]innerRX(nil), e.inner...)
}

// dnsReplyPacket crafts an IP-level DNS A reply for a query packet.
func dnsReplyPacket(query []byte) []byte {
	if len(query) < 40 || query[0]>>4 != 4 || query[9] != 17 {
		return nil
	}
	out := append([]byte(nil), query...)
	copy(out[12:16], query[16:20])
	copy(out[16:20], query[12:16])
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:], ipv4Checksum(out[:20]))
	ihl := int(query[0]&0x0f) * 4
	u := out[ihl:]
	u[0], u[1], u[2], u[3] = u[2], u[3], u[0], u[1]
	dns := u[8:]
	if len(dns) < 12 {
		return nil
	}
	dns[2] |= 0x80
	// gvisor validates the UDP checksum: compute over the pseudo-header.
	binary.BigEndian.PutUint16(u[6:], 0)
	var src, dst [4]byte
	copy(src[:], out[12:16])
	copy(dst[:], out[16:20])
	sum := uint32(17 + len(u))
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src[:])
	add(dst[:])
	add(u)
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(u[6:], ^uint16(sum))
	return out
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
