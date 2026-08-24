// Cross-engine M+W e2e (E-NM tail #1): a REAL transportwarp CONNECT-IP
// session against a fake MASQUE edge whose capsule handler NATs the crafted
// IPv4/UDP datagrams to a REAL amneziawg-go responder on loopback host UDP.
// The composed MasqueAwgRuntime must carry the inner AWG client's handshake
// AND trust-gate DNS round trips through BOTH planes:
//
//	inner WG -> LoopbackForwarder -> ForwarderSeam -> MasqueDatagramCarrier
//	         -> capsule frame -> fake MASQUE edge --NAT--> real AWG edge
//	reply    <- demux <- tap pump <- capsule <- NAT <- responder <- TUN
//
// Success criterion: inner session reaches wg_established (handshake + both
// gate DNS round trips) and the edge records a completed handshake. This is
// the offline proof of the non-RU escalation path (design 7.5 step 2).
package nested

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/http2"

	twarp "github.com/daniellavrushin/b4/transport/warp"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// ---- direct capsule plane over one DialSession (no enrollment) ----

type planeAdapter struct{ sess *twarp.Session }

func (p planeAdapter) WritePacket(pkt []byte) error { return p.sess.WritePacket(pkt) }
func (p planeAdapter) SubscribePackets() (<-chan []byte, func()) {
	return p.sess.SubscribePackets()
}
func (p planeAdapter) Snapshot() twarp.Status {
	return twarp.Status{State: twarp.StateConnected, RouteHeld: true}
}

// ---- fake MASQUE edge: TLS+h2 CONNECT-IP with a NAT into the AWG edge ----

type relayEdge struct {
	t     *testing.T
	key   *ecdsa.PrivateKey
	ln    net.Listener
	decl  netip.AddrPort // DECLARED inner edge seen by carrier/config
	real  netip.AddrPort // REAL loopback address of the AWG responder
	local [4]byte        // outer assigned v4 (datagram dst on replies)

	mu          sync.Mutex
	clientSport uint16
	capsulesIn  int
	fwd         int64 // payloads NAT-forwarded to the real edge
	epRead      int64 // replies read from the uplink socket
	epSent      int64 // reply capsules written back
}

func newTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// startRelayEdge serves one CONNECT-IP endpoint that forwards UDP payloads
// between the capsule plane and the REAL awg edge, rewriting addresses so
// the declared TEST-NET inner edge stays stable for validation/demux.
func startRelayEdge(t *testing.T, decl netip.AddrPort, real netip.AddrPort, outerLocal [4]byte) *relayEdge {
	t.Helper()
	re := &relayEdge{t: t, key: newTestECDSAKey(t), decl: decl, real: real, local: outerLocal}
	der := selfSignedDER(t, re.key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: re.key}},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	re.ln = ln
	go re.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return re
}

func selfSignedDER(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (re *relayEdge) addr() netip.AddrPort {
	return netip.MustParseAddrPort(re.ln.Addr().String())
}

func capsuleHeader(buf []byte) (typ, length, hdr int, complete bool) {
	if len(buf) == 0 {
		return 0, 0, 0, false
	}
	s1 := 1 << (buf[0] >> 6)
	if len(buf) < s1 {
		return 0, 0, 0, false
	}
	tv := uint64(buf[0] & 0x3f)
	for i := 1; i < s1; i++ {
		tv = tv<<8 | uint64(buf[i])
	}
	rest := buf[s1:]
	if len(rest) == 0 {
		return 0, 0, 0, false
	}
	s2 := 1 << (rest[0] >> 6)
	if len(rest) < s2 {
		return 0, 0, 0, false
	}
	lv := uint64(rest[0] & 0x3f)
	for i := 1; i < s2; i++ {
		lv = lv<<8 | uint64(rest[i])
	}
	return int(tv), int(lv), s1 + s2, true
}

func appendCapsule(dst []byte, payload []byte) []byte {
	dst = appendVarint(dst, 0)
	dst = appendVarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}

// appendVarint mirrors the QUIC/RFC9000 section-16 encoding used by the
// capsule protocol (warp varint.go AppendVarint): 2-bit length prefix.
func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v <= 0x3f:
		return append(dst, byte(v))
	case v <= 0x3fff:
		return append(dst, byte(v>>8)&0x3f|0x40, byte(v))
	case v <= 0x3fffffff:
		return append(dst, byte(v>>24)&0x3f|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst, byte(v>>56)&0x3f|0xc0,
			byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24),
			byte(v>>16), byte(v>>8), byte(v))
	}
}

func (re *relayEdge) serve() {
	for {
		conn, err := re.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			if tc, ok := c.(*tls.Conn); ok {
				if err := tc.Handshake(); err != nil {
					_ = c.Close()
					return
				}
			}
			h2s := &http2.Server{}
			h2s.ServeConn(c, &http2.ServeConnOpts{Handler: http.HandlerFunc(re.handle)})
		}(conn)
	}
}

func (re *relayEdge) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("cf-warp-colo", "TEST")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}

	uplink, err := net.DialUDP("udp4", nil, udpAddrOf(re.real))
	if err != nil {
		return
	}
	defer func() { _ = uplink.Close() }()

	// Invariant copied from the proven fakeServer fixture: ALL writes to
	// the h2 ResponseWriter come from THIS (handler) goroutine; helpers
	// only produce frames into wrCh.
	wrCh := make(chan []byte, 128)
	done := make(chan struct{})

	// Uplink reader: AWG responder replies -> crafted reply datagrams.
	go func() {
		defer close(wrCh)
		buf := make([]byte, 65535)
		for {
			n, rerr := uplink.Read(buf)
			if rerr != nil {
				return
			}
			atomic.AddInt64(&re.epRead, 1)
			re.mu.Lock()
			sport := re.clientSport
			re.mu.Unlock()
			if sport == 0 {
				continue // no client flow observed yet
			}
			pkt, cerr := BuildUDPDatagram(
				netip.AddrFrom4(re.decl.Addr().As4()), netip.AddrFrom4(re.local),
				uint16(re.decl.Port()), sport, buf[:n])
			if cerr != nil {
				continue
			}
			frame := appendCapsule(nil, pkt)
			select {
			case wrCh <- frame:
				atomic.AddInt64(&re.epSent, 1)
			case <-done:
				return
			}
		}
	}()

	// Request-body reader: capsule parse + NAT forward toward the edge.
	go func() {
		defer close(done)
		pending := make([]byte, 0, 4096)
		chunk := make([]byte, 16<<10)
		for {
			typ, length, hdr, complete := capsuleHeader(pending)
			if !(complete && len(pending) >= hdr+length) {
				n, rerr := r.Body.Read(chunk)
				if n > 0 {
					pending = append(pending, chunk[:n]...)
				}
				if n == 0 && rerr != nil {
					return
				}
				continue
			}
			payload := append([]byte(nil), pending[hdr:hdr+length]...)
			pending = pending[hdr+length:]
			if typ != 0 {
				continue
			}
			re.mu.Lock()
			re.capsulesIn++
			re.mu.Unlock()

			tuple, wgPayload, perr := SplitUDPDatagram(payload)
			if perr != nil {
				continue
			}
			re.mu.Lock()
			// Last writer wins - mirrors the forwarder's single-session
			// semantics and self-heals across inner generation restarts
			// (each restart allocates a fresh carrier sport).
			re.clientSport = tuple.SrcPort
			re.mu.Unlock()

			if tuple.DstIP == re.decl.Addr() && tuple.DstPort == re.decl.Port() {
				atomic.AddInt64(&re.fwd, 1)
				if _, werr := uplink.Write(wgPayload); werr != nil {
					return
				}
			}
			// Everything else (e.g. data-plane probes to 8.8.8.8) is
			// swallowed: this edge routes ONLY the declared peer.
		}
	}()

	for frame := range wrCh {
		if _, werr := w.Write(frame); werr != nil {
			return
		}
		if fl != nil {
			fl.Flush()
		}
	}
}

func udpAddrOf(ap netip.AddrPort) *net.UDPAddr {
	ip := ap.Addr().As4()
	return &net.UDPAddr{IP: ip[:], Port: int(ap.Port())}
}

// ---- real AWG responder (vanilla amneziawg device on host loopback) ----

type onceCloseTUN struct {
	tun.Device
	once sync.Once
}

func (w *onceCloseTUN) Close() error {
	var err error
	w.once.Do(func() { err = w.Device.Close() })
	return err
}

type wgEdge struct {
	tun   *tuntest.ChannelTUN
	dev   *device.Device
	bind  *twg.Bind
	portI int

	rx, tx int64 // wire datagrams observed via the hook (atomic)

	firstMu sync.Mutex
	firstRX string
}

// edgeCountHook observes wire datagrams both directions (observation only).
type edgeCountHook struct{ e *wgEdge }

func (h edgeCountHook) PatchOutbound(buf []byte) {
	atomic.AddInt64(&h.e.tx, 1)
}

func (h edgeCountHook) AdjustInbound(buf []byte) {
	atomic.AddInt64(&h.e.rx, 1)
	h.e.firstMu.Lock()
	if h.e.firstRX == "" && len(buf) >= 4 {
		h.e.firstRX = fmt.Sprintf("len=%d head=% x", len(buf), buf[:4])
	}
	h.e.firstMu.Unlock()
}

func startWgEdge(t *testing.T, edgePriv, clientPub twg.Key, clientV4 netip.Addr) *wgEdge {
	t.Helper()

	e := &wgEdge{tun: tuntest.NewChannelTUN()}
	bind := twg.NewBind(twg.SocketOptions{}) // unconstrained is fine in-process
	e.bind = bind
	bind.SetDatagramHook(edgeCountHook{e})
	var logger *device.Logger
	if testing.Verbose() {
		logger = device.NewLogger(device.LogLevelVerbose, "edge: ")
	} else {
		logger = twg.DeviceLogger(nil)
	}
	e.dev = device.NewDevice(&onceCloseTUN{Device: e.tun.TUN()}, bind, logger)

	cfg := twg.Config{
		PrivateKey: edgePriv,
		Peers: []twg.PeerConfig{{
			PublicKey: clientPub,
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(clientV4, 32),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 9, 9, 1}), 32),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 32),
			},
		}},
	}
	ipc, err := cfg.IPCString()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.dev.IpcSet(ipc); err != nil {
		t.Fatal(err)
	}
	if err := e.dev.Up(); err != nil {
		t.Fatal(err)
	}
	// The REAL listening port belongs to the bind's own sockets - only
	// readable after Up().
	e.portI = int(bind.ActualPort())
	if e.portI == 0 {
		t.Fatal("edge bind did not report its port")
	}
	t.Cleanup(e.dev.Close)

	// Responder: decrypted UDP/53 queries get a crafted A reply injected
	// back through the tunnel (trust-gate food).
	go func() {
		for pkt := range e.tun.Inbound {
			if reply := dnsReply(pkt); reply != nil {
				select {
				case e.tun.Outbound <- reply:
				default:
				}
			}
		}
	}()
	return e
}

// dnsReply mirrors the wg-suite fixture: swap IP/UDP directions, set QR=1,
// recompute both checksums (gVisor validates the UDP one).
func dnsReply(query []byte) []byte {
	if len(query) < 40 || query[0]>>4 != 4 || query[9] != 17 {
		return nil
	}
	out := append([]byte(nil), query...)
	copy(out[12:16], query[16:20])
	copy(out[16:20], query[12:16])
	binary.BigEndian.PutUint16(out[10:], 0) // zero BEFORE summing (gVisor validates)
	binary.BigEndian.PutUint16(out[10:], finalize(sum32(out[:20])))
	ihl := int(query[0]&0x0f) * 4
	u := out[ihl:]
	u[0], u[1], u[2], u[3] = u[2], u[3], u[0], u[1]
	dns := u[8:]
	if len(dns) < 12 {
		return nil
	}
	dns[2] |= 0x80

	var src, dst [4]byte
	copy(src[:], out[12:16])
	copy(dst[:], out[16:20])
	binary.BigEndian.PutUint16(u[6:], 0) // zero before summing
	var pseudo []byte
	pseudo = append(pseudo, src[:]...)
	pseudo = append(pseudo, dst[:]...)
	pseudo = append(pseudo, 0, 17)
	plen := make([]byte, 2)
	binary.BigEndian.PutUint16(plen, uint16(len(u)))
	pseudo = append(pseudo, plen...)
	sum := sum32(append(pseudo, u...))
	binary.BigEndian.PutUint16(u[6:], finalize(sum))
	return out
}

func (e *wgEdge) handshakeSeen() bool {
	state, err := e.dev.IpcGet()
	if err != nil {
		return false
	}
	return contains(state, "last_handshake_time_sec=") &&
		!contains(state, "last_handshake_time_sec=0")
}

func (e *wgEdge) firstSnapshot() string {
	e.firstMu.Lock()
	defer e.firstMu.Unlock()
	return e.firstRX
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ---- key material ----

func genWGPair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

// ---- the e2e ----

func TestMasqueAwgE2EHandshakeAndGateThroughBothPlanes(t *testing.T) {
	outerLocal := [4]byte{198, 51, 100, 7} // outer assigned (carrier source)

	// Client identity (generic AWG server, cf_warp=false: zero reserved).
	cliPrivB64, cliPubB64 := genWGPair(t)
	edgePrivB64, edgePubB64 := genWGPair(t)
	edgePriv, err := twg.ParseKeyB64(edgePrivB64)
	if err != nil {
		t.Fatal(err)
	}
	cliPub, err := twg.ParseKeyB64(cliPubB64)
	if err != nil {
		t.Fatal(err)
	}
	ident, err := twg.NewIdentity(cliPrivB64, edgePubB64, "AAAA", "10.66.66.2", "", false)
	if err != nil {
		t.Fatal(err)
	}

	// Real AWG responder first: its ACTUAL bind port feeds the DECLARED edge.
	edge := startWgEdge(t, edgePriv, cliPub, netip.MustParseAddr("10.66.66.2"))
	if edge.portI == 0 {
		t.Fatal("edge port unknown")
	}
	decl := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 9}), uint16(edge.portI))

	// Fake MASQUE edge (CONNECT-IP + NAT into the responder).
	relay := startRelayEdge(t, decl, netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(edge.portI)), outerLocal)

	// OUTER plane: one real CONNECT-IP session, no supervisor enrollment.
	var planeRef planeAdapter
	sess, cres, err := twarp.DialSession(context.Background(), twarp.SessionConfig{
		Endpoint:  relay.addr(),
		ClientKey: newTestECDSAKey(t),
		Pin:       &relay.key.PublicKey,
		LocalV4:   outerLocal,
	})
	if err != nil {
		t.Fatalf("masque dial: %v (class=%s status=%d)", err, cres.FailureClass, cres.Status)
	}
	planeRef = planeAdapter{sess: sess}

	rt, err := NewMasqueAwgRuntime(MasqueAwgConfig{
		Pair: PairConfig{
			Outer: LayerSpec{
				Kind: KindMasqueH2, IdentitySlot: SlotPrimary,
				ProfileID: "test/masque", Endpoint: relay.addr(), MTU: 1280,
			},
			Inner: LayerSpec{
				Kind: KindAWG, IdentitySlot: SlotSecondary,
				ProfileID: "test/awg", Endpoint: decl, MTU: MaxInnerMTU,
			},
		},
		Plane:        planeRef,
		LocalV4:      outerLocal,
		InnerIdent:   ident,
		InnerProfile: twg.Profile{},
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}

	events := newEventLog()
	rt.cfg.InnerOnEvent = func(ev twg.SessionEvent) {
		if ev.Reason != "" {
			events.add(ev.Name + "[" + string(ev.Class) + "/" + ev.Reason + "]")
			return
		}
		events.add(ev.Name)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer rt.Stop()

	// The full chain proof: handshake completion AND trust-gate passage
	// (two DNS round trips through BOTH planes) on the INNER session.
	if !events.await(t, 90*time.Second, "wg_handshake_ok") {
		link, gen, child := rt.Status()
		relay.mu.Lock()
		caps := relay.capsulesIn
		sport := relay.clientSport
		fwd, repRead, repSent := relay.fwd, relay.epRead, relay.epSent
		relay.mu.Unlock()
		matched, unknown := rt.RelayDemuxStats()
		t.Fatalf("diagnostics: link=%s gen=%d child=%v relayCaps=%d clientSport=%d fwd=%d repRead=%d repSent=%d edgeRx=%d edgeTx=%d firstRX=%s demuxMatched=%d demuxUnknown=%d events=%v",
			link, gen, child, caps, sport, fwd, repRead, repSent,
			atomic.LoadInt64(&edge.rx), atomic.LoadInt64(&edge.tx),
			edge.firstSnapshot(), matched, unknown, events.tail())
	}
	if !events.await(t, 90*time.Second, "wg_established") {
		t.Fatalf("handshake ok but no established; events=%v", events.tail())
	}

	link, gen, child := rt.Status()
	if link != "up" || !child || gen == 0 {
		t.Fatalf("status = %s/gen=%d/child=%v", link, gen, child)
	}
	if !edge.handshakeSeen() {
		t.Fatal("responder never recorded a completed handshake")
	}
	relay.mu.Lock()
	caps := relay.capsulesIn
	relay.mu.Unlock()
	if caps == 0 {
		t.Fatal("relay edge saw no capsules")
	}
	if matched, _ := rt.RelayDemuxStats(); matched == 0 {
		t.Fatal("carrier demux never matched a reply")
	}
	t.Logf("e2e: established through %d relayed capsules", caps)
}

// eventLog keeps every event name and lets await() fail with full context.
type eventLog struct {
	mu   sync.Mutex
	all  []string
	seen chan string
}

func newEventLog() *eventLog { return &eventLog{seen: make(chan string, 128)} }

func (l *eventLog) add(name string) {
	l.mu.Lock()
	l.all = append(l.all, name)
	l.mu.Unlock()
	select {
	case l.seen <- name:
	default:
	}
}

func (l *eventLog) tail() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.all) > 12 {
		return append([]string(nil), l.all[len(l.all)-12:]...)
	}
	return append([]string(nil), l.all...)
}

func (l *eventLog) await(t *testing.T, d time.Duration, want string) bool {
	t.Helper()
	deadline := time.After(d)
	for {
		// Drain anything already buffered before blocking.
		select {
		case ev := <-l.seen:
			if ev == want {
				return true
			}
			continue
		default:
		}
		select {
		case ev := <-l.seen:
			if ev == want {
				return true
			}
		case <-deadline:
			return false
		}
	}
}
