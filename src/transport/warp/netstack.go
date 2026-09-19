// NetstackCarrier closes bd b4x-9aa: a userspace TCP/IP endpoint over one
// live MASQUE session built on the vendored gVisor netstack. Every
// carrier-dependent engine surface reduces to "dial TCP through the tunnel":
//
//   - Backend-B inner dialing: DialStream satisfies StreamDialer; wrap with
//     BackendBDialFunc to feed SessionConfig.DialFunc of an inner session.
//   - HTTPS-in-tunnel probes: HTTPSExchangeViaNetstack powers
//     TunnelGeoTransport.WithHTTPSExchange (cf-warp trace warp=on|plus — the
//     ROUTER_PATH_VERIFIED evidence).
//   - DoH upgrade: DoHExchangeViaNetstack feeds NewDoHResolver().WithExchange.
//   - Inner-H3 UDP leg (bd b4x-ive): ListenPacketConn opens the unconnected
//     UDP socket the nested M+M inner QUIC/H3 session rides, so the inner
//     MASQUE establishment is H3-in-H3 rather than the forbidden TCP-over-TCP.
//
// Inbound delivery uses the session tap fan-out (SubscribePackets), which is
// drop-instead-of-block by design; gVisor TCP retransmission absorbs the loss
// at RTT cost. That is acceptable for control-plane traffic this carrier is
// scoped to, and is stated here rather than hidden.
package transportwarp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// PacketSink is what the carrier writes encapsulated IP datagrams to.
// *Session implements it.
type PacketSink interface {
	WritePacket(pkt []byte) error
}

const netstackQueueLen = 256

const (
	// defaultDoHEndpoint is the in-tunnel resolver used when a hostname must
	// be resolved and no override was set: Cloudflare, the WARP edge's own
	// resolver. MUST stay a literal IPv4 URL - it is dialed through this same
	// carrier, so a hostname here would recurse.
	defaultDoHEndpoint = "https://1.1.1.1/dns-query"
)

var ErrNetstackClosed = errors.New("transportwarp: netstack carrier closed")

// NetstackCarrier is one userspace IP host attached to a tunnel packet path.
type NetstackCarrier struct {
	sink    PacketSink
	stack   *stack.Stack
	ep      *channel.Endpoint
	localV4 [4]byte

	mu     sync.Mutex
	closed bool
	cancel context.CancelFunc

	// In-tunnel DNS (b4x-4cl): hostnames handed to DialStreamHost/HTTPClient
	// are resolved with RFC 8484 DoH carried through this same tunnel.
	dohMu       sync.Mutex
	doh         *DoHResolver
	dohEndpoint string
}

// AttachNetstack builds the userspace host with address localV4 (the WARP
// assigned v4) and routes everything over the tunnel. packetSource must yield
// raw IPv4 datagrams received from the tunnel (Session.SubscribePackets or
// Supervisor.SubscribePackets).
func AttachNetstack(sink PacketSink, localV4 [4]byte, mtu int, packetSource <-chan []byte) (*NetstackCarrier, error) {
	if sink == nil {
		return nil, errors.New("transportwarp: netstack requires a packet sink")
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(netstackQueueLen, uint32(mtu), "")
	const nicID tcpip.NICID = 1
	if err := st.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("transportwarp: netstack create nic: %v", err)
	}
	addr := tcpip.AddrFromSlice(netip.AddrFrom4(localV4).AsSlice())
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 32,
		},
	}
	if err := st.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("transportwarp: netstack assign %v: %v", localV4, err)
	}
	st.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	ctx, cancel := context.WithCancel(context.Background())
	c := &NetstackCarrier{sink: sink, stack: st, ep: ep, localV4: localV4, cancel: cancel}
	go c.pumpInbound(ctx, packetSource)
	go c.drainEgress(ctx)
	return c, nil
}

// netstackUDPDebug gates the bd b4x-ive nested-UDP diagnostics (set
// B4_NETSTACK_UDP_DBG=1; stdout/stderr must be redirected to a file). Cached
// at startup so the hot path pays no os.Getenv per packet.
var netstackUDPDebugOn = os.Getenv("B4_NETSTACK_UDP_DBG") != ""

func netstackUDPDebug() bool { return netstackUDPDebugOn }

func netstackUDPDebugLog(format string, args ...any) {
	fmt.Printf("[nsdbg] "+format+"\n", args...)
}

// pumpInbound delivers tunnel-received datagrams into the stack.
func (c *NetstackCarrier) pumpInbound(ctx context.Context, packets <-chan []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-packets:
			if !ok {
				return
			}
			if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 { // IPv4 version nibble
				continue // non-IPv4 or truncated: out of scope for v1 carrier
			}
			if netstackUDPDebug() && pkt[9] == 17 {
				netstackUDPDebugLog("inbound udp len=%d src=%v dst=%v",
					len(pkt), ipv4Src(pkt), ipv4Dst(pkt))
			}
			in := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			})
			c.ep.InjectInbound(ipv4.ProtocolNumber, in)
		}
	}
}

// drainEgress forwards stack-emitted datagrams into the tunnel sink.
func (c *NetstackCarrier) drainEgress(ctx context.Context) {
	for {
		pkt := c.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		data := append([]byte(nil), pkt.ToView().AsSlice()...)
		pkt.DecRef()
		if netstackUDPDebug() && len(data) >= header.IPv4MinimumSize && data[9] == 17 {
			netstackUDPDebugLog("egress udp len=%d src=%v dst=%v",
				len(data), ipv4Src(data), ipv4Dst(data))
		}
		if err := c.sink.WritePacket(data); err != nil {
			if netstackUDPDebug() {
				netstackUDPDebugLog("sink write err: %v", err)
			}
			return // session gone; carrier is dead by definition
		}
	}
}

func ipv4Src(pkt []byte) string {
	if len(pkt) < 16 {
		return "?"
	}
	return netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}).String()
}

func ipv4Dst(pkt []byte) string {
	if len(pkt) < 20 {
		return "?"
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}).String()
}

// LocalV4 returns the assigned tunnel address.
func (c *NetstackCarrier) LocalV4() [4]byte { return c.localV4 }

func (c *NetstackCarrier) closedErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrNetstackClosed
	}
	return nil
}

// DialStream dials TCP through the tunnel (StreamDialer shape).
func (c *NetstackCarrier) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if err := c.closedErr(); err != nil {
		return nil, err
	}
	if !addr.Addr().Is4() {
		return nil, fmt.Errorf("transportwarp: netstack v1 carries IPv4 only, got %v", addr.Addr())
	}
	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}
	conn, err := gonet.DialContextTCP(ctx, c.stack, fa, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("transportwarp: netstack dial %v: %v", addr, err)
	}
	return conn, nil
}

// ListenPacketConn opens an UNCONNECTED UDP socket on the tunnel netstack
// (bd b4x-ive). It is the UDP leg of the nested M+M carrier: the inner
// MASQUE H3 (QUIC) session hands its packets to this socket, so they ride the
// outer CONNECT-IP plane as ordinary IPv4/UDP datagrams. The caller owns the
// returned conn; closing it releases only the socket, never the carrier.
func (c *NetstackCarrier) ListenPacketConn() (net.PacketConn, error) {
	if err := c.closedErr(); err != nil {
		return nil, err
	}
	// Bind to the tunnel's assigned address (unconnected socket): an explicit
	// local bind makes the source address and route unambiguous for gVisor.
	laddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(netip.AddrFrom4(c.localV4).AsSlice()),
	}
	conn, err := gonet.DialUDP(c.stack, &laddr, nil, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("transportwarp: netstack udp socket: %v", err)
	}
	if netstackUDPDebug() {
		netstackUDPDebugLog("bound udp local=%v", conn.LocalAddr())
		return &dbgPacketConn{PacketConn: conn}, nil
	}
	return conn, nil
}

// dbgPacketConn wraps the gonet UDP PacketConn for the b4x-ive diagnostics,
// logging every write/read so the QUIC-over-netstack path is observable.
type dbgPacketConn struct {
	net.PacketConn
}

func (d *dbgPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := d.PacketConn.WriteTo(b, addr)
	netstackUDPDebugLog("pc write len=%d to=%v n=%d err=%v", len(b), addr, n, err)
	return n, err
}

func (d *dbgPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := d.PacketConn.ReadFrom(b)
	if err == nil {
		netstackUDPDebugLog("pc read len=%d from=%v", n, addr)
	}
	return n, addr, err
}

// WithDoHResolver overrides the in-tunnel DoH endpoint used to resolve the
// hostnames handed to DialStreamHost/HTTPClient (b4x-4cl). The endpoint MUST
// be a literal IPv4 URL: it is dialed through this same carrier, so a hostname
// would recurse. Empty keeps the WARP default (Cloudflare 1.1.1.1).
func (c *NetstackCarrier) WithDoHResolver(endpointURL string) *NetstackCarrier {
	c.dohMu.Lock()
	c.dohEndpoint = strings.TrimSpace(endpointURL)
	c.doh = nil
	c.dohMu.Unlock()
	return c
}

// resolver lazily builds the DoH resolver bound to this carrier.
func (c *NetstackCarrier) resolver() *DoHResolver {
	c.dohMu.Lock()
	defer c.dohMu.Unlock()
	if c.doh == nil {
		ep := c.dohEndpoint
		if ep == "" {
			ep = defaultDoHEndpoint
		}
		c.doh = NewDoHResolver().WithExchange(DoHExchangeViaNetstack(c, ep))
	}
	return c.doh
}

// resolveV4 returns the literal IPv4 of host, resolving a hostname through
// the tunnel (in-tunnel DoH) when needed. Non-IPv4 literals are refused.
func (c *NetstackCarrier) resolveV4(ctx context.Context, host string) (netip.Addr, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return netip.AddrFrom4([4]byte(v4)), nil
		}
		return netip.Addr{}, fmt.Errorf("transportwarp: netstack v1 carries IPv4 only, got %q", host)
	}
	addrs, _, err := c.resolver().ResolveA(ctx, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("transportwarp: netstack v1 in-tunnel resolve %q: %w", host, err)
	}
	for _, a := range addrs {
		if a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("transportwarp: netstack v1 in-tunnel resolve %q: no IPv4 answer", host)
}

// DialStreamHost dials host:port through the tunnel, resolving the hostname
// with in-tunnel DoH first. It implements the tproxy hostDialer seam so a
// routing.mode=tunnel set that targets a DOMAIN (not a literal IP) is carried
// by the netstack carrier (b4x-4cl).
func (c *NetstackCarrier) DialStreamHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	addr, err := c.resolveV4(ctx, host)
	if err != nil {
		return nil, err
	}
	return c.DialStream(ctx, netip.AddrPortFrom(addr, port))
}

// HTTPClient returns an HTTP client whose connections ride the tunnel.
// Hostnames are resolved in-tunnel (RFC 8484 DoH over this carrier, b4x-4cl);
// literal-IPv4 URLs dial directly. The DoH endpoint itself is always a
// literal IPv4, so the resolver never recurses.
func (c *NetstackCarrier) HTTPClient(timeout time.Duration) *http.Client {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portS, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("transportwarp: bad dial addr %q: %w", addr, err)
		}
		port, _ := parseUint16(portS)
		ip, rerr := c.resolveV4(ctx, host)
		if rerr != nil {
			return nil, rerr
		}
		return c.DialStream(ctx, netip.AddrPortFrom(ip, port))
	}
	tr := &http.Transport{
		DialContext: dial,
		// Classical curves only: Go 1.24+ offers the X25519MLKEM768 key
		// share by default, which inflates the TLS ClientHello and the server
		// flight by ~1.2 KB. Through a WARP tunnel the outer flow gets only a
		// small per-flow budget (~3-4 KB in this environment), so the
		// post-quantum handshake can stall (FIELD 2026-09-18, bd b4x-nxx).
		TLSClientConfig:       &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// HTTPSExchangeViaNetstack adapts the carrier to TunnelGeoTransport's probe
// slot: plain GET through the tunnel, body bytes back.
func HTTPSExchangeViaNetstack(c *NetstackCarrier) HTTPSExchangeFunc {
	if c == nil {
		return nil
	}
	return func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.HTTPClient(20 * time.Second).Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("transportwarp: https exchange %q: status %d", url, resp.StatusCode)
		}
		body := new(strings.Builder)
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				body.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		return []byte(body.String()), nil
	}
}

// DoHExchangeViaNetstack adapts the carrier to NewDoHResolver().WithExchange:
// RFC 8484 POST of the wire-format query through the tunnel.
func DoHExchangeViaNetstack(c *NetstackCarrier, endpointURL string) DoHExchangeFunc {
	if c == nil {
		return nil
	}
	return func(ctx context.Context, query []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, strings.NewReader(string(query)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		resp, err := c.HTTPClient(10 * time.Second).Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("transportwarp: doh exchange: status %d", resp.StatusCode)
		}
		out := make([]byte, 0, 512)
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			out = append(out, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		return out, nil
	}
}

// Close tears the carrier down: pumps stop, queued egress drops.
func (c *NetstackCarrier) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.ep.Close()
	c.ep.Drain()
}

// CurrentSession snapshots the live H2 session (nil while the supervisor is
// idle/backoff/stopped, or when the current carrier is not the H2 *Session —
// e.g. an established H3 transport). The data-plane accessor canon:
// snapshots only, never lifecycle control — the supervisor keeps owning the
// session's lifetime; consumers attach their own taps/netstacks to it. The
// E7 geo wiring (TunnelGeoTransport) is the first consumer: it needs the
// session's packet surface + counters for the §43 counter-delta proof.
func (s *Supervisor) CurrentSession() *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	sess, ok := s.cur.(*Session)
	if !ok {
		return nil
	}
	return sess
}

// AttachNetstack mounts the userspace TCP/IP carrier (bd b4x-9aa) on the
// CURRENT session generation: egress writes into the live session, inbound
// rides the generation-surviving supervisor tap fan-out. The returned closer
// releases BOTH the carrier and its tap subscription; on session reconnect
// the old carrier's sink dies (WritePacket error) — re-attach against the
// new generation.
func (s *Supervisor) AttachNetstack(localV4 [4]byte, mtu int) (*NetstackCarrier, func(), error) {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur == nil {
		return nil, nil, errors.New("transportwarp: no live session to attach netstack to")
	}
	src, cancelSrc := s.SubscribePackets()
	carrier, err := AttachNetstack(cur, localV4, mtu, src)
	if err != nil {
		cancelSrc()
		return nil, nil, err
	}
	closer := func() {
		carrier.Close()
		cancelSrc()
	}
	return carrier, closer, nil
}

// AssignedLocalV4 returns the current identity's assigned tunnel address, or
// ok=false when no validated identity is loaded yet.
func (s *Supervisor) AssignedLocalV4() ([4]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastIdent == nil {
		return [4]byte{}, false
	}
	v4, err := netip.ParseAddr(s.lastIdent.AssignedV4)
	if err != nil || !v4.Is4() {
		return [4]byte{}, false
	}
	oct := v4.As4()
	return oct, true
}

func parseUint16(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(v), nil
}
