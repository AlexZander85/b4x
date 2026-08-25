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
//
// Inbound delivery uses the session tap fan-out (SubscribePackets), which is
// drop-instead-of-block by design; gVisor TCP retransmission absorbs the loss
// at RTT cost. That is acceptable for control-plane traffic this carrier is
// scoped to, and is stated here rather than hidden.
package transportwarp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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
)

// PacketSink is what the carrier writes encapsulated IP datagrams to.
// *Session implements it.
type PacketSink interface {
	WritePacket(pkt []byte) error
}

const netstackQueueLen = 256

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
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
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
		if pkt.IsNil() {
			return
		}
		data := append([]byte(nil), pkt.ToView().AsSlice()...)
		pkt.DecRef()
		if err := c.sink.WritePacket(data); err != nil {
			return // session gone; carrier is dead by definition
		}
	}
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

// HTTPClient returns an HTTP client whose connections ride the tunnel.
// Hostnames are resolved by the CALLER (TunnelResolver/DoH); only literal-IP
// URLs and pre-resolved dial addresses are carried by v1.
func (c *NetstackCarrier) HTTPClient(timeout time.Duration) *http.Client {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portS, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("transportwarp: bad dial addr %q: %w", addr, err)
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("transportwarp: netstack v1 needs literal IPv4 dial targets, got %q", host)
		}
		var p4 [4]byte
		copy(p4[:], ip.To4())
		port, _ := parseUint16(portS)
		ap := netip.AddrPortFrom(netip.AddrFrom4(p4), port)
		return c.DialStream(ctx, ap)
	}
	tr := &http.Transport{
		DialContext:           dial,
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
