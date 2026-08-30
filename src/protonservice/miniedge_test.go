package protonservice

// The fake Proton edge: a vanilla WireGuard responder on loopback UDP (the
// transportwg stand-pattern, compacted for the service tests). It answers
// the trust gate's DNS probes so a REAL wg.Session can establish through the
// full seek -> gate -> established path.

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	twg "github.com/daniellavrushin/b4/transport/wg"
	"golang.org/x/crypto/curve25519"
)

type miniEdge struct {
	mu            sync.Mutex
	tun           *tuntest.ChannelTUN
	dev           *device.Device
	udp           *net.UDPConn
	port          int
	responderMode int // 0 normal, 1 silent
	stopCh        chan struct{}
	stopped       bool
	priv          twg.Key
	clientPK      twg.Key
}

var _ conn.Bind = (*edgeBindWrap)(nil)

type edgeBindWrap struct {
	*miniEdge
}

func (b *edgeBindWrap) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	b.mu.Lock()
	b.udp = pc.(*net.UDPConn)
	b.port = b.udp.LocalAddr().(*net.UDPAddr).Port
	b.mu.Unlock()
	return []conn.ReceiveFunc{b.makeReadFunc()}, uint16(b.port), nil
}

func (b *edgeBindWrap) makeReadFunc() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		buf := make([]byte, 65535)
		for {
			n, from, err := b.udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return 0, err
			}
			if n > len(bufs[0]) {
				continue
			}
			copy(bufs[0], buf[:n])
			sizes[0] = n
			endpoints[0] = &conn.StdNetEndpoint{AddrPort: from}
			return 1, nil
		}
	}
}

func (b *edgeBindWrap) Send(bufs [][]byte, ep conn.Endpoint) error {
	stdEp, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return errors.New("mini edge: unexpected endpoint type")
	}
	udpEp := &net.UDPAddr{IP: stdEp.AddrPort.Addr().AsSlice(), Port: int(stdEp.AddrPort.Port())}
	for _, buf := range bufs {
		if _, err := b.udp.WriteToUDP(buf, udpEp); err != nil {
			return err
		}
	}
	return nil
}

func (b *edgeBindWrap) SetMark(uint32) error { return nil }
func (b *edgeBindWrap) BatchSize() int       { return 1 }

func (b *edgeBindWrap) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return &conn.StdNetEndpoint{AddrPort: ap}, err
}
func (b *edgeBindWrap) Close() error {
	b.mu.Lock()
	udp := b.udp
	b.mu.Unlock()
	if udp != nil {
		return udp.Close()
	}
	return nil
}

func newMiniEdge(t *testing.T) *miniEdge {
	t.Helper()
	e := &miniEdge{
		tun:    tuntest.NewChannelTUN(),
		stopCh: make(chan struct{}),
	}
	e.dev = device.NewDevice(e.tun.TUN(), &edgeBindWrap{e}, device.NewLogger(device.LogLevelError, "miniedge: "))
	t.Cleanup(e.dev.Close)
	t.Cleanup(e.StopResponder)
	return e
}

// configure sets the vanilla edge keys for the client's public key and
// returns the edge's own public key in base64 (the X25519PublicKey the
// logicals answer must carry).
func (e *miniEdge) configure(clientPub twg.Key) (string, error) {
	priv, err := twg.GenerateKey()
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	e.priv = priv
	e.clientPK = clientPub
	e.mu.Unlock()
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pub)
	cfg := twg.Config{
		PrivateKey: priv,
		Peers: []twg.PeerConfig{{
			PublicKey: clientPub,
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("10.2.0.2/32"),
				netip.MustParsePrefix("10.9.9.1/32"),
				netip.MustParsePrefix("8.8.8.8/32"),
			},
		}},
	}
	ipc, err := cfg.IPCString()
	if err != nil {
		return "", err
	}
	if err := e.dev.IpcSet(ipc); err != nil {
		return "", err
	}
	return pubKeyB64, e.dev.Up()
}

func (e *miniEdge) addrPort() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return "127.0.0.1:" + itoa(e.port)
}

func (e *miniEdge) setSilent() {
	e.mu.Lock()
	e.responderMode = 1
	e.mu.Unlock()
}

func (e *miniEdge) StopResponder() {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	e.mu.Unlock()
	close(e.stopCh)
}

// StartResponder replies to the gate's DNS queries (crafted A responses) —
// the minimal data-plane behavior the trust gate needs.
func (e *miniEdge) StartResponder() {
	go func() {
		for {
			select {
			case <-e.stopCh:
				return
			default:
			}
			select {
			case pkt := <-e.tun.Inbound:
				e.mu.Lock()
				silent := e.responderMode == 1
				e.mu.Unlock()
				if silent {
					continue
				}
				if reply, ok := craftDNSReply(pkt); ok {
					select {
					case e.tun.Outbound <- reply:
					case <-e.stopCh:
						return
					}
				}
			case <-time.After(100 * time.Millisecond):
			case <-e.stopCh:
				return
			}
		}
	}()
}

// craftDNSReply mirrors the gate's DNS query back as a response: the echo
// trick of the transportwg fixture — swap src/dst (IP + UDP ports), set the
// QR bit, and RECOMPUTE both checksums (gVisor validates the UDP checksum).
func craftDNSReply(query []byte) ([]byte, bool) {
	if len(query) < 40 || query[0]>>4 != 4 || query[9] != 17 {
		return nil, false
	}
	out := append([]byte(nil), query...)
	copy(out[12:16], query[16:20]) // src = query dst
	copy(out[16:20], query[12:16]) // dst = query src
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:], ipv4Checksum(out[:20]))
	ihl := int(query[0]&0x0f) * 4
	u := out[ihl:]
	u[0], u[1], u[2], u[3] = u[2], u[3], u[0], u[1] // swap ports
	dns := u[8:]
	if len(dns) < 12 {
		return nil, false
	}
	dns[2] |= 0x80 // QR = response
	// UDP checksum over the pseudo-header (gVisor validates it).
	binary.BigEndian.PutUint16(u[6:], 0)
	var srcAddr, dstAddr [4]byte
	copy(srcAddr[:], out[12:16])
	copy(dstAddr[:], out[16:20])
	sum := uint32(17 + len(u))
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(srcAddr[:])
	add(dstAddr[:])
	add(u)
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(u[6:], ^uint16(sum))
	return out, true
}

// ipv4Checksum computes the header checksum over a 20-byte IPv4 header.
func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
