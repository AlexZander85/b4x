package torsnowflake

// Protected pion network (patch-plan §6.2): every Snowflake socket is
// explicit about its egress semantics. TCP follows the E-TOR egress dialer.
// UDP/packet sockets may go direct only in the `none`/`auto` availability
// profiles; a named `through=<carrier>` is strict and therefore refuses the
// packet path because today's reserve.Carrier contract is TCP-only.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/pion/transport/v4"

	"github.com/daniellavrushin/b4/transport/tor"
)

// ErrPacketCarrierRequired is returned when Snowflake asks Pion for UDP
// while E-TOR is pinned to a stream-only carrier. Silent direct fallback is
// forbidden: privacy/no-leak beats Snowflake availability in this profile.
var ErrPacketCarrierRequired = errors.New("snowflake packet egress unavailable under pinned TCP-only carrier")

type protectedPionNet struct {
	dial              tor.EgressDialFunc
	markCtl           tor.MarkControlFunc
	allowDirectPacket bool
}

func (p *protectedPionNet) wrap(inner transport.Net) transport.Net {
	if inner == nil {
		return failingPionNet{}
	}
	return &wrappedPionNet{Net: inner, prot: p}
}

type wrappedPionNet struct {
	transport.Net
	prot *protectedPionNet
}

func (w *wrappedPionNet) Dial(network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return w.prot.dialAddr(context.Background(), tor.ClassBridgePT, network, address)
	case "udp", "udp4", "udp6":
		if !w.prot.allowDirectPacket {
			return nil, ErrPacketCarrierRequired
		}
		return w.prot.markedDial(network, address)
	default:
		return w.prot.markedDial(network, address)
	}
}

func (w *wrappedPionNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	if raddr == nil {
		return nil, errors.New("protected pion net: DialTCP without raddr")
	}
	if laddr != nil {
		return nil, errors.New("protected pion net: DialTCP with laddr unsupported (egress policy owns the source)")
	}
	conn, err := w.prot.dialAddr(context.Background(), tor.ClassBridgePT, network, net.JoinHostPort(raddr.IP.String(), strconv.Itoa(raddr.Port)))
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc, nil
	}
	return &pionTCPConnShim{Conn: conn}, nil
}

func (w *wrappedPionNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	return nil, errors.New("protected pion net: TCP listeners unsupported")
}

func (w *wrappedPionNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	if !w.prot.allowDirectPacket {
		return nil, ErrPacketCarrierRequired
	}
	lc := net.ListenConfig{Control: w.prot.markCtl}
	pc, err := lc.ListenPacket(context.Background(), network, addrToString(locAddr))
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("protected pion net: ListenUDP returned %T", pc)
	}
	return uc, nil
}

func (w *wrappedPionNet) ListenPacket(network, address string) (net.PacketConn, error) {
	if !w.prot.allowDirectPacket {
		return nil, ErrPacketCarrierRequired
	}
	lc := net.ListenConfig{Control: w.prot.markCtl}
	return lc.ListenPacket(context.Background(), network, address)
}

func (w *wrappedPionNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	if raddr == nil {
		return nil, errors.New("protected pion net: DialUDP without raddr")
	}
	if !w.prot.allowDirectPacket {
		return nil, ErrPacketCarrierRequired
	}
	d := net.Dialer{Control: w.prot.markCtl, Timeout: tor.EgressDirectTimeout}
	conn, err := d.DialContext(context.Background(), network, addrToString(raddr))
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("protected pion net: DialUDP returned %T", conn)
	}
	return uc, nil
}

func (p *protectedPionNet) dialAddr(ctx context.Context, class tor.ConnClass, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("protected pion net addr %q: %w", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("protected pion net port %q invalid", portStr)
	}
	if p.dial == nil {
		return nil, errors.New("protected pion net: egress dialer not wired")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, tor.EgressDirectTimeout*2)
		defer cancel()
	}
	return p.dial(ctx, class, host, uint16(port))
}

func (p *protectedPionNet) markedDial(network, address string) (net.Conn, error) {
	if !p.allowDirectPacket && (network == "udp" || network == "udp4" || network == "udp6") {
		return nil, ErrPacketCarrierRequired
	}
	d := net.Dialer{Control: p.markCtl, Timeout: tor.EgressDirectTimeout}
	return d.Dial(network, address)
}

func addrToString(a *net.UDPAddr) string {
	if a == nil {
		return ":0"
	}
	return a.String()
}

type pionTCPConnShim struct {
	net.Conn
}

func (c *pionTCPConnShim) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *pionTCPConnShim) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *pionTCPConnShim) ReadFrom(r io.Reader) (int64, error) { return io.Copy(c.Conn, r) }
func (c *pionTCPConnShim) SetLinger(sec int) error                  { return nil }
func (c *pionTCPConnShim) SetKeepAlive(keepalive bool) error        { return nil }
func (c *pionTCPConnShim) SetKeepAlivePeriod(d time.Duration) error { return nil }
func (c *pionTCPConnShim) SetNoDelay(noDelay bool) error            { return nil }
func (c *pionTCPConnShim) SetWriteBuffer(bytes int) error           { return nil }
func (c *pionTCPConnShim) SetReadBuffer(bytes int) error            { return nil }

type failingPionNet struct{}

func (failingPionNet) ListenPacket(network, address string) (net.PacketConn, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) Dial(network, address string) (net.Conn, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) Interfaces() ([]*transport.Interface, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) InterfaceByName(name string) (*transport.Interface, error) {
	return nil, errPionNetRefused
}
func (failingPionNet) CreateDialer(dialer *net.Dialer) transport.Dialer {
	return failingPionDialer{}
}
func (failingPionNet) CreateListenConfig(d *net.ListenConfig) transport.ListenConfig {
	return failingPionListenConfig{}
}

type failingPionListenConfig struct{}

func (failingPionListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return nil, errPionNetRefused
}
func (failingPionListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return nil, errPionNetRefused
}

type failingPionDialer struct{}

func (failingPionDialer) Dial(network, address string) (net.Conn, error) {
	return nil, errPionNetRefused
}
func (failingPionDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errPionNetRefused
}

var errPionNetRefused = errors.New("protected pion net: nil inner net refused (G154)")
