// Custom conn.Bind for the embedded AWG device (design §1): plain UDP
// sockets with scoped-routing options applied at creation (SO_MARK,
// SO_BINDTODEVICE — apply-or-fail, mirroring the warp dialpolicy posture)
// and a datagram patch seam for Cloudflare reserved routing bytes.
//
// The seam is intentionally INERT in WG1 (owner decision 24.08): WG2 fills
// the hook bodies without changing this architecture. Two directions are
// separate by contract:
//
//   - PatchOutbound(buf) runs in Send(), i.e. after Noise encapsulation,
//     right before the datagram hits the wire. CF reserved bytes go into
//     packet[1:4] for message types 1..4.
//   - AdjustInbound(buf) runs in the receive funcs BEFORE the buffer is
//     handed to the device (the MAC is computed over zeroed reserved bytes,
//     so inbound must be re-zeroed first; warp-socks tunnel.rs pattern).
//
// A nil hook means pure passthrough with zero allocations. This seam carries
// ONLY the CF reserved bytes: AWG junk chains (I1-I5) live inside the
// amneziawg-go device via IpcSet config parameters and never touch it.
package transportwg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

var (
	_ conn.Bind = (*Bind)(nil)
)

// SocketOptions pins every UDP socket of the bind. Zero value = unconstrained
// (unit tests, non-production). Production instances MUST set FwMark or
// BindDevice so tunnel traffic can never recurse into itself; on platforms
// where a constrained policy cannot be applied, Open fails closed.
type SocketOptions struct {
	// FwMark sets SO_MARK at socket creation and on SetMark updates.
	FwMark uint32
	// BindDevice pins sockets to the named interface (SO_BINDTODEVICE).
	BindDevice string
	// RequireMark makes Open/SetMark fail closed when no mark is configured
	// or mark application fails (production posture: no silent fallback).
	RequireMark bool
}

// Constrained reports whether the options actually pin the path.
func (o SocketOptions) Constrained() bool { return o.FwMark != 0 || o.BindDevice != "" }

// DatagramHook is the reserved-bytes seam (see package doc). Implementations
// must be safe for concurrent use: Send and the receive funcs run on device
// worker goroutines.
type DatagramHook interface {
	PatchOutbound(buf []byte)
	AdjustInbound(buf []byte)
}

// Bind implements conn.Bind over real UDP sockets with batch size 1
// (ReadMsgUDPAddrPort/WriteMsgUDPAddrPort). Batch size 1 is legal per the
// Bind contract and keeps the patch seam trivially correct.
type Bind struct {
	mu      sync.Mutex
	opts    SocketOptions
	mark    uint32 // current mark (set before or after Open)
	v4, v6  *net.UDPConn
	port    uint16
	opened  bool
	hook    atomic.Pointer[DatagramHook]
}


// NewBind returns an unopened bind carrying opts.
func NewBind(opts SocketOptions) *Bind {
	return &Bind{opts: opts}
}

// SetDatagramHook installs the reserved-bytes seam. Safe to call at any time;
// nil restores passthrough.
func (b *Bind) SetDatagramHook(h DatagramHook) {
	if h == nil {
		b.hook.Store(nil)
		return
	}
	b.hook.Store(&h)
}

func (b *Bind) loadHook() DatagramHook {
	if p := b.hook.Load(); p != nil {
		return *p
	}
	return nil
}

// ActualPort reports the UDP port the kernel assigned during Open (0 before).
func (b *Bind) ActualPort() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.port
}

// Open implements conn.Bind. It listens on udp4+udp6 (missing family support
// is tolerated like upstream StdNetBind, bind_std.go:159-174) and applies
// SocketOptions plus the current mark to each created socket, apply-or-fail.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.opened {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	// Snapshot under lock; the Control callback runs on this goroutine while
	// b.mu is still held, so it must not touch b again (deadlock otherwise).
	mark := b.mark
	opts := b.opts

	lc := net.ListenConfig{
		Control: func(_ string, _ string, c syscall.RawConn) error {
			return applySocketControl(c, opts, mark)
		},
	}

	var fns []conn.ReceiveFunc
	actual := int(port)
	for _, network := range []string{"udp4", "udp6"} {
		pc, err := lc.ListenPacket(context.Background(), network, ":"+strconv.Itoa(actual))
		if err != nil {
			if isFamilyUnsupported(err) {
				continue // e.g. ipv6 absent: same tolerance as upstream
			}
			b.closeLocked()
			b.mu.Unlock()
			return nil, 0, err
		}
		uc := pc.(*net.UDPConn)
		if la, ok := pc.LocalAddr().(*net.UDPAddr); ok {
			actual = la.Port
		}
		if network == "udp4" {
			b.v4 = uc
			fns = append(fns, b.makeReceive(uc))
		} else {
			b.v6 = uc
			fns = append(fns, b.makeReceive(uc))
		}
	}
	if len(fns) == 0 {
		b.mu.Unlock()
		return nil, 0, syscall.EAFNOSUPPORT
	}
	b.port = uint16(actual)
	b.opened = true
	b.mu.Unlock()
	return fns, b.port, nil
}

func (b *Bind) makeReceive(c *net.UDPConn) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, _, _, addr, err := c.ReadMsgUDPAddrPort(bufs[0], nil)
		if err != nil {
			return 0, err
		}
		if hook := b.loadHook(); hook != nil {
			hook.AdjustInbound(bufs[0][:n])
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: addr}
		return 1, nil
	}
}

// ParseEndpoint implements conn.Bind using upstream's exported endpoint type.
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

// BatchSize implements conn.Bind: one datagram per call.
func (b *Bind) BatchSize() int { return 1 }

// Send implements conn.Bind: patch then write, preserving order.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	endp, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	dst := endp.AddrPort

	b.mu.Lock()
	c := b.v4
	if dst.Addr().Is6() {
		c = b.v6
	}
	b.mu.Unlock()

	if c == nil {
		return syscall.EAFNOSUPPORT
	}
	hook := b.loadHook()
	for i := range bufs {
		if len(bufs[i]) == 0 {
			continue
		}
		if hook != nil {
			hook.PatchOutbound(bufs[i])
		}
		if _, _, err := c.WriteMsgUDPAddrPort(bufs[i], nil, dst); err != nil {
			return err
		}
	}
	return nil
}

// SetMark implements conn.Bind. The mark is stored immediately (covers the
// set-before-open order) and applied to already-open sockets apply-or-fail.
func (b *Bind) SetMark(mark uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.opts.RequireMark && mark == 0 && b.opts.FwMark == 0 {
		return errors.New("transportwg: policy requires SO_MARK but none configured")
	}
	b.mark = mark
	var firstErr error
	for _, c := range []*net.UDPConn{b.v4, b.v6} {
		if c == nil || mark == 0 {
			continue
		}
		if err := setMarkOnConn(c, mark); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close implements conn.Bind; idempotent.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.opened && b.v4 == nil && b.v6 == nil {
		return nil
	}
	return b.closeLocked()
}

func (b *Bind) closeLocked() error {
	var err1, err2 error
	if b.v4 != nil {
		err1 = b.v4.Close()
		b.v4 = nil
	}
	if b.v6 != nil {
		err2 = b.v6.Close()
		b.v6 = nil
	}
	b.opened = false
	if err1 != nil {
		return err1
	}
	return err2
}
