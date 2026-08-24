// Backend-B loopback carrier (design §7, gool/wireproxy lineage): a
// single-session UDP relay that exposes the INNER edge on 127.0.0.1 so the
// inner WG instance dials loopback while its datagrams physically travel
// encrypted inside the OUTER tunnel's netstack.
//
// Wire path:
//
//	innerWG.bind.Send -> 127.0.0.1:<port>   (host loopback)
//	forwarder         -> gonet UDP conn connected to <innerEdge>
//	                   -> gVisor emits IP/UDP into the outer TUN device
//	                   -> outer WG encrypts toward the outer edge
//	reply             <- outer WG decrypts <- netstack delivers to the
//	                     connected gonet conn <- relayed back to the client
//
// Single-client semantics ("last writer wins") follow the Aether gool
// reference (односессионный форвардер, последний клиент побеждает). The
// dial seam is injectable: unit tests drive the whole relay over plain
// host sockets, production passes nsUDPDial(outerTunnel.Netstack).
package transportwg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// DefaultForwarderHost is the only legal bind host for the Backend-B
// carrier; anything else would widen the inner blast radius.
const DefaultForwarderHost = "127.0.0.1"

// LoopbackForwarder relays UDP between one host-loopback client and the
// inner edge through an injected dial (netstack in production).
type LoopbackForwarder struct {
	dial       dialUDPFunc
	innerEdge  netip.AddrPort
	listenAddr string

	mu        sync.Mutex
	client    netip.AddrPort // last writer wins
	host      *net.UDPConn
	up        udpConn
	closeOnce sync.Once
	started   bool
	wg        sync.WaitGroup
	done      chan struct{}
}

// NewLoopbackForwarder builds a forwarder toward innerEdge. dial is the
// upstream socket factory (nsUDPDial of the OUTER tunnel's netstack).
func NewLoopbackForwarder(dial dialUDPFunc, innerEdge netip.AddrPort) (*LoopbackForwarder, error) {
	if dial == nil {
		return nil, errors.New("transportwg: forwarder requires a dial function")
	}
	if !innerEdge.IsValid() || innerEdge.Port() == 0 {
		return nil, fmt.Errorf("transportwg: forwarder invalid inner edge %v", innerEdge)
	}
	return &LoopbackForwarder{
		dial:       dial,
		innerEdge:  innerEdge,
		listenAddr: net.JoinHostPort(DefaultForwarderHost, "0"),
		done:       make(chan struct{}),
	}, nil
}

// Start binds the loopback listener, connects the upstream socket and
// launches both copy directions. Returns the bound client address
// (127.0.0.1:<ephemeral> unless configured otherwise by tests).
func (f *LoopbackForwarder) Start(ctx context.Context) (netip.AddrPort, error) {
	f.mu.Lock()
	if f.started {
		f.mu.Unlock()
		return netip.AddrPort{}, errors.New("transportwg: forwarder already started")
	}
	up, err := f.dial(ctx, "udp", f.innerEdge.String())
	if err != nil {
		f.mu.Unlock()
		return netip.AddrPort{}, fmt.Errorf("transportwg: forwarder upstream dial: %w", err)
	}
	lc := &net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", f.listenAddr)
	if err != nil {
		_ = up.Close()
		f.mu.Unlock()
		return netip.AddrPort{}, fmt.Errorf("transportwg: forwarder listen: %w", err)
	}
	host, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		_ = up.Close()
		f.mu.Unlock()
		return netip.AddrPort{}, errors.New("transportwg: forwarder listen is not UDP")
	}
	f.up = up
	f.host = host
	f.started = true
	f.mu.Unlock()

	f.wg.Add(2)
	go f.pumpClientToEdge(host, up)
	go f.pumpEdgeToClient(host, up)

	local, err := net.ResolveUDPAddr("udp", host.LocalAddr().String())
	if err != nil {
		_ = f.Close()
		return netip.AddrPort{}, fmt.Errorf("transportwg: forwarder local addr: %w", err)
	}
	ip, _ := netip.AddrFromSlice(local.IP)
	return netip.AddrPortFrom(ip.Unmap(), uint16(local.Port)), nil
}

// Addr reports the bound client address (zero before Start).
func (f *LoopbackForwarder) Addr() netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.host == nil {
		return netip.AddrPort{}
	}
	local, err := net.ResolveUDPAddr("udp", f.host.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}
	}
	ip, _ := netip.AddrFromSlice(local.IP)
	return netip.AddrPortFrom(ip.Unmap(), uint16(local.Port))
}

// Close stops both pumps and releases sockets. Idempotent; safe from any
// goroutine.
func (f *LoopbackForwarder) Close() error {
	var err error
	f.closeOnce.Do(func() {
		close(f.done)
		f.mu.Lock()
		host, up := f.host, f.up
		f.mu.Unlock()
		if host != nil {
			err = host.Close() // unblocks pumpClientToEdge
		}
		if up != nil {
			_ = up.Close() // unblocks pumpEdgeToClient
		}
	})
	return err
}

// Wait blocks until both pumps exited (test/join helper).
func (f *LoopbackForwarder) Wait() { f.wg.Wait() }

func (f *LoopbackForwarder) stopped() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

// pumpClientToEdge: host loopback -> upstream (outer tunnel).
func (f *LoopbackForwarder) pumpClientToEdge(host *net.UDPConn, up udpConn) {
	defer f.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := host.ReadFromUDP(buf)
		if err != nil {
			if !f.stopped() {
				_ = f.Close() // socket died outside teardown: tear down cleanly
			}
			return
		}
		if f.stopped() {
			return
		}
		if ap, ok := udpAddrPort(from); ok {
			f.mu.Lock()
			f.client = ap // last writer wins
			f.mu.Unlock()
		}
		if _, err := up.Write(buf[:n]); err != nil && !f.stopped() {
			_ = f.Close()
			return
		}
	}
}

// pumpEdgeToClient: upstream (inner edge replies through the outer
// tunnel) -> the recorded loopback client.
func (f *LoopbackForwarder) pumpEdgeToClient(host *net.UDPConn, up udpConn) {
	defer f.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := up.Read(buf)
		if err != nil {
			if !f.stopped() {
				_ = f.Close()
			}
			return
		}
		if f.stopped() {
			return
		}
		f.mu.Lock()
		client := f.client
		f.mu.Unlock()
		if !client.IsValid() {
			continue // no client yet: drop (single-session semantics)
		}
		if _, err := host.WriteToUDP(buf[:n], udpAddrPortOf(client)); err != nil && !f.stopped() {
			_ = f.Close()
			return
		}
	}
}

func udpAddrPort(a *net.UDPAddr) (netip.AddrPort, bool) {
	if a == nil || a.IP == nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)), true
}

func udpAddrPortOf(ap netip.AddrPort) *net.UDPAddr {
	ip := ap.Addr().As4()
	return &net.UDPAddr{IP: ip[:], Port: int(ap.Port())}
}
