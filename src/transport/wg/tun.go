// TUN factory for the two data-plane modes of the design (§1) plus the
// in-process fake used by tests:
//
//   - ModeNetstack: gVisor userspace netstack (netstack.CreateNetTUN, the
//     outline/dialer.go embed pattern). Pure Go; exercised by CI.
//
//   - ModeKernel: /dev/net/tun via upstream tun.CreateTUN — the scoped-PBR
//     router path. Compile-gated on GOOS=linux; runtime requires the device
//     node and CAP_NET_ADMIN, so it is NOT part of default CI. Manual
//     privileged gate before any field session:
//
//     docker run --rm --device /dev/net/tun --cap-add NET_ADMIN ... \
//     go test ./transport/wg/ -run TestKernelTUNOpen -count=1
//
//     The kernel backend is a thin adapter over upstream CreateTUN so all
//     logic under test lives in the shared, tested code paths.
package transportwg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// TUNMode selects the data-plane mode.
type TUNMode int

const (
	// ModeNetstack is the gVisor userspace netstack device.
	ModeNetstack TUNMode = iota
	// ModeKernel is the kernel /dev/net/tun device (linux only).
	ModeKernel
)

// Design MTUs (§7): outer 1280, inner 1200. DefaultMTU applies to new tunnels.
const (
	DefaultMTU      = 1280
	DefaultInnerMTU = 1200
)

// Tunnel bundles the device handle with its netstack accessor (nil unless
// ModeNetstack). For raw-TUN modes the trust gate needs the two directions
// of the TUN explicitly:
//
//   - Inject feeds an outbound packet INTO the tunnel (kernel: /dev fd
//     write; channel test backend: chan send);
//   - Capture awaits one inbound packet the device delivers to the local
//     stack (kernel: /dev fd read; channel test backend: chan receive).
//
// Netstack mode leaves both nil and uses its own sockets instead.
type Tunnel struct {
	Device   tun.Device
	Netstack *netstack.Net
	Inject   func([]byte) error
	Capture  func(ctx context.Context) ([]byte, error)
}

// TunnelConfig describes a new tunnel device.
type TunnelConfig struct {
	Mode          TUNMode
	Addresses     []netip.Addr // assigned WG addresses (netstack mode)
	DNS           []netip.Addr // resolver inside the netstack
	MTU           int          // 0 -> DefaultMTU
	InterfaceName string       // kernel mode hint; empty = kernel picks
}

// ErrKernelTUNUnavailable is returned by the non-linux stub and by linux
// runs where /dev/net/tun cannot be opened (missing privileges).
var ErrKernelTUNUnavailable = errors.New("transportwg: kernel TUN unavailable")

// NewTunnel creates the requested device.
func NewTunnel(cfg TunnelConfig) (*Tunnel, error) {
	if cfg.MTU <= 0 {
		cfg.MTU = DefaultMTU
	}
	switch cfg.Mode {
	case ModeNetstack:
		if len(cfg.Addresses) == 0 {
			return nil, errors.New("transportwg: netstack mode requires at least one assigned address")
		}
		dev, ns, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
		if err != nil {
			return nil, fmt.Errorf("transportwg: create netstack TUN: %w", err)
		}
		return &Tunnel{Device: dev, Netstack: ns}, nil
	case ModeKernel:
		dev, err := newKernelTUN(cfg.InterfaceName, cfg.MTU)
		if err != nil {
			return nil, fmt.Errorf("transportwg: %w: %v", ErrKernelTUNUnavailable, err)
		}
		f := dev.File()
		inject := func(b []byte) error {
			// Bounded write: a full kernel queue must not wedge the session
			// lifecycle; fd close during teardown unblocks the helper.
			errc := make(chan error, 1)
			go func() {
				_, werr := f.Write(b)
				errc <- werr
			}()
			select {
			case err := <-errc:
				return err
			case <-time.After(3 * time.Second):
				return errors.New("transportwg: tun inject timeout")
			}
		}
		capture := func(ctx context.Context) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			pkt := make([]byte, 65535)
			// Blocking read: unblocks with an error when teardown closes the
			// device fd; ctx cancellation is honored by the session owning
			// the teardown ordering.
			n, err := f.Read(pkt)
			if err != nil {
				return nil, err
			}
			return pkt[:n], nil
		}
		return &Tunnel{Device: dev, Inject: inject, Capture: capture}, nil
	default:
		return nil, fmt.Errorf("transportwg: unknown TUN mode %d", cfg.Mode)
	}
}
