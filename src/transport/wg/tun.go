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
	"errors"
	"fmt"
	"net/netip"

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
// ModeNetstack).
type Tunnel struct {
	Device   tun.Device
	Netstack *netstack.Net
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
		return &Tunnel{Device: dev}, nil
	default:
		return nil, fmt.Errorf("transportwg: unknown TUN mode %d", cfg.Mode)
	}
}
