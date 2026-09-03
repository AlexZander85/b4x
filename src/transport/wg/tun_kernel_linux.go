//go:build linux

package transportwg

import "github.com/amnezia-vpn/amneziawg-go/v3/tun"

// newKernelTUN is a thin adapter over upstream tun.CreateTUN
// (tun_linux.go:551). Deliberately logic-free: everything testable lives in
// shared code; this file only bridges the syscall boundary that CI cannot
// cross without --device /dev/net/tun --cap-add NET_ADMIN.
func newKernelTUN(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}
