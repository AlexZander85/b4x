//go:build !linux

package transportwg

import (
	"fmt"
	"runtime"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// newKernelTUN stub: the kernel data plane exists only on linux. The error
// names the rebuild requirement explicitly (sing-box stub pattern) so a
// misconfigured production build fails loudly instead of silently.
func newKernelTUN(_ string, _ int) (tun.Device, error) {
	return nil, fmt.Errorf("kernel TUN requires GOOS=linux; this binary was built for %s without kernel transport support", runtime.GOOS())
}
