//go:build linux

// Production RouteRunner: iproute2 exec. House style follows src/tun/route.go
// (shell-out, not netlink) so the carrier behaves identically on busybox and
// full iproute2 routers.
package nested

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// IPRouteRunner shells out to `ip <args...>` with a bounded lifetime.
func IPRouteRunner(ctx context.Context, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ip", args...)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			return string(out), fmt.Errorf("ip %s: %w", strings.Join(args, " "), err)
		}
		return string(out), fmt.Errorf("ip %s: %s", strings.Join(args, " "), msg)
	}
	return string(out), nil
}
