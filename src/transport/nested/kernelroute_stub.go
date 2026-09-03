//go:build !linux

// Non-linux stub: the kernel-route carrier is a router/field-layer mode.
// CI (windows/darwin) exercises the ownership logic through injected fake
// runners; production wiring is linux-only.
package nested

import (
	"context"
	"errors"
)

// ErrIPRouteUnavailable marks the platform gap structurally (fail-closed).
var ErrIPRouteUnavailable = errors.New("nested: iproute2 route runner requires linux")

// IPRouteRunner always fails closed off-linux.
func IPRouteRunner(ctx context.Context, args ...string) (string, error) {
	return "", ErrIPRouteUnavailable
}
