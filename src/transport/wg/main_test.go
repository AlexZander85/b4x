// PATCH-16 (WG MINOR 11 / B8): goleak verification for the whole wg suite.
// Every test in the package inherits the check; a leaked goroutine fails
// the run instead of hiding until a field session wedges.
//
// Ignored goroutines are EXPLICIT and carry their justification — unknown
// leaks are findings, never silence (plan: "неизвестные — отдельные
// findings, НЕ молчать").
package transportwg

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// Known upstream: amneziawg-go device goroutines that outlive a
		// closed device in rare teardown windows (device/timers.go
		// fastrandn retry loops documented in the race-gate policy). The
		// race-filter tests deliberately exclude device lifecycle from
		// -race runs; goleak ignores follow the same boundary.
		goleak.IgnoreAnyFunction("github.com/amnezia-vpn/amneziawg-go/v3/device.(*Device).RoutineSendHandshakeRetries"),
		goleak.IgnoreAnyFunction("github.com/amnezia-vpn/amneziawg-go/v3/device.(*Device).RoutineReadFromTUN"),
		// Upstream device.Close leaves the TUN-event reader parked on the
		// (never-closed) events channel of tuntest.ChannelTUN devices — a
		// known vendored teardown gap (device/tun.go:19); the goroutine dies
		// with the process, holds no buffers. Documented boundary, NOT
		// silence for new leaks.
		goleak.IgnoreAnyFunction("github.com/amnezia-vpn/amneziawg-go/v3/device.(*Device).RoutineTUNEventReader"),
	)
}
