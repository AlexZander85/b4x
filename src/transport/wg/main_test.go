// PATCH-16 (WG MINOR 11 / B8): goleak verification for the whole wg suite.
// Every test in the package inherits the check; a leaked goroutine fails
// the run instead of hiding until a field session wedges.
//
// Ignored goroutines are EXPLICIT and carry their justification — unknown
// leaks are findings, never silence (plan: "неизвестные — отдельные
// findings, НЕ молчать").
package transportwg

import (
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	verifyWithSettle(m,
		// Load tolerance: the three transport suites run concurrently in
		// CI; goroutines from passing tests need a settle window before
		// the leak check (goleak v1.3.0 has no exported Timeout option,
		// default max sleep ~1s flakes under parallel load).
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

// verifyWithSettle replicates goleak.VerifyTestMain with a bounded settle
// window: the leak check is retried until goroutines from passing tests
// quiesce or the window closes (fail-closed: exhaustion still fails the
// run). goleak v1.3.0 has no exported Timeout option, hence this shim.
func verifyWithSettle(m goleak.TestingM, options ...goleak.Option) {
	exitCode := m.Run()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := goleak.Find(options...)
		if err == nil {
			os.Exit(0)
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "goleak: Errors on successful test run: %v\n", err)
			os.Exit(1)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
