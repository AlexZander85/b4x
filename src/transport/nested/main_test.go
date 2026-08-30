// PATCH-16 (WG MINOR 11 / B8): goleak verification for the nested suite —
// runtime lifecycles (Start/Stop, assertion loops, pumps, retry chains)
// must leave nothing behind, package-wide.
package nested

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
		// Known upstream (same boundary as the wg package): amneziawg-go
		// device goroutines in rare teardown windows; the e2e races already
		// scope device lifecycle out of -race runs.
		goleak.IgnoreAnyFunction("github.com/amnezia-vpn/amneziawg-go/v3/device.(*Device).RoutineSendHandshakeRetries"),
		goleak.IgnoreAnyFunction("github.com/amnezia-vpn/amneziawg-go/v3/device.(*Device).RoutineReadFromTUN"),
		// gvisor parking boundary: endpoint/processor goroutines of gvisor
		// netstacks park through gvisor sync.Gopark and are only reaped with
		// the whole stack (the vendored netstack exposes no stack-level
		// Close). Our OWN goroutines (runtimes, pumps, assertion loops) park
		// in b4 code and are NOT covered by this ignore — they still fail
		// the run. Documented boundary per the PATCH-16 discipline, not
		// blanket silence.
		goleak.IgnoreAnyFunction("gvisor.dev/gvisor/pkg/sync.Gopark"),
	)
}

// verifyWithSettle replicates goleak.VerifyTestMain with a bounded settle
// window: the leak check is retried until goroutines from passing tests
// quiesce or the window closes (fail-closed: exhaustion still fails).
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
