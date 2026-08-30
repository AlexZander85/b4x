// PATCH-16 (WG MINOR 11 / B8): goleak verification for the nested suite —
// runtime lifecycles (Start/Stop, assertion loops, pumps, retry chains)
// must leave nothing behind, package-wide.
package nested

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
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
