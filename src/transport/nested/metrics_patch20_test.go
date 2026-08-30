// PATCH-20/E12 acceptance: gate series absent until observed; the inner
// version-mismatch mapping produces its class.
package nested

import (
	"strings"
	"testing"
	"time"

	twg "github.com/daniellavrushin/b4/transport/wg"
)

// TestGateSeriesAbsentUntilObserved (PATCH-20/E12(в)): a fresh Metrics block
// exports NO layer_gate series (no 0.000 false data); after ObserveGate the
// series appears with the real value.
func TestGateSeriesAbsentUntilObserved(t *testing.T) {
	m := &Metrics{}
	for _, s := range m.Snapshot() {
		if s.Name == SeriesLayerGateSeconds {
			t.Fatalf("fresh Metrics exported gate series %+v (false 0.000 data)", s)
		}
	}
	m.ObserveGate("outer", 2*time.Second)
	m.ObserveGate("inner", 1500*time.Millisecond)
	found := map[string]float64{}
	for _, s := range m.Snapshot() {
		if s.Name == SeriesLayerGateSeconds {
			found[s.Labels["layer"]] = s.Value
		}
	}
	if found["outer"] != 2.0 || found["inner"] != 1.5 {
		t.Fatalf("gate series after observation = %v, want outer 2.0 inner 1.5", found)
	}
}

// TestInnerVersionMismatchMapped (PATCH-20/E12(г)): the M+W runtime maps the
// inner WG session's awg-version-mismatch into ClassInnerVersionMismatch.
func TestInnerVersionMismatchMapped(t *testing.T) {
	plane := newFakePlane()
	var mu strings.Builder
	_ = mu
	got := make(chan Event, 4)
	rt, err := NewMasqueAwgRuntime(MasqueAwgConfig{
		Pair:       validPair(),
		Plane:      plane,
		LocalV4:    localV4(),
		InnerIdent: testInnerIdentity(),
		OnEvent:    func(ev Event) { got <- ev },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Stop()

	rt.innerEvent(twg.SessionEvent{Name: "wg_lost", Class: twg.ClassVersionMismatch, Reason: "92b-20kb"})
	select {
	case ev := <-got:
		if ev.Class != ClassInnerVersionMismatch || !strings.HasPrefix(ev.Reason, "inner:") {
			t.Fatalf("mapped event = %+v, want class %s with inner: prefix", ev, ClassInnerVersionMismatch)
		}
	case <-time.After(time.Second):
		t.Fatal("version-mismatch mapping never fired")
	}

	// Non-mismatch events must not produce the nested class.
	rt.innerEvent(twg.SessionEvent{Name: "wg_established"})
	select {
	case ev := <-got:
		t.Fatalf("non-mismatch produced %s", ev.Class)
	case <-time.After(50 * time.Millisecond):
	}
}
