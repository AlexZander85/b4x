package transportwg

import (
	"testing"

	quici1 "github.com/daniellavrushin/b4/transport/quici1"
)

// TestFillBootstrapCover pins the b4x-b7n fill contract: a runtime-I1 profile
// gets a real (RFC 9000-sized) QUIC Initial repeated across every I-slot; any
// other profile and a failed render are honest no-ops.
func TestFillBootstrapCover(t *testing.T) {
	base := Profile{JunkCount: 4, JunkMin: 40, JunkMax: 70}
	unchanged := FillBootstrapCover(base, false, "ozon.ru")
	if unchanged.JunkCount != base.JunkCount || unchanged.InitPacket[0] != "" {
		t.Fatalf("non-runtime-I1 profile mutated: %+v", unchanged)
	}
	if got := FillBootstrapCover(Profile{}, true, ""); got.InitPacket[0] != "" {
		t.Fatal("empty cover SNI must be an honest no-op, not a broken chain")
	}

	got := FillBootstrapCover(Profile{}, true, "ozon.ru")
	if err := got.Validate(); err != nil {
		t.Fatalf("cover profile invalid: %v", err)
	}
	var first string
	for i := 0; i < BootstrapCoverSlots; i++ {
		if got.InitPacket[i] == "" {
			t.Fatalf("I%d slot empty — the cover would never ship", i+1)
		}
		if i == 0 {
			first = got.InitPacket[i]
			continue
		}
		if got.InitPacket[i] != first {
			t.Fatalf("I%d differs from I1 — the repeats pattern is broken", i+1)
		}
	}
	if n := quici1.InitialSize(first); n < 1200 {
		t.Fatalf("cover Initial is %d bytes, want the RFC 9000 sec 14 floor (>=1200)", n)
	}
}
