package silentpath

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
)

func progressKey() classifier.FlowKey {
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.4")}
	return classifier.NewFlowKey(client, client.SourceIP, netip.MustParseAddr("198.51.100.4"), 40000, 443, 6)
}
func progressStore() (*ProgressStore, *clock.FixedClock) {
	c := clock.NewFixed(time.Unix(1000, 0))
	return NewProgressStore(ProgressConfig{MaxFlows: 2, MaxRangesPerFlow: 4, IdleTimeout: time.Second, Clock: c}), c
}
func observe(store *ProgressStore, direction Direction, seq uint32, bytes int) ProgressResult {
	return store.Observe(ProgressObservation{FlowKey: progressKey(), Direction: direction, Sequence: seq, Bytes: bytes, ConfigGen: 7})
}

func TestUniqueProgressIgnoresDuplicateAndOverlap(t *testing.T) {
	s, _ := progressStore()
	if got := observe(s, DirectionInbound, 100, 10); got.NewBytes != 10 {
		t.Fatalf("first=%+v", got)
	}
	if got := observe(s, DirectionInbound, 100, 10); !got.Duplicate || got.NewBytes != 0 {
		t.Fatalf("duplicate=%+v", got)
	}
	if got := observe(s, DirectionInbound, 105, 10); got.NewBytes != 5 || got.State.UniqueInboundBytes != 15 {
		t.Fatalf("overlap=%+v", got)
	}
}

func TestUniqueProgressOutOfOrderAndWrap(t *testing.T) {
	s, _ := progressStore()
	observe(s, DirectionOutbound, 0xfffffff8, 8)
	if got := observe(s, DirectionOutbound, 0, 8); got.NewBytes != 8 || got.State.UniqueOutboundBytes != 16 {
		t.Fatalf("wrap=%+v", got)
	}
	s, _ = progressStore()
	observe(s, DirectionInbound, 110, 10)
	if got := observe(s, DirectionInbound, 100, 10); got.NewBytes != 10 || got.State.UniqueInboundBytes != 20 {
		t.Fatalf("out-of-order=%+v", got)
	}
}

func TestGSOAndMSSHaveEqualUniqueTotals(t *testing.T) {
	gso, _ := progressStore()
	mss, _ := progressStore()
	observe(gso, DirectionInbound, 1000, 3000)
	for i := 0; i < 3; i++ {
		observe(mss, DirectionInbound, uint32(1000+i*1000), 1000)
	}
	if a, b := observe(gso, DirectionInbound, 4000, 1).State.UniqueInboundBytes, observe(mss, DirectionInbound, 4000, 1).State.UniqueInboundBytes; a != b || a != 3001 {
		t.Fatalf("gso=%d mss=%d", a, b)
	}
}

func TestProgressLifecycleAndBounds(t *testing.T) {
	s, c := progressStore()
	observe(s, DirectionInbound, 1, 1)
	if !s.Close(progressKey()) || s.Len() != 0 {
		t.Fatal("close did not remove flow")
	}
	observe(s, DirectionInbound, 1, 1)
	if s.InvalidateGeneration(7) != 1 || s.Len() != 0 {
		t.Fatal("generation invalidation failed")
	}
	observe(s, DirectionInbound, 1, 1)
	c.Advance(2 * time.Second)
	if s.GC(c.Now()) != 1 {
		t.Fatal("timeout did not remove flow")
	}
	for i := 0; i < 5; i++ {
		if got := observe(s, DirectionInbound, uint32(i*10), 1); i == 4 && !got.TrackingStopped {
			t.Fatalf("range bound=%+v", got)
		}
	}
}
