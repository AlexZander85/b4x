package classifier

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/fixtures"
)

func reassemblyTestKey() FlowKey {
	client := ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.70")}
	return NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.70"), 51000, 443, 6)
}

func testReassemblyConfig(clk clock.Clock) TCPReassemblyConfig {
	return TCPReassemblyConfig{
		MaxFlows: 8, MaxBytesPerFlow: 8 * 1024, MaxBytesTotal: 32 * 1024,
		MaxSegments: 16, MaxClientHello: 8 * 1024, Timeout: time.Second, Clock: clk,
	}
}

func TestTCPReassemblyOutOfOrderAndMetadata(t *testing.T) {
	fixture := fixtures.TLSCorpus()[5]
	clk := clock.NewFixed(time.Unix(1000, 0))
	store := NewTCPReassemblyStore(testReassemblyConfig(clk))
	key := reassemblyTestKey()
	store.Start(key, 1000, 7)
	var last TCPReassemblyResult
	for _, segment := range fixture.OutOfOrder {
		last = store.Observe(key, 1000+segment.Seq, segment.Payload, 7)
	}
	if last.Status != ReassemblyComplete || !last.Metadata.Complete || last.Metadata.SNI != fixture.Host || last.Metadata.MaxVersion != fixture.TLSVersion {
		t.Fatalf("out-of-order result = %+v", last)
	}
	if last.BufferedBytes != len(fixture.Record) || store.Bytes() != len(fixture.Record) {
		t.Fatalf("buffer accounting result=%+v storeBytes=%d", last, store.Bytes())
	}
}

func TestTCPReassemblyRetransmissionAndConflictingOverlap(t *testing.T) {
	fixture := fixtures.TLSCorpus()[2]
	clk := clock.NewFixed(time.Unix(1100, 0))
	store := NewTCPReassemblyStore(testReassemblyConfig(clk))
	key := reassemblyTestKey()
	store.Start(key, 2000, 1)
	for _, segment := range fixture.Segments {
		store.Observe(key, 2000+segment.Seq, segment.Payload, 1)
	}
	duplicate := store.Observe(key, 2000+fixture.Segments[0].Seq, fixture.Segments[0].Payload, 1)
	if duplicate.Status != ReassemblyComplete || !duplicate.Duplicate || duplicate.NewBytes != 0 {
		t.Fatalf("duplicate result = %+v", duplicate)
	}
	if store.Stats().Retransmissions == 0 {
		t.Fatal("retransmission was not counted")
	}

	conflictKey := NewFlowKey(reassemblyTestKey().Client, netip.MustParseAddr("192.0.2.71"), netip.MustParseAddr("203.0.113.71"), 51001, 443, 6)
	store.Start(conflictKey, 3000, 1)
	partial := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)[:7]
	store.Observe(conflictKey, 3000, partial, 1)
	conflicting := store.Observe(conflictKey, 3002, []byte{0xff}, 1)
	if conflicting.Status != ReassemblyAborted || conflicting.Reason != ReassemblyAbortConflictingOverlap || store.Len() != 1 {
		t.Fatalf("conflict result=%+v len=%d", conflicting, store.Len())
	}
	if _, ok := store.Lookup(conflictKey); ok {
		t.Fatal("conflicting flow survived abort")
	}
}

func TestTCPReassemblyTimeoutLifecycleAndGenerationAbort(t *testing.T) {
	clk := clock.NewFixed(time.Unix(1200, 0))
	store := NewTCPReassemblyStore(testReassemblyConfig(clk))
	key := reassemblyTestKey()
	store.Observe(key, 4000, []byte{0x16, 0x03, 0x03, 0, 10, 1, 0}, 4)
	clk.Advance(2 * time.Second)
	if removed := store.GC(clk.Now()); removed != 1 || store.Len() != 0 {
		t.Fatalf("timeout GC removed=%d len=%d", removed, store.Len())
	}
	store.Observe(key, 5000, []byte{0x16, 0x03, 0x03, 0, 10, 1, 0}, 4)
	generation := store.Observe(key, 5000, []byte{0x16, 0x03, 0x03, 0, 10, 1, 0}, 5)
	if generation.Status != ReassemblyPartial || store.Len() != 1 || store.Stats().GenerationAborts == 0 {
		t.Fatalf("generation restart result=%+v stats=%+v", generation, store.Stats())
	}
	if result := store.ObserveEvent(key, TCPEventFIN, 5); result.Status != ReassemblyAborted || store.Len() != 0 {
		t.Fatalf("FIN result=%+v len=%d", result, store.Len())
	}
}

func TestTCPReassemblyGlobalBudgetAndFailOpen(t *testing.T) {
	clk := clock.NewFixed(time.Unix(1300, 0))
	cfg := testReassemblyConfig(clk)
	cfg.MaxBytesTotal = 5
	store := NewTCPReassemblyStore(cfg)
	first := reassemblyTestKey()
	second := NewFlowKey(reassemblyTestKey().Client, netip.MustParseAddr("192.0.2.72"), netip.MustParseAddr("203.0.113.72"), 51002, 443, 6)
	if got := store.Observe(first, 6000, []byte{0x16, 0x03, 0x03, 0, 10}, 1); got.Status != ReassemblyPartial {
		t.Fatalf("first budget result=%+v", got)
	}
	if got := store.Observe(second, 7000, []byte("ef"), 1); got.Status != ReassemblyAborted || got.Reason != ReassemblyAbortBudget {
		t.Fatalf("second budget result=%+v", got)
	}
	if store.Bytes() != 5 {
		t.Fatalf("global bytes changed after fail-open rejection: %d", store.Bytes())
	}
}

func FuzzTCPReassemblyNeverPanics(f *testing.F) {
	f.Add(uint32(1000), []byte("hello"), uint32(7))
	f.Fuzz(func(t *testing.T, sequence uint32, payload []byte, generation uint32) {
		clk := clock.NewFixed(time.Unix(1400, 0))
		cfg := testReassemblyConfig(clk)
		cfg.MaxBytesPerFlow = 2048
		cfg.MaxBytesTotal = 4096
		store := NewTCPReassemblyStore(cfg)
		key := reassemblyTestKey()
		store.Observe(key, sequence, payload, uint64(generation))
		store.GC(clk.Now().Add(time.Hour))
	})
}

func BenchmarkTCPReassemblyObserve(b *testing.B) {
	fixture := fixtures.TLSCorpus()[1]
	clk := clock.NewFixed(time.Unix(1500, 0))
	store := NewTCPReassemblyStore(testReassemblyConfig(clk))
	key := reassemblyTestKey()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.Start(key, 8000, 1)
		for _, segment := range fixture.Segments {
			store.Observe(key, 8000+segment.Seq, segment.Payload, 1)
		}
		store.Close(key, ReassemblyAbortManual)
	}
}

func TestTCPReassemblyResultCarriesStableClientHelloIdentity(t *testing.T) {
	store := NewTCPReassemblyStore(DefaultTCPReassemblyConfig())
	key := testFlowKey()
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	first := store.Observe(key, 1000, hello, 42)
	second := store.Observe(key, 1000, hello, 42)
	if first.Status != ReassemblyComplete || first.ClientHelloID == 0 || first.ConfigGen != 42 {
		t.Fatalf("missing completed identity: %+v", first)
	}
	if second.ClientHelloID != first.ClientHelloID {
		t.Fatalf("retransmission changed logical identity: first=%d second=%d", first.ClientHelloID, second.ClientHelloID)
	}
}

func TestTCPReassemblyLogicalClientHelloParityAcrossLayouts(t *testing.T) {
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 3072)
	key := reassemblyTestKey()
	const base = uint32(9000)
	const generation = uint64(73)
	layouts := map[string][]int{
		"one":   {len(hello)},
		"two":   {17, len(hello)},
		"three": {5, 251, len(hello)},
		"five":  {1, 5, 73, 1024, len(hello)},
	}
	var parityID uint64
	for name, cuts := range layouts {
		t.Run(name, func(t *testing.T) {
			store := NewTCPReassemblyStore(testReassemblyConfig(clock.NewFixed(time.Unix(1600, 0))))
			store.Start(key, base, generation)
			start := 0
			var result TCPReassemblyResult
			for _, end := range cuts {
				if end > len(hello) {
					end = len(hello)
				}
				result = store.Observe(key, base+uint32(start), hello[start:end], generation)
				start = end
			}
			if result.Status != ReassemblyComplete || result.Metadata.SNI != "api.youtube.com" || result.ClientHelloID == 0 {
				t.Fatalf("layout result = %+v", result)
			}
			if parityID == 0 {
				parityID = result.ClientHelloID
			} else if result.ClientHelloID != parityID {
				t.Fatalf("layout changed logical identity: got=%d want=%d", result.ClientHelloID, parityID)
			}
		})
	}
}

func TestTCPReassemblyReorderedSecondSegmentSNIAndTrailingRecord(t *testing.T) {
	hello := fixtures.BuildTLSClientHello("video.google.com", 0x0304, false, 1024)
	trailing := []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}
	stream := append(append([]byte(nil), hello...), trailing...)
	key := reassemblyTestKey()
	store := NewTCPReassemblyStore(testReassemblyConfig(clock.NewFixed(time.Unix(1700, 0))))
	store.Start(key, 10000, 81)
	cut := 23 // the clear hostname is not fully present in the first segment
	second := store.Observe(key, 10000+uint32(cut), stream[cut:], 81)
	if second.Status != ReassemblyPartial {
		t.Fatalf("reordered tail should remain partial: %+v", second)
	}
	complete := store.Observe(key, 10000, stream[:cut], 81)
	if complete.Status != ReassemblyComplete || complete.Metadata.SNI != "video.google.com" || !complete.Metadata.Complete {
		t.Fatalf("reordered completion = %+v", complete)
	}
}

func TestLogicalClientHelloIdentitySeparatesClients(t *testing.T) {
	first := reassemblyTestKey()
	secondClient := first.Client
	secondClient.SourceIP = netip.MustParseAddr("192.0.2.71")
	second := NewFlowKey(secondClient, secondClient.SourceIP, first.DstIP, first.SrcPort, first.DstPort, first.Proto)
	firstID := LogicalClientHelloID(first, 12000, 91)
	secondID := LogicalClientHelloID(second, 12000, 91)
	if firstID == 0 || secondID == 0 || firstID == secondID {
		t.Fatalf("client isolation lost: first=%d second=%d", firstID, secondID)
	}
}
