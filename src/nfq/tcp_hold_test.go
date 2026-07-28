package nfq

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fixtures"
)

func holdTestKey(client, server string, clientPort uint16) classifier.FlowKey {
	clientAddr := netip.MustParseAddr(client)
	clientKey := classifier.ClientKey{L3Family: 4, SourceIP: clientAddr}
	return classifier.NewFlowKey(clientKey, clientAddr, netip.MustParseAddr(server), clientPort, 443, 6)
}

func TestTCPHoldStoreBoundsTimeoutAndRelease(t *testing.T) {
	clk := clock.NewFixed(time.Unix(2000, 0))
	store := NewTCPHoldStore(TCPHoldConfig{MaxFlows: 2, MaxPacketsPerFlow: 2, MaxBytesTotal: 10, Timeout: time.Second, Clock: clk})
	key := holdTestKey("192.0.2.90", "203.0.113.90", 52000)
	if !store.Hold(key, 1, nil, 1, 4) || !store.Hold(key, 1, nil, 2, 3) {
		t.Fatal("bounded hold rejected packets before limits")
	}
	if store.Len() != 1 || store.Bytes() != 7 {
		t.Fatalf("hold accounting len=%d bytes=%d", store.Len(), store.Bytes())
	}
	if store.Hold(key, 1, nil, 3, 1) || store.Len() != 0 || store.Bytes() != 0 {
		t.Fatalf("per-flow pressure did not fail-open: len=%d bytes=%d", store.Len(), store.Bytes())
	}
	if store.Stats().PressureReleases != 2 {
		t.Fatalf("pressure stats = %+v", store.Stats())
	}
	if !store.Hold(key, 1, nil, 4, 5) {
		t.Fatal("hold after pressure release failed")
	}
	clk.Advance(2 * time.Second)
	if removed := store.GC(clk.Now()); removed != 1 || store.Len() != 0 || store.Bytes() != 0 {
		t.Fatalf("timeout release removed=%d len=%d bytes=%d", removed, store.Len(), store.Bytes())
	}
	if store.Stats().TimeoutReleases != 1 {
		t.Fatalf("timeout stats = %+v", store.Stats())
	}
}

func TestTCPHoldStoreGenerationAndFlowEviction(t *testing.T) {
	store := NewTCPHoldStore(TCPHoldConfig{MaxFlows: 1, MaxPacketsPerFlow: 4, MaxBytesTotal: 100, Timeout: time.Minute, Clock: clock.NewFixed(time.Unix(2100, 0))})
	first := holdTestKey("192.0.2.91", "203.0.113.91", 52001)
	second := holdTestKey("192.0.2.92", "203.0.113.92", 52002)
	if !store.Hold(first, 7, nil, 1, 2) || !store.Hold(second, 7, nil, 2, 2) || store.Len() != 1 {
		t.Fatalf("flow eviction failed len=%d stats=%+v", store.Len(), store.Stats())
	}
	if !store.Hold(second, 8, nil, 3, 3) || store.Bytes() != 3 || store.Stats().GenerationReleases != 1 {
		t.Fatalf("generation rollover failed bytes=%d stats=%+v", store.Bytes(), store.Stats())
	}
	if store.Release(second, "fin") != 1 || store.Len() != 0 {
		t.Fatalf("explicit release failed len=%d", store.Len())
	}
}

func TestAutoHoldReplayHoldsOnlyIncompleteClientHello(t *testing.T) {
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Flags.TCPReassemblyMode = config.ReassemblyObserve
	cfg.System.Classifier.Flags.TCPHoldReplayMode = config.HoldReplayAuto
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 93), dst: net.IPv4(203, 0, 113, 93), srcMac: ""}
	fixture := fixtures.TLSCorpus()[2]
	first := fixture.Segments[0]
	result := worker.observeTCPReassembly(&cfg, pkt, 1000+first.Seq, 52003, 443, classifier.TCPFlagACK, first.Payload)
	key, ok := tcpFlowKeyForPacket(pkt, 52003, 443)
	if !ok || result.Status != classifier.ReassemblyPartial || result.Metadata.NeedBytes == 0 {
		t.Fatalf("incomplete reassembly result=%+v key=%v", result, ok)
	}
	metadata := worker.tcpTLSDecisionMetadata(&cfg, pkt, 52003, 443, first.Payload)
	held, failOpen := worker.maybeHoldTCPPacket(&cfg, pkt, key, dnsHintConfigGeneration(&cfg), 443, first.Payload, classifier.TCPFlagACK, metadata, result, false, nil, 1)
	if !held || failOpen || worker.tcpHold.Len() != 1 {
		t.Fatalf("auto hold result held=%v failOpen=%v len=%d", held, failOpen, worker.tcpHold.Len())
	}

	second := fixture.Segments[1]
	complete := worker.observeTCPReassembly(&cfg, pkt, 1000+second.Seq, 52003, 443, classifier.TCPFlagACK, second.Payload)
	if complete.Status != classifier.ReassemblyComplete {
		t.Fatalf("completion result=%+v", complete)
	}
	worker.tcpHold.Release(key, complete.Reason)
	if worker.tcpHold.Len() != 0 || worker.tcpHold.Bytes() != 0 {
		t.Fatalf("completed flow remained held len=%d bytes=%d", worker.tcpHold.Len(), worker.tcpHold.Bytes())
	}
}

func TestHoldReplayObserveAndServerProgressRelease(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Classifier.Flags.TCPReassemblyMode = config.ReassemblyObserve
	cfg.System.Classifier.Flags.TCPHoldReplayMode = config.HoldReplayObserve
	worker := NewWorkerWithQueue(&cfg, 0)
	pkt := &pktInfo{src: net.IPv4(192, 0, 2, 94), dst: net.IPv4(203, 0, 113, 94)}
	fixture := fixtures.TLSCorpus()[2].Segments[0]
	result := worker.observeTCPReassembly(&cfg, pkt, 2000+fixture.Seq, 52004, 443, classifier.TCPFlagACK, fixture.Payload)
	key, _ := tcpFlowKeyForPacket(pkt, 52004, 443)
	metadata := worker.tcpTLSDecisionMetadata(&cfg, pkt, 52004, 443, fixture.Payload)
	held, failOpen := worker.maybeHoldTCPPacket(&cfg, pkt, key, 0, 443, fixture.Payload, classifier.TCPFlagACK, metadata, result, false, nil, 1)
	if held || failOpen || worker.tcpHold.Len() != 0 {
		t.Fatalf("observe mode held packet: held=%v failOpen=%v len=%d", held, failOpen, worker.tcpHold.Len())
	}

	cfg.System.Classifier.Flags.TCPHoldReplayMode = config.HoldReplayAuto
	if !worker.tcpHold.Hold(key, 1, nil, 2, 3) {
		t.Fatal("setup hold failed")
	}
	incoming := &pktInfo{src: net.IPv4(203, 0, 113, 94), dst: net.IPv4(192, 0, 2, 94)}
	if released := worker.releaseTCPHoldOnServerProgress(incoming, 443, 52004); released != 1 || worker.tcpHold.Len() != 0 {
		t.Fatalf("server progress release=%d len=%d", released, worker.tcpHold.Len())
	}
}

func FuzzTCPHoldStoreNeverPanics(f *testing.F) {
	f.Add(uint64(1), uint64(32), uint64(7))
	f.Fuzz(func(t *testing.T, packetID, bytes, generation uint64) {
		store := NewTCPHoldStore(TCPHoldConfig{MaxFlows: 4, MaxPacketsPerFlow: 4, MaxBytesTotal: 256, Timeout: time.Second, Clock: clock.NewFixed(time.Unix(2200, 0))})
		key := holdTestKey("192.0.2.95", "203.0.113.95", uint16(packetID))
		store.Hold(key, generation, nil, uint32(packetID), int(bytes%128))
		store.Release(key, "fuzz")
		store.GC(time.Unix(2202, 0))
	})
}

func BenchmarkTCPHoldStoreHoldRelease(b *testing.B) {
	store := NewTCPHoldStore(TCPHoldConfig{MaxFlows: 64, MaxPacketsPerFlow: 8, MaxBytesTotal: 64 * 1024, Timeout: time.Second, Clock: clock.NewFixed(time.Unix(2300, 0))})
	key := holdTestKey("192.0.2.96", "203.0.113.96", 52006)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.Hold(key, 1, nil, uint32(i), 1200)
		store.Release(key, "complete")
	}
}
