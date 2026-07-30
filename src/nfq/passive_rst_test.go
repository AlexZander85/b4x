package nfq

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
)

func passiveRSTTestFlow(clientOctet byte, sport uint16) classifier.FlowKey {
	clientIP := netip.AddrFrom4([4]byte{192, 0, 2, clientOctet})
	serverIP := netip.MustParseAddr("203.0.113.10")
	client := classifier.ClientKey{L3Family: 4, SourceIP: clientIP, SourceMAC: [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, clientOctet}}
	return classifier.NewFlowKey(client, clientIP, serverIP, sport, 443, 6)
}

func passiveRSTTestConfig() config.PassiveRSTRuntimeConfig {
	cfg := config.DefaultClassifierRuntimeConfig.PassiveRST
	cfg.MaxFlows = 8
	cfg.FlowTTLSeconds = 30
	cfg.BaselineSamples = 8
	cfg.BaselineFreshnessSeconds = 10
	cfg.BurstThreshold = 2
	cfg.BurstWindowMS = 1000
	return cfg
}

func clientObservation(flags uint8, seq, ack uint32, window uint16, at time.Time) PassiveRSTPacketObservation {
	return PassiveRSTPacketObservation{Direction: PassiveRSTClientToServer, Family: 4, Flags: flags, Sequence: seq, Acknowledgment: ack, Window: window, VisibilityComplete: true, ObservedAt: at, DeviceScope: "aa:bb:cc:dd:ee:01", SetID: "youtube"}
}

func serverObservation(flags uint8, seq, ack uint32, window uint16, ttl uint8, payload int, at time.Time) PassiveRSTPacketObservation {
	return PassiveRSTPacketObservation{Direction: PassiveRSTServerToClient, Family: 4, Flags: flags, Sequence: seq, Acknowledgment: ack, Window: window, TTLOrHopLimit: ttl, PayloadBytes: payload, VisibilityComplete: true, ObservedAt: at, OptionsKnown: true, OptionsFingerprint: 0x1234, IPID: 100}
}

func establishPassiveRSTFlow(t *testing.T, store *PassiveRSTStore, flow classifier.FlowKey, generation uint64, now time.Time, withPayload bool) {
	t.Helper()
	store.ObserveOutgoing(flow, generation, clientObservation(classifier.TCPFlagSYN, 100, 0, 4096, now))
	if _, tracked := store.ObserveIncoming(flow.Client.SourceIP.String(), "203.0.113.10", flowClientPort(flow), 443, generation,
		serverObservation(classifier.TCPFlagSYN|classifier.TCPFlagACK, 1000, 101, 4096, 52, 0, now.Add(10*time.Millisecond))); !tracked {
		t.Fatal("SYN-ACK did not resolve exact flow")
	}
	store.ObserveOutgoing(flow, generation, clientObservation(classifier.TCPFlagACK, 101, 1001, 2048, now.Add(20*time.Millisecond)))
	for i, ttl := range []uint8{51, 52} {
		payload := 0
		if withPayload && i == 0 {
			payload = 512
		}
		if _, tracked := store.ObserveIncoming(flow.Client.SourceIP.String(), "203.0.113.10", flowClientPort(flow), 443, generation,
			serverObservation(classifier.TCPFlagACK, 1001+uint32(i), 101, 4096, ttl, payload, now.Add(time.Duration(30+i)*time.Millisecond))); !tracked {
			t.Fatal("server observation did not resolve exact flow")
		}
	}
}

func flowClientPort(flow classifier.FlowKey) uint16 {
	if flow.SrcIP == flow.Client.SourceIP {
		return flow.SrcPort
	}
	return flow.DstPort
}

func TestPassiveRSTObservationBuildsStrongAndCorroboratingEvidence(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	clk := clock.NewFixed(now)
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clk)
	flow := passiveRSTTestFlow(1, 51000)
	establishPassiveRSTFlow(t, store, flow, 11, now, false)

	rst := serverObservation(classifier.TCPFlagRST, 9000, 0, 0, 30, 0, now.Add(50*time.Millisecond))
	rst.OptionsFingerprint = 0
	rst.IPID = 10000
	evidence, tracked := store.ObserveIncoming("192.0.2.1", "203.0.113.10", 51000, 443, 11, rst)
	if !tracked || evidence.Decision != PassiveRSTDecisionObserve {
		t.Fatalf("tracked=%v evidence=%+v", tracked, evidence)
	}
	want := map[PassiveRSTSignal]bool{
		PassiveRSTSignalPreServerPayload: true,
		PassiveRSTSignalTTLMismatch:      true,
		PassiveRSTSignalSequenceOutside:  true,
		PassiveRSTSignalOptionsMismatch:  true,
		PassiveRSTSignalMissingACK:       true,
		PassiveRSTSignalIPIDAnomaly:      true,
	}
	for _, signal := range evidence.Signals {
		delete(want, signal.Signal)
	}
	if len(want) != 0 {
		t.Fatalf("missing signals: %v; evidence=%+v", want, evidence.Signals)
	}
	if evidence.Baseline.Quality != PassiveRSTBaselineStable || evidence.Baseline.Center != 52 || evidence.Baseline.Spread != 1 {
		t.Fatalf("baseline=%+v", evidence.Baseline)
	}
	if !evidence.Sequence.Reliable || evidence.Sequence.InWindow {
		t.Fatalf("sequence decision=%+v", evidence.Sequence)
	}
	if evidence.Flow.RSTCount != 1 || evidence.Flow.SuppressionBudget != 2 || evidence.Flow.SetID != "youtube" {
		t.Fatalf("flow snapshot=%+v", evidence.Flow)
	}
}

func TestPassiveRSTLegitimateServerProgressIsObservedWithoutPrePayloadSignal(t *testing.T) {
	now := time.Unix(1100, 0).UTC()
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))
	flow := passiveRSTTestFlow(2, 51001)
	establishPassiveRSTFlow(t, store, flow, 12, now, true)
	rst := serverObservation(classifier.TCPFlagRST|classifier.TCPFlagACK, 1002, 101, 4096, 52, 0, now.Add(60*time.Millisecond))
	evidence, tracked := store.ObserveIncoming("192.0.2.2", "203.0.113.10", 51001, 443, 12, rst)
	if !tracked || !evidence.Flow.ServerPayloadProgress {
		t.Fatalf("evidence=%+v", evidence)
	}
	for _, signal := range evidence.Signals {
		if signal.Signal == PassiveRSTSignalPreServerPayload || signal.Signal == PassiveRSTSignalTTLMismatch || signal.Signal == PassiveRSTSignalSequenceOutside {
			t.Fatalf("legitimate RST received suspicious strong signal: %+v", signal)
		}
	}
}

func TestPassiveRSTWeakStaleAndRouteChangeTTLRemainDiagnostic(t *testing.T) {
	now := time.Unix(1200, 0).UTC()
	cfg := passiveRSTTestConfig()
	clk := clock.NewFixed(now)
	store := NewPassiveRSTStore(cfg, clk)
	flow := passiveRSTTestFlow(3, 51002)
	store.ObserveOutgoing(flow, 13, clientObservation(classifier.TCPFlagSYN, 1, 0, 1000, now))
	_, _ = store.ObserveIncoming("192.0.2.3", "203.0.113.10", 51002, 443, 13, serverObservation(classifier.TCPFlagSYN|classifier.TCPFlagACK, 10, 2, 1000, 52, 0, now))
	rst := serverObservation(classifier.TCPFlagRST|classifier.TCPFlagACK, 10, 2, 1000, 20, 0, now.Add(time.Millisecond))
	evidence, _ := store.ObserveIncoming("192.0.2.3", "203.0.113.10", 51002, 443, 13, rst)
	if evidence.Baseline.Quality != PassiveRSTBaselineWeak || !hasSignalStrength(evidence, PassiveRSTSignalWeakTTLMismatch, PassiveRSTStrengthDiagnostic) {
		t.Fatalf("weak evidence=%+v", evidence)
	}

	clk.Advance(11 * time.Second)
	rst.ObservedAt = clk.Now()
	evidence, _ = store.ObserveIncoming("192.0.2.3", "203.0.113.10", 51002, 443, 13, rst)
	if evidence.Baseline.Quality != PassiveRSTBaselineStale {
		t.Fatalf("stale baseline=%+v", evidence.Baseline)
	}

	flow2 := passiveRSTTestFlow(4, 51003)
	store.ObserveOutgoing(flow2, 13, clientObservation(classifier.TCPFlagSYN, 1, 0, 1000, clk.Now()))
	for i, ttl := range []uint8{32, 52, 64} {
		flags := uint8(classifier.TCPFlagACK)
		if i == 0 {
			flags |= classifier.TCPFlagSYN
		}
		_, _ = store.ObserveIncoming("192.0.2.4", "203.0.113.10", 51003, 443, 13, serverObservation(flags, uint32(10+i), 2, 1000, ttl, 0, clk.Now().Add(time.Duration(i)*time.Millisecond)))
	}
	evidence, _ = store.ObserveIncoming("192.0.2.4", "203.0.113.10", 51003, 443, 13, serverObservation(classifier.TCPFlagRST|classifier.TCPFlagACK, 12, 2, 1000, 10, 0, clk.Now().Add(5*time.Millisecond)))
	if evidence.Baseline.Quality != PassiveRSTBaselineRouteChangeSuspected || hasSignalStrength(evidence, PassiveRSTSignalTTLMismatch, PassiveRSTStrengthStrong) {
		t.Fatalf("route-change evidence=%+v", evidence)
	}
}

func hasSignalStrength(e PassiveRSTEvidence, signal PassiveRSTSignal, strength PassiveRSTSignalStrength) bool {
	for _, got := range e.Signals {
		if got.Signal == signal && got.Strength == strength {
			return true
		}
	}
	return false
}

func TestPassiveRSTBurstExactFlowAndClientIsolation(t *testing.T) {
	now := time.Unix(1300, 0).UTC()
	store := NewPassiveRSTStore(passiveRSTTestConfig(), clock.NewFixed(now))
	flowA := passiveRSTTestFlow(5, 51004)
	flowB := passiveRSTTestFlow(6, 51004)
	establishPassiveRSTFlow(t, store, flowA, 14, now, false)
	establishPassiveRSTFlow(t, store, flowB, 14, now, false)
	rst := serverObservation(classifier.TCPFlagRST|classifier.TCPFlagACK, 1001, 101, 4096, 52, 0, now.Add(100*time.Millisecond))
	_, _ = store.ObserveIncoming("192.0.2.5", "203.0.113.10", 51004, 443, 14, rst)
	rst.ObservedAt = now.Add(200 * time.Millisecond)
	evidenceA, _ := store.ObserveIncoming("192.0.2.5", "203.0.113.10", 51004, 443, 14, rst)
	if !hasSignalStrength(evidenceA, PassiveRSTSignalBurst, PassiveRSTStrengthCorroborating) {
		t.Fatalf("flow A evidence=%+v", evidenceA)
	}
	evidenceB, tracked := store.ObserveIncoming("192.0.2.6", "203.0.113.10", 51004, 443, 14, rst)
	if !tracked {
		t.Fatal("flow B not tracked")
	}
	if hasSignalStrength(evidenceB, PassiveRSTSignalBurst, PassiveRSTStrengthCorroborating) {
		t.Fatalf("cross-client burst leak: %+v", evidenceB)
	}
}

func TestPassiveRSTBoundedEvictionGenerationAndCleanup(t *testing.T) {
	now := time.Unix(1400, 0).UTC()
	cfg := passiveRSTTestConfig()
	cfg.MaxFlows = 2
	cfg.FlowTTLSeconds = 5
	clk := clock.NewFixed(now)
	store := NewPassiveRSTStore(cfg, clk)
	flow1 := passiveRSTTestFlow(7, 51005)
	flow2 := passiveRSTTestFlow(8, 51006)
	flow3 := passiveRSTTestFlow(9, 51007)
	store.ObserveOutgoing(flow1, 15, clientObservation(classifier.TCPFlagSYN, 1, 0, 1, now))
	store.ObserveOutgoing(flow2, 15, clientObservation(classifier.TCPFlagSYN, 1, 0, 1, now))
	store.ObserveOutgoing(flow3, 15, clientObservation(classifier.TCPFlagSYN, 1, 0, 1, now))
	if _, ok := store.Lookup(flow1); ok {
		t.Fatal("oldest flow was not evicted")
	}
	if stats := store.Stats(); stats.Evicted != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	if removed := store.InvalidateGeneration(15); removed != 2 {
		t.Fatalf("generation removed=%d", removed)
	}
	store.ObserveOutgoing(flow1, 16, clientObservation(classifier.TCPFlagSYN, 1, 0, 1, clk.Now()))
	clk.Advance(6 * time.Second)
	if removed := store.GC(clk.Now()); removed != 1 {
		t.Fatalf("GC removed=%d", removed)
	}
	store.ObserveOutgoing(flow1, 17, clientObservation(classifier.TCPFlagSYN, 1, 0, 1, clk.Now()))
	if removed := store.Clear(); removed != 1 {
		t.Fatalf("Clear removed=%d", removed)
	}
}

func TestPassiveRSTOptionsFingerprintIgnoresOptionValues(t *testing.T) {
	first := []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 7, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8}
	second := []byte{2, 4, 0x04, 0x00, 1, 3, 3, 7, 8, 10, 9, 9, 9, 9, 8, 8, 8, 8}
	a, okA, scaleA, scaleKnownA := passiveRSTOptionsFingerprint(first)
	b, okB, scaleB, scaleKnownB := passiveRSTOptionsFingerprint(second)
	if !okA || !okB || a != b || !scaleKnownA || !scaleKnownB || scaleA != 7 || scaleB != 7 {
		t.Fatalf("a=%x b=%x ok=%t/%t scale=%d/%d", a, b, okA, okB, scaleA, scaleB)
	}
}
