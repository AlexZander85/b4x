package diagnostics

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
)

func inboxClient(last byte) classifier.ClientKey {
	return classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2." + string(rune('0'+last))), SourceMAC: [6]byte{0x02, 0, 0, 0, 0, last}}
}

func validFailureObservation(client classifier.ClientKey, signal FailureSignal, now time.Time) FailureObservation {
	return FailureObservation{
		Signal:          signal,
		Client:          client,
		DestinationIP:   netip.MustParseAddr("203.0.113.10"),
		DestinationPort: 443,
		Protocol:        6,
		ObservedAt:      now,
		Reason:          "test failure",
	}
}

func TestFailureInboxSeparatesClientsAndUpdatesScopedEvidence(t *testing.T) {
	fixed := clock.NewFixed(time.Unix(100, 0))
	inbox := NewFailureInbox(InboxConfig{Retention: time.Minute}, fixed)
	clientA := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.21"), SourceMAC: [6]byte{0x02, 1, 2, 3, 4, 5}}
	clientB := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.22"), SourceMAC: [6]byte{0x02, 1, 2, 3, 6}}
	now := fixed.Now()
	if _, err := inbox.Observe(validFailureObservation(clientA, SignalConntrackUnreplied, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Observe(validFailureObservation(clientB, SignalConntrackUnreplied, now)); err != nil {
		t.Fatal(err)
	}
	evidence := classifier.Evidence{
		Source:          classifier.EvidenceDNSAnswer,
		Client:          clientA,
		DestinationIP:   netip.MustParseAddr("203.0.113.10"),
		DestinationPort: 443,
		L4Proto:         6,
		Domain:          "api.youtube.example",
		SetID:           "private-youtube-set",
		Confidence:      89,
		ExpiresAt:       now.Add(20 * time.Second),
	}
	if !inbox.UpdateEvidence(clientA, evidence.DestinationIP, 443, 6, []classifier.Evidence{evidence}) {
		t.Fatal("DNS evidence was not attached to existing candidate")
	}
	quic := evidence
	quic.Source = classifier.EvidenceQUICSNI
	quic.Domain = "video.google.example"
	if !inbox.UpdateEvidence(clientA, evidence.DestinationIP, 443, 6, []classifier.Evidence{quic}) {
		t.Fatal("QUIC evidence was not attached to existing candidate")
	}
	list := inbox.List(0)
	if len(list) != 2 {
		t.Fatalf("same destination candidates were merged across clients: %d", len(list))
	}
	for _, candidate := range list {
		if candidate.Client == clientA {
			if len(candidate.DNSCandidates) != 1 || len(candidate.QUICCandidates) != 1 {
				t.Fatalf("source-scoped DNS/QUIC evidence missing: %+v", candidate)
			}
			if strings.Contains(string(mustJSON(candidate)), "private-youtube-set") || strings.Contains(string(mustJSON(candidate)), "api.youtube.example") {
				t.Fatal("clear DNS/set identifier leaked from candidate export")
			}
		} else if candidate.Client == clientB && len(candidate.DNSCandidates) != 0 {
			t.Fatal("client A evidence crossed into client B")
		}
	}
}

func TestFailureInboxSynSentAgingAndAbsoluteExpiry(t *testing.T) {
	fixed := clock.NewFixed(time.Unix(200, 0))
	inbox := NewFailureInbox(InboxConfig{Retention: 10 * time.Second, MinSynSentAge: 3 * time.Second}, fixed)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.31")}
	firstSeen := fixed.Now()
	observation := validFailureObservation(client, SignalConntrackSynSent, fixed.Now())
	observation.FirstSeen = firstSeen
	if _, err := inbox.Observe(observation); !errors.Is(err, ErrFailureTooFresh) {
		t.Fatalf("fresh SYN_SENT accepted: %v", err)
	}
	fixed.Advance(3 * time.Second)
	observation.ObservedAt = fixed.Now()
	candidate, err := inbox.Observe(observation)
	if err != nil {
		t.Fatal(err)
	}
	expires := candidate.ExpiresAt
	fixed.Advance(2 * time.Second)
	observation.ObservedAt = fixed.Now()
	updated, err := inbox.Observe(observation)
	if err != nil || !updated.ExpiresAt.Equal(expires) {
		t.Fatalf("expiry became sliding: before=%v after=%v err=%v", expires, updated.ExpiresAt, err)
	}
	fixed.Advance(6 * time.Second)
	if inbox.Len() != 0 {
		t.Fatal("expired SYN_SENT candidate was retained")
	}
}

func TestFailureInboxOffloadRequiresFreshCounters(t *testing.T) {
	fixed := clock.NewFixed(time.Unix(300, 0))
	inbox := NewFailureInbox(InboxConfig{}, fixed)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.41")}
	report := capture.OffloadReport{FlowOffloadBypassSuspected: true, Reasons: []string{"queue counters did not advance"}}
	if candidate, err := inbox.ObserveOffload(OffloadObservation{Client: client, DestinationIP: netip.MustParseAddr("203.0.113.11"), DestinationPort: 443, Protocol: 6, Report: report, ObservedAt: fixed.Now(), CounterSampleFresh: false}); err != nil || candidate != nil {
		t.Fatalf("stale offload observation created candidate=%+v err=%v", candidate, err)
	}
	if inbox.Len() != 0 {
		t.Fatal("stale offload counters entered inbox")
	}
	candidate, err := inbox.ObserveOffload(OffloadObservation{Client: client, DestinationIP: netip.MustParseAddr("203.0.113.11"), DestinationPort: 443, Protocol: 6, Report: report, ObservedAt: fixed.Now(), CounterSampleFresh: true})
	if err != nil || candidate == nil || candidate.SuggestedAction != ActionPCAP {
		t.Fatalf("fresh offload suspicion was not recorded safely: candidate=%+v err=%v", candidate, err)
	}
}

func TestFailureInboxBoundedActionsAndEviction(t *testing.T) {
	fixed := clock.NewFixed(time.Unix(400, 0))
	inbox := NewFailureInbox(InboxConfig{MaxCandidates: 1, MaxEvidencePerCandidate: 1, MaxSignals: 1, MaxReasons: 1}, fixed)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.51")}
	first := validFailureObservation(client, SignalReassemblyAbort, fixed.Now())
	first.DNSCandidates = []classifier.Evidence{{Source: classifier.EvidenceDNSAnswer, Client: client, DestinationIP: first.DestinationIP, DestinationPort: 443, L4Proto: 6, Domain: "one.example", SetID: "one", ExpiresAt: fixed.Now().Add(time.Minute)}}
	candidate, err := inbox.Observe(first)
	if err != nil || candidate.SuggestedAction != ActionClientHello || len(candidate.AvailableActions) != 6 {
		t.Fatalf("reassembly action model invalid: %+v err=%v", candidate, err)
	}
	second := validFailureObservation(client, SignalQueueDrop, fixed.Now().Add(time.Second))
	second.DestinationIP = netip.MustParseAddr("203.0.113.12")
	if _, err := inbox.Observe(second); err != nil {
		t.Fatal(err)
	}
	if inbox.Len() != 1 || inbox.List(1)[0].DestinationIP != second.DestinationIP {
		t.Fatal("bounded eviction did not remove the oldest candidate")
	}
}

func TestFailureInboxRejectsUnscopedInput(t *testing.T) {
	inbox := NewFailureInbox(InboxConfig{}, clock.NewFixed(time.Unix(500, 0)))
	_, err := inbox.Observe(validFailureObservation(classifier.ClientKey{}, SignalProbeFailure, time.Unix(500, 0)))
	if !errors.Is(err, ErrFailureClientRequired) {
		t.Fatalf("unscoped input was accepted: %v", err)
	}
}

func mustJSON(value FailureCandidate) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func FuzzFailureInboxValidation(f *testing.F) {
	f.Add("probe_failure", "192.0.2.61", uint16(443), uint8(6), "reason")
	f.Fuzz(func(t *testing.T, signal, address string, port uint16, protocol uint8, reason string) {
		inbox := NewFailureInbox(InboxConfig{MaxCandidates: 2}, clock.NewFixed(time.Unix(600, 0)))
		client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.61")}
		destination, err := netip.ParseAddr(address)
		if err != nil {
			destination = netip.MustParseAddr("203.0.113.61")
		}
		_, _ = inbox.Observe(FailureObservation{Signal: FailureSignal(signal), Client: client, DestinationIP: destination, DestinationPort: port, Protocol: protocol, Reason: reason, ObservedAt: time.Unix(600, 0)})
	})
}

func BenchmarkFailureInboxObserve(b *testing.B) {
	fixed := clock.NewFixed(time.Unix(700, 0))
	inbox := NewFailureInbox(InboxConfig{MaxCandidates: 128}, fixed)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.71")}
	observation := validFailureObservation(client, SignalConntrackUnreplied, fixed.Now())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = inbox.Observe(observation)
	}
}

func TestFailureInboxStoresPrivacySafePassiveRSTEvidenceAndOutcome(t *testing.T) {
	fixed := clock.NewFixed(time.Unix(800, 0))
	inbox := NewFailureInbox(InboxConfig{Retention: time.Minute}, fixed)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.81"), SourceMAC: [6]byte{2, 1, 2, 3, 4, 81}}
	observation := validFailureObservation(client, SignalPassiveRSTSuppressed, fixed.Now())
	observation.SetCandidates = []string{"private-youtube"}
	observation.PassiveRST = &PassiveRSTFailureDetails{
		FlowID: "raw exact flow", SetID: "private-youtube", DeviceScope: "aa:bb:cc:dd:ee:81", ConfigGeneration: 77,
		TCPPhase: "post-syn-ack-pre-payload", Signals: []PassiveRSTSignalDetail{{Signal: "sequence-outside", Strength: "strong", Reason: "raw seq 1234"}},
		BaselineQuality: "stable", BaselineSpread: 2, Sequence: PassiveRSTWindowDetail{Reliable: true, InWindow: false},
		Acknowledgment: PassiveRSTWindowDetail{Reliable: true, InWindow: true}, OptionFingerprint: "mismatch", Decision: "suppress",
		RequestedMode: "conservative", EffectiveMode: "conservative",
	}
	candidate, err := inbox.Observe(observation)
	if err != nil || candidate.PassiveRST == nil || candidate.SuggestedAction != ActionScopedCanary {
		t.Fatalf("candidate=%+v err=%v", candidate, err)
	}
	exported := string(mustJSON(*candidate))
	for _, secret := range []string{"raw exact flow", "private-youtube", "aa:bb:cc:dd:ee:81"} {
		if strings.Contains(exported, secret) {
			t.Fatalf("privacy leak %q in %s", secret, exported)
		}
	}
	if !inbox.UpdatePassiveRSTOutcome(client, "203.0.113.10", 443, 6, "server-progress", fixed.Now().Add(time.Second)) {
		t.Fatal("causal outcome was not attached")
	}
	got := inbox.List(1)[0]
	if got.PassiveRST.PostDecisionOutcome != "server-progress" || got.PassiveRST.Decision != "suppress" {
		t.Fatalf("outcome changed decision semantics: %+v", got.PassiveRST)
	}
}
