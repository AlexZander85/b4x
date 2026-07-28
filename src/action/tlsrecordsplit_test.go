package action

import (
	"bytes"
	"errors"
	"testing"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/fixtures"
)

func tlsRecordSplitRequest(t testing.TB, dryRun bool) TLSRecordSplitRequest {
	t.Helper()
	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	return TLSRecordSplitRequest{
		Enabled: true, StrategyID: "tls-record-split-test",
		Input:         PlanInput{BaseSequence: 9000, Payload: payload, Markers: DiscoverTLSMarkers(payload), MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1 << 29, MaxWrites: 16, DryRun: dryRun},
		Positions:     []SplitPositionSpec{{Marker: MarkerHostStart}, {Marker: MarkerHostEnd}},
		Preconditions: StrategyPreconditions{MinConfidence: 85, RequiresClearSNI: true, RequiresCompleteCH: true, AllowedTCPPhases: []string{"clienthello"}, FirstFlightOnly: true},
		Budgets:       DefaultActionBudgets(), Confidence: 96, TCPPhase: "clienthello", FlowHash: 900, ClientHelloID: 12, ConfigGen: 15,
	}
}

func TestPlanTLSRecordSplitPreservesClientHelloAndTrailingRecords(t *testing.T) {
	request := tlsRecordSplitRequest(t, true)
	trailing := []byte{0x17, 0x03, 0x03, 0, 1, 0}
	request.Input.Payload = append(request.Input.Payload, trailing...)
	request.Input.Markers = DiscoverTLSMarkers(request.Input.Payload)
	original := append([]byte(nil), request.Input.Payload...)
	plan, err := PlanTLSRecordSplit(request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Valid || plan.Technique != TechniqueTLSRecordSplit || plan.RecordCount != 2 || plan.TrailingBytes != len(trailing) {
		t.Fatalf("plan=%+v", plan)
	}
	if len(plan.ResolvedOffsets) != 2 || plan.ClientHelloEnd >= uint64(len(original)) {
		t.Fatalf("marker boundaries=%+v", plan)
	}
	reassembled := make([]byte, 0, len(original))
	for _, write := range plan.ActionPlan.Writes {
		reassembled = append(reassembled, write.Payload...)
	}
	if !bytes.Equal(reassembled, original) {
		t.Fatalf("record split changed stream")
	}
	if !bytes.Equal(reassembled[plan.ClientHelloEnd:], trailing) {
		t.Fatalf("trailing TLS record was not preserved: %x", reassembled[plan.ClientHelloEnd:])
	}
}

func TestPlanTLSRecordSplitTokenAndPreconditionGates(t *testing.T) {
	request := tlsRecordSplitRequest(t, false)
	request.Tokens = NewActionTokenStore(ActionTokenStoreConfig{Clock: clock.NewFixed(testNow()), Budgets: DefaultActionBudgets()})
	first, err := PlanTLSRecordSplit(request)
	if err != nil || !first.Token.Applied {
		t.Fatalf("first plan=%+v err=%v", first, err)
	}
	request.Input.Retransmission = true
	second, err := PlanTLSRecordSplit(request)
	if !errors.Is(err, ErrRetransmission) || !second.Token.Suppressed {
		t.Fatalf("retransmission was not suppressed: plan=%+v err=%v", second, err)
	}

	request = tlsRecordSplitRequest(t, true)
	request.Positions = []SplitPositionSpec{{Absolute: u64(1)}}
	if _, err := PlanTLSRecordSplit(request); !errors.Is(err, ErrTLSRecordSplitInvalid) {
		t.Fatalf("absolute boundary error=%v", err)
	}
	request = tlsRecordSplitRequest(t, true)
	request.Preconditions.FirstFlightOnly = false
	if _, err := PlanTLSRecordSplit(request); !errors.Is(err, ErrTLSRecordSplitInvalid) {
		t.Fatalf("first-flight error=%v", err)
	}
	request = tlsRecordSplitRequest(t, true)
	request.Input.Markers.ECH = true
	if _, err := PlanTLSRecordSplit(request); !errors.Is(err, ErrStrategyPrecondition) {
		t.Fatalf("ECH clear-SNI error=%v", err)
	}
}

func TestPlanTLSRecordSplitRejectsNonClientHelloAndMalformedEnvelope(t *testing.T) {
	request := tlsRecordSplitRequest(t, true)
	request.Input.Payload = append([]byte{0x14, 0x03, 0x03, 0, 1, 0}, request.Input.Payload...)
	request.Input.Markers = DiscoverTLSMarkers(request.Input.Payload)
	if _, err := PlanTLSRecordSplit(request); !errors.Is(err, ErrTLSRecordSplitMalformed) {
		t.Fatalf("non-ClientHello first record error=%v", err)
	}
	request = tlsRecordSplitRequest(t, true)
	request.Input.Payload = []byte{0x16, 0x03, 0x03, 0, 4, 1, 0, 0, 0xff}
	request.Input.Markers = DiscoverTLSMarkers(request.Input.Payload)
	if _, err := PlanTLSRecordSplit(request); !errors.Is(err, ErrTLSRecordSplitMalformed) {
		t.Fatalf("malformed record error=%v", err)
	}
	request = tlsRecordSplitRequest(t, true)
	request.Enabled = false
	if _, err := PlanTLSRecordSplit(request); !errors.Is(err, ErrTechniqueDisabled) {
		t.Fatalf("disabled technique error=%v", err)
	}
}

func FuzzPlanTLSRecordSplitNoPanic(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x03, 0, 1, 1}, int32(0), uint8(96))
	f.Add([]byte{1, 2, 3}, int32(-10), uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, delta int32, confidence uint8) {
		request := tlsRecordSplitRequest(t, true)
		request.Input.Payload = append([]byte(nil), payload...)
		request.Input.Markers = DiscoverTLSMarkers(payload)
		request.Confidence = confidence
		request.Positions = []SplitPositionSpec{{Marker: MarkerHostStart, Delta: delta}}
		_, _ = PlanTLSRecordSplit(request)
	})
}

func BenchmarkPlanTLSRecordSplit(b *testing.B) {
	request := tlsRecordSplitRequest(b, true)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = PlanTLSRecordSplit(request)
	}
}
