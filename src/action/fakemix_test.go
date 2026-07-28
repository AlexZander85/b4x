package action

import (
	"errors"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/sni"
)

func u64(value uint64) *uint64 { return &value }

func fakeMixRequest(t testing.TB, dryRun bool) FakeMixRequest {
	t.Helper()
	real := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	return FakeMixRequest{
		Enabled: true, StrategyID: "fakedsplit-test", Mode: FakeMixSplit,
		Real:          PlanInput{BaseSequence: 8000, Payload: real, Markers: DiscoverTLSMarkers(real), MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1 << 30, MaxWrites: 16, DryRun: dryRun},
		RealPositions: []SplitPositionSpec{{Marker: MarkerHostStart}, {Marker: MarkerHostEnd}},
		FakePositions: []SplitPositionSpec{{Absolute: u64(1)}},
		Profile:       compiledFakeProfile(t), Confidence: 96, MinConfidence: 85, TCPPhase: "clienthello", AllowedTCPPhases: []string{"clienthello"},
		Order: FakeThenReal, FakeSegmentOrder: OrderForward, Budgets: DefaultActionBudgets(), FlowHash: 800, ClientHelloID: 11, ConfigGen: 14,
	}
}

func TestPlanFakeMixKillSwitchAndEndpointStream(t *testing.T) {
	request := fakeMixRequest(t, true)
	request.Enabled = false
	if _, err := PlanFakeMix(request); !errors.Is(err, ErrTechniqueDisabled) {
		t.Fatalf("disabled technique error=%v", err)
	}
	request = fakeMixRequest(t, true)
	original := append([]byte(nil), request.Real.Payload...)
	plan, err := PlanFakeMix(request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Valid || !plan.Enabled || plan.Mode != FakeMixSplit || len(plan.FakeWrites) == 0 || len(plan.RealWrites) == 0 {
		t.Fatalf("plan=%+v", plan)
	}
	if string(plan.EndpointPayload) != string(original) || plan.EndpointSHA256 == "" || plan.GeneratedBytes == 0 {
		t.Fatalf("endpoint stream changed: %+v", plan)
	}
	if !strings.EqualFold(sni.ParseTLSClientHelloMetadata(plan.EndpointPayload).SNI, "api.youtube.com") {
		t.Fatalf("endpoint SNI was not original: %q", sni.ParseTLSClientHelloMetadata(plan.EndpointPayload).SNI)
	}
	for _, write := range plan.FakeWrites {
		if write.EndpointVisible || write.Kind != FakeWrite || write.ProcessedMark == 0 {
			t.Fatalf("fake write visibility/provenance=%+v", write)
		}
	}
	for _, write := range plan.RealWrites {
		if !write.EndpointVisible || write.Kind != RealWrite || write.ProcessedMark == 0 {
			t.Fatalf("real write visibility/provenance=%+v", write)
		}
	}
}

func TestPlanFakeDisorderAndTokenIdempotency(t *testing.T) {
	request := fakeMixRequest(t, false)
	request.Mode = FakeMixDisorder
	request.StrategyID = "fakeddisorder-test"
	request.FakeSegmentOrder = OrderReverse
	request.FakePositions = []SplitPositionSpec{{Absolute: u64(1)}, {Absolute: u64(2)}}
	request.Tokens = NewActionTokenStore(ActionTokenStoreConfig{Clock: clock.NewFixed(testNow()), Budgets: DefaultActionBudgets()})
	first, err := PlanFakeMix(request)
	if err != nil || !first.Token.Applied {
		t.Fatalf("first plan=%+v err=%v", first, err)
	}
	if len(first.FakeWrites) < 2 || first.FakeWrites[0].StreamStart <= first.FakeWrites[1].StreamStart {
		t.Fatalf("fake disorder was not sequence-aware: %+v", first.FakeWrites)
	}
	request.Real.Retransmission = true
	second, err := PlanFakeMix(request)
	if !errors.Is(err, ErrRetransmission) || !second.Token.Suppressed {
		t.Fatalf("retransmission was not suppressed: plan=%+v err=%v", second, err)
	}
}

func TestPlanFakeMixRejectsLowConfidenceECHAndOversizedProfile(t *testing.T) {
	request := fakeMixRequest(t, true)
	request.Confidence = 10
	if _, err := PlanFakeMix(request); !errors.Is(err, ErrFakeMixPrecondition) {
		t.Fatalf("low-confidence error=%v", err)
	}
	request = fakeMixRequest(t, true)
	request.Real.Markers.ECH = true
	if _, err := PlanFakeMix(request); !errors.Is(err, ErrFakeMixPrecondition) {
		t.Fatalf("ECH error=%v", err)
	}
	request = fakeMixRequest(t, true)
	request.Profile.Profile.MTUFits = false
	if _, err := PlanFakeMix(request); !errors.Is(err, ErrFakeMixProfile) {
		t.Fatalf("oversized profile error=%v", err)
	}
}

func FuzzPlanFakeMixNoPanic(f *testing.F) {
	f.Add(uint8(96), int32(0), true)
	f.Add(uint8(1), int32(-20), false)
	f.Fuzz(func(t *testing.T, confidence uint8, delta int32, dryRun bool) {
		request := fakeMixRequest(t, dryRun)
		request.Confidence = confidence
		request.RealPositions = []SplitPositionSpec{{Marker: MarkerHostStart, Delta: delta}}
		_, _ = PlanFakeMix(request)
	})
}

func BenchmarkPlanFakeMix(b *testing.B) {
	request := fakeMixRequest(b, true)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = PlanFakeMix(request)
	}
}
