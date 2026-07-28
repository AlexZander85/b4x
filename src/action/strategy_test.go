package action

import (
	"errors"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func strategyMarkers() MarkerSet {
	return MarkerSet{
		Host:     "api.youtube.com",
		Complete: true,
		Markers: []LogicalMarker{
			{Kind: MarkerClientHelloStart, Offset: 0, Available: true},
			{Kind: MarkerSNIExtensionStart, Offset: 2, Available: true},
			{Kind: MarkerHostStart, Offset: 4, Available: true},
			{Kind: MarkerSLDMiddle, Offset: 7, Available: true},
			{Kind: MarkerHostEnd, Offset: 11, Available: true},
			{Kind: MarkerClientHelloEnd, Offset: 16, Available: true},
		},
	}
}

func strategyRequest(definition StrategyDefinition, payload []byte) StrategyRequest {
	return StrategyRequest{
		Input:      PlanInput{BaseSequence: 1000, Payload: payload, Markers: strategyMarkers(), MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1 << 30, MaxWrites: 16},
		Definition: definition, Confidence: 95, CompleteClientHello: true, FlowHash: 7, ClientHelloID: 11, ConfigGen: 3,
	}
}

func TestPlanStrategyForwardReverseAndCustomOrder(t *testing.T) {
	payload := []byte("abcdefghijklmnop")
	base := StrategyDefinition{ID: "two", Technique: TechniqueMultiSplit, Positions: []SplitPositionSpec{{Absolute: uint64Ptr(4)}}, SegmentOrder: OrderForward, Preconditions: StrategyPreconditions{MinConfidence: 80, RequiresCompleteCH: true, FirstFlightOnly: true}, Budgets: DefaultActionBudgets()}
	forwardRequest := strategyRequest(base, payload)
	forwardRequest.Input.DryRun = true
	forward, err := PlanStrategy(forwardRequest)
	if err != nil {
		t.Fatal(err)
	}
	if got := forward.ResolvedOffsets; len(got) != 1 || got[0] != 4 || len(forward.ActionPlan.Writes) != 2 {
		t.Fatalf("forward=%+v", forward)
	}
	if forward.ActionPlan.Writes[0].Sequence != 1000 || forward.ActionPlan.Writes[1].Sequence != 1004 {
		t.Fatalf("forward sequence mapping=%+v", forward.ActionPlan.Writes)
	}

	base.Technique = TechniqueMultiDisorder
	base.SegmentOrder = OrderReverse
	reverseRequest := strategyRequest(base, payload)
	reverseRequest.Input.DryRun = true
	reverse, err := PlanStrategy(reverseRequest)
	if err != nil {
		t.Fatal(err)
	}
	if reverse.ActionPlan.Writes[0].StreamStart != 4 || reverse.ActionPlan.Writes[0].Sequence != 1004 || string(reverse.ActionPlan.Writes[0].Payload) != "efghijklmnop" {
		t.Fatalf("reverse did not preserve stream sequence=%+v", reverse.ActionPlan.Writes)
	}

	base.SegmentOrder = OrderCustom
	base.CustomOrder = []int{1, 0}
	customRequest := strategyRequest(base, payload)
	customRequest.Input.DryRun = true
	custom, err := PlanStrategy(customRequest)
	if err != nil {
		t.Fatal(err)
	}
	if custom.Order[0] != 1 || custom.Order[1] != 0 {
		t.Fatalf("custom order=%v", custom.Order)
	}
}

func TestPlanStrategySemanticMarkersAndMTU(t *testing.T) {
	payload := make([]byte, 3200)
	definition := StrategyDefinition{
		ID: "host-three", Technique: TechniqueMultiSplit,
		Positions:     []SplitPositionSpec{{Marker: MarkerHostStart}, {Marker: MarkerSLDMiddle}},
		SegmentOrder:  OrderForward,
		Preconditions: StrategyPreconditions{MinConfidence: 90, RequiresClearSNI: true, RequiresCompleteCH: true, FirstFlightOnly: true},
		Budgets:       ActionBudgets{MaxWritesPerHello: 8, MaxFakeBytes: 4096, MaxAmplification: 1},
	}
	request := strategyRequest(definition, payload)
	request.Input.DryRun = true
	request.Input.MTU = 1500
	planned, err := PlanStrategy(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(planned.ResolvedOffsets) != 2 || planned.ResolvedOffsets[0] != 4 || planned.ResolvedOffsets[1] != 7 {
		t.Fatalf("offsets=%v", planned.ResolvedOffsets)
	}
	for _, write := range planned.ActionPlan.Writes {
		if len(write.Payload) > 1460 {
			t.Fatalf("MTU overflow write=%d", len(write.Payload))
		}
	}
	if planned.ActionPlan.TotalBytes != len(payload) {
		t.Fatalf("stream bytes changed: %d", planned.ActionPlan.TotalBytes)
	}
}

func TestPlanStrategyFiveSegmentsForAPIVideoProfiles(t *testing.T) {
	for _, profile := range []string{"youtube-api", "youtube-ui", "googlevideo"} {
		definition := StrategyDefinition{
			ID: profile + "-five-segment", Technique: TechniqueMultiSplit,
			Positions:     []SplitPositionSpec{{Absolute: uint64Ptr(4)}, {Absolute: uint64Ptr(8)}, {Absolute: uint64Ptr(16)}, {Absolute: uint64Ptr(24)}},
			SegmentOrder:  OrderForward,
			Preconditions: StrategyPreconditions{MinConfidence: 70, RequiresCompleteCH: true},
			Budgets:       DefaultActionBudgets(),
		}
		request := strategyRequest(definition, []byte("0123456789abcdefghijklmnopqrstuv"))
		request.Input.DryRun = true
		planned, err := PlanStrategy(request)
		if err != nil {
			t.Fatalf("profile=%s err=%v", profile, err)
		}
		if len(planned.ActionPlan.Writes) != 5 || planned.ActionPlan.TotalBytes != len(request.Input.Payload) {
			t.Fatalf("profile=%s plan=%+v", profile, planned.ActionPlan)
		}
	}
}

func TestPlanStrategyPreconditionsECHAndNoToken(t *testing.T) {
	definition := InitialMarkerStrategyCatalog()[2]
	request := strategyRequest(definition, []byte("abcdefghijklmnop"))
	request.Input.Markers.ECH = true
	if _, err := PlanStrategy(request); !errors.Is(err, ErrStrategyPrecondition) {
		t.Fatalf("ECH strategy error=%v", err)
	}

	request.Input.Markers.ECH = false
	request.Input.DryRun = false
	if _, err := PlanStrategy(request); !errors.Is(err, ErrStrategyTokenRequired) {
		t.Fatalf("missing token store error=%v", err)
	}
	request.Input.DryRun = true
	if _, err := PlanStrategy(request); err != nil {
		t.Fatalf("dry-run unexpectedly requires token: %v", err)
	}
}

func TestPlanStrategyTokenIdempotencyAndRollbackGeneration(t *testing.T) {
	definition := InitialMarkerStrategyCatalog()[0]
	store := NewActionTokenStore(ActionTokenStoreConfig{Clock: clock.NewFixed(testNow()), Budgets: DefaultActionBudgets()})
	request := strategyRequest(definition, []byte("abcdefghijklmnop"))
	request.Tokens = store
	first, err := PlanStrategy(request)
	if err != nil || !first.Token.Applied {
		t.Fatalf("first plan=%+v err=%v", first, err)
	}
	request.Input.Retransmission = true
	second, err := PlanStrategy(request)
	if !errors.Is(err, ErrRetransmission) || !second.Token.Suppressed {
		t.Fatalf("retransmission plan=%+v err=%v", second, err)
	}
	store.InvalidateGeneration(request.ConfigGen)
	request.Input.Retransmission = false
	third, err := PlanStrategy(request)
	if !errors.Is(err, ErrRetransmission) || !third.Token.Suppressed {
		t.Fatalf("invalidated generation plan=%+v err=%v", third, err)
	}
}

func TestInitialMarkerCatalogIsReadOnlyAndBounded(t *testing.T) {
	first := InitialMarkerStrategyCatalog()
	second := InitialMarkerStrategyCatalog()
	if len(first) != 5 || len(second) != len(first) {
		t.Fatalf("catalog size first=%d second=%d", len(first), len(second))
	}
	first[0].Positions[0].Absolute = uint64Ptr(99)
	if *second[0].Positions[0].Absolute == 99 {
		t.Fatal("catalog returned shared mutable position pointers")
	}
	for _, definition := range first {
		if len(definition.Positions) == 0 || len(definition.Positions) > 8 || definition.Budgets.MaxWritesPerHello == 0 {
			t.Fatalf("unbounded catalog entry=%+v", definition)
		}
	}
}

func FuzzPlanStrategyNoPanic(f *testing.F) {
	f.Add(uint64(1), uint64(4), true)
	f.Add(uint64(100), uint64(7), false)
	definition := InitialMarkerStrategyCatalog()[0]
	f.Fuzz(func(t *testing.T, offset, payloadSize uint64, dryRun bool) {
		payloadSize = payloadSize%2048 + 1
		offset = offset % (payloadSize + 1)
		definition.Positions = []SplitPositionSpec{{Absolute: &offset}}
		request := strategyRequest(definition, make([]byte, payloadSize))
		request.Input.DryRun = dryRun
		_, _ = PlanStrategy(request)
	})
}

func BenchmarkPlanStrategy(b *testing.B) {
	definition := InitialMarkerStrategyCatalog()[2]
	request := strategyRequest(definition, make([]byte, 1800))
	request.Input.DryRun = true
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = PlanStrategy(request)
	}
}

func uint64Ptr(value uint64) *uint64 { return &value }

func testNow() time.Time { return time.Unix(100, 0) }
