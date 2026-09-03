package action

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/fixtures"
	"github.com/daniellavrushin/b4/lab"
	"github.com/daniellavrushin/b4/sni"
)

func compiledFakeProfile(t testing.TB) lab.CompiledArtifact {
	t.Helper()
	raw := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	source, err := lab.NewRawClientHelloArtifact("hostfakesplit-source", lab.CapturedHelloProfile{ID: "source", HelloHash: hash, SHA256: hash, RawSize: len(raw), IPFamily: "ipv4", PrivacySafe: true}, raw, "stage-29-test")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := lab.CompileFakeProfile(lab.CompileRequest{Source: source, Mode: lab.CompileFingerprintPreserving, ReplacementSNI: "fake.example", MTU: lab.MTUEstimator{Family: "ipv4", MTU: 1500}, Seed: 7, Provenance: "stage-29-test"})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func hostFakeRequest(t testing.TB, dryRun bool) HostFakeSplitRequest {
	t.Helper()
	real := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	return HostFakeSplitRequest{
		StrategyID:    "hostfakesplit-test",
		Real:          PlanInput{BaseSequence: 5000, Payload: real, Markers: DiscoverTLSMarkers(real), MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1 << 30, MaxWrites: 16, DryRun: dryRun},
		RealPositions: []SplitPositionSpec{{Marker: MarkerHostStart}, {Marker: MarkerHostEnd}},
		Profile:       compiledFakeProfile(t), Confidence: 95, MinConfidence: 85, TCPPhase: "clienthello", AllowedTCPPhases: []string{"clienthello"}, Order: FakeThenReal, Budgets: DefaultActionBudgets(), FlowHash: 77, ClientHelloID: 9, ConfigGen: 12,
	}
}

func TestPlanHostFakeSplitPreservesOriginalEndpointStream(t *testing.T) {
	request := hostFakeRequest(t, true)
	original := append([]byte(nil), request.Real.Payload...)
	plan, err := PlanHostFakeSplit(request)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Valid || plan.ProfileID == "" || plan.Order != FakeThenReal || len(plan.FakeWrites) == 0 || len(plan.RealWrites) == 0 {
		t.Fatalf("plan=%+v", plan)
	}
	if string(plan.EndpointPayload) != string(original) || plan.EndpointSHA256 == "" || plan.GeneratedBytes == 0 {
		t.Fatalf("endpoint stream was not preserved: %+v", plan)
	}
	if plan.Writes[0].Kind != FakeWrite || plan.Writes[0].EndpointVisible {
		t.Fatalf("fake visibility=%+v", plan.Writes[0])
	}
	if plan.Writes[len(plan.Writes)-1].Kind != RealWrite || !plan.Writes[len(plan.Writes)-1].EndpointVisible {
		t.Fatalf("real visibility=%+v", plan.Writes[len(plan.Writes)-1])
	}
	for _, write := range plan.RealWrites {
		if write.ProcessedMark == 0 || write.Kind != RealWrite {
			t.Fatalf("real write provenance=%+v", write)
		}
	}
	meta := sni.ParseTLSClientHelloMetadata(plan.EndpointPayload)
	if !meta.Complete || !strings.EqualFold(meta.SNI, "api.youtube.com") {
		t.Fatalf("endpoint metadata=%+v", meta)
	}
}

func TestPlanHostFakeSplitTokenIdempotencyAndOrder(t *testing.T) {
	request := hostFakeRequest(t, false)
	request.Tokens = NewActionTokenStore(ActionTokenStoreConfig{Clock: clock.NewFixed(testNow()), Budgets: DefaultActionBudgets()})
	first, err := PlanHostFakeSplit(request)
	if err != nil || !first.Token.Applied {
		t.Fatalf("first plan=%+v err=%v", first, err)
	}
	request.Order = RealThenFake
	request.Real.Retransmission = true
	second, err := PlanHostFakeSplit(request)
	if !errors.Is(err, ErrRetransmission) || !second.Token.Suppressed || second.Writes[0].Kind != RealWrite {
		t.Fatalf("repeat plan=%+v err=%v", second, err)
	}
}

func TestPlanHostFakeSplitRejectsECHConfidenceFSMAndSameSNI(t *testing.T) {
	request := hostFakeRequest(t, true)
	request.Real.Markers.ECH = true
	if _, err := PlanHostFakeSplit(request); !errors.Is(err, ErrHostFakePrecondition) {
		t.Fatalf("ECH error=%v", err)
	}
	request = hostFakeRequest(t, true)
	request.Confidence = 20
	if _, err := PlanHostFakeSplit(request); !errors.Is(err, ErrHostFakePrecondition) {
		t.Fatalf("confidence error=%v", err)
	}
	request = hostFakeRequest(t, true)
	request.TCPPhase = "server-progress"
	if _, err := PlanHostFakeSplit(request); !errors.Is(err, ErrHostFakePrecondition) {
		t.Fatalf("FSM error=%v", err)
	}
	request = hostFakeRequest(t, true)
	request.Profile = sameSNIProfile(t)
	if _, err := PlanHostFakeSplit(request); !errors.Is(err, ErrHostFakeProfile) {
		t.Fatalf("same SNI error=%v", err)
	}
}

func sameSNIProfile(t testing.TB) lab.CompiledArtifact {
	t.Helper()
	raw := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	source, err := lab.NewRawClientHelloArtifact("same-source", lab.CapturedHelloProfile{ID: "same-source", HelloHash: hash, SHA256: hash, RawSize: len(raw), IPFamily: "ipv4", PrivacySafe: true}, raw, "test")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := lab.CompileFakeProfile(lab.CompileRequest{Source: source, Mode: lab.CompileFingerprintPreserving, ReplacementSNI: "api.youtube.com", MTU: lab.MTUEstimator{Family: "ipv4", MTU: 1500}, Provenance: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func FuzzPlanHostFakeSplitNoPanic(f *testing.F) {
	f.Add(uint8(95), int32(0), true)
	f.Add(uint8(1), int32(-20), false)
	f.Fuzz(func(t *testing.T, confidence uint8, delta int32, dryRun bool) {
		request := hostFakeRequest(t, dryRun)
		request.Confidence = confidence
		request.RealPositions = []SplitPositionSpec{{Marker: MarkerHostStart, Delta: delta}}
		_, _ = PlanHostFakeSplit(request)
	})
}

func BenchmarkPlanHostFakeSplit(b *testing.B) {
	request := hostFakeRequest(b, true)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = PlanHostFakeSplit(request)
	}
}
