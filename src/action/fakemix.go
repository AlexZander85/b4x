package action

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/daniellavrushin/b4/lab"
	"github.com/daniellavrushin/b4/sni"
)

// FakeMixMode names the two explicitly selected fake-payload techniques. The
// mode is a property of a request, never an automatic strategy choice.
type FakeMixMode string

const (
	FakeMixSplit    FakeMixMode = "fakedsplit"
	FakeMixDisorder FakeMixMode = "fakeddisorder"
)

var (
	ErrTechniqueDisabled   = errors.New("action technique kill switch is disabled")
	ErrFakeMixInvalid      = errors.New("invalid fake-mix request")
	ErrFakeMixPrecondition = errors.New("fake-mix precondition failed")
	ErrFakeMixProfile      = errors.New("fake-mix profile is invalid")
)

// FakeMixRequest is a bounded, declarative fake/real write request. It does
// not own packet I/O. Enabled is the per-technique kill switch and defaults to
// false at every call site unless a rollout explicitly opts in.
type FakeMixRequest struct {
	Enabled          bool
	StrategyID       string
	Mode             FakeMixMode
	Real             PlanInput
	RealPositions    []SplitPositionSpec
	FakePositions    []SplitPositionSpec
	Profile          lab.CompiledArtifact
	Confidence       uint8
	MinConfidence    uint8
	TCPPhase         string
	AllowedTCPPhases []string
	Order            FakeRealOrder
	FakeSegmentOrder SegmentOrder
	FakeCustomOrder  []int
	Budgets          ActionBudgets
	FlowHash         uint64
	ClientHelloID    uint64
	ConfigGen        uint64
	Tokens           *ActionTokenStore
}

// FakeMixPlan carries both wire intents and the endpoint-visible original
// stream. A consumer must route fake writes according to EndpointVisible; the
// planner itself never sends, requeues, or mutates a packet.
type FakeMixPlan struct {
	Valid            bool
	DryRun           bool
	Enabled          bool
	StrategyID       string
	Mode             FakeMixMode
	ProfileID        string
	Order            FakeRealOrder
	FakeSegmentOrder SegmentOrder
	FakeWrites       []HostFakeWrite
	RealWrites       []HostFakeWrite
	Writes           []HostFakeWrite
	EndpointPayload  []byte
	EndpointSHA256   string
	TotalBytes       int
	GeneratedBytes   int
	Token            ActionTokenResult
	Reason           string
}

// PlanFakeMix applies a selected fake-split or fake-disorder plan. The fake
// profile must be a validated, inactive, single-packet-safe artifact and the
// real ClientHello must have clear, complete host markers. The real stream is
// never replaced by the fake profile.
func PlanFakeMix(request FakeMixRequest) (FakeMixPlan, error) {
	plan := FakeMixPlan{
		DryRun: request.Real.DryRun, Enabled: request.Enabled,
		StrategyID: request.StrategyID, Mode: request.Mode,
		ProfileID: request.Profile.Profile.ID, Order: request.Order,
		FakeSegmentOrder: request.FakeSegmentOrder,
	}
	if !request.Enabled {
		return plan, ErrTechniqueDisabled
	}
	if err := validateFakeMixRequest(request); err != nil {
		return plan, err
	}
	if err := request.Profile.Validate(); err != nil || !request.Profile.Profile.MTUFits {
		return plan, fmt.Errorf("%w: inactive single-packet-safe artifact is required", ErrFakeMixProfile)
	}

	realMeta := sni.ParseTLSClientHelloMetadata(request.Real.Payload)
	fakeMeta := sni.ParseTLSClientHelloMetadata(request.Profile.Bytes())
	if !realMeta.Complete || realMeta.ParseError != "" || realMeta.SNI == "" ||
		!fakeMeta.Complete || fakeMeta.ParseError != "" || fakeMeta.SNI == "" {
		return plan, ErrFakeMixProfile
	}
	if !strings.EqualFold(realMeta.SNI, request.Real.Markers.Host) {
		return plan, fmt.Errorf("%w: reassembled SNI does not match host marker", ErrFakeMixPrecondition)
	}
	if strings.EqualFold(realMeta.SNI, fakeMeta.SNI) {
		return plan, fmt.Errorf("%w: fake profile did not structurally replace SNI", ErrFakeMixProfile)
	}

	realOffsets, err := resolveStrategyOffsets(request.RealPositions, request.Real.Markers, len(request.Real.Payload))
	if err != nil {
		return plan, err
	}
	fakeOffsets, err := resolveAbsoluteOnlyPositions(request.FakePositions, len(request.Profile.Bytes()))
	if err != nil {
		return plan, err
	}

	realInput := request.Real
	realRetransmission := realInput.Retransmission
	realInput.Retransmission = false
	realInput.DryRun = true
	realInput.SplitPositions = splitPositionsFromOffsets(realOffsets)
	realPlan, err := Plan(realInput)
	if err != nil {
		return plan, err
	}

	fakeInput := PlanInput{
		BaseSequence: request.Real.BaseSequence,
		Payload:      request.Profile.Bytes(), SplitPositions: splitPositionsFromOffsets(fakeOffsets),
		MTU: request.Real.MTU, IPHeaderLen: request.Real.IPHeaderLen, TCPHeaderLen: request.Real.TCPHeaderLen,
		ProcessedMark: request.Real.ProcessedMark, MaxWrites: request.Real.MaxWrites,
		MaxBytes: request.Real.MaxBytes, DryRun: true,
	}
	fakePlan, err := Plan(fakeInput)
	if err != nil {
		return plan, err
	}

	fakeOrder, err := fakeSegmentOrder(request)
	if err != nil {
		return plan, err
	}
	fakePlan.Writes = reorderWrites(fakePlan.Writes, fakeOrder, fakeOffsets)
	for i := range fakePlan.Writes {
		fakePlan.Writes[i].Order = i
	}
	if err := request.Budgets.Check(len(request.Real.Payload), len(realPlan.Writes)+len(fakePlan.Writes), len(request.Profile.Bytes())); err != nil {
		return plan, err
	}

	plan.FakeWrites = hostFakeWrites(FakeWrite, fakePlan.Writes, request.Real.ProcessedMark, false)
	plan.RealWrites = hostFakeWrites(RealWrite, realPlan.Writes, request.Real.ProcessedMark, true)
	plan.Writes = orderedHostFakeWrites(plan.FakeWrites, plan.RealWrites, request.Order)
	plan.EndpointPayload = append([]byte(nil), request.Real.Payload...)
	sum := sha256.Sum256(plan.EndpointPayload)
	plan.EndpointSHA256 = hex.EncodeToString(sum[:])
	plan.TotalBytes = realPlan.TotalBytes + fakePlan.TotalBytes
	plan.GeneratedBytes = len(request.Profile.Bytes())
	plan.Reason = "explicit confidence-gated fake mix preserves original endpoint stream"
	plan.Valid = true
	if request.Real.DryRun {
		return plan, nil
	}
	if request.Tokens == nil {
		return plan, ErrStrategyTokenRequired
	}
	token := request.Tokens.Claim(ActionTokenRequest{
		FlowHash: request.FlowHash, ClientHelloID: request.ClientHelloID, StrategyID: request.StrategyID,
		ConfigGen: request.ConfigGen, StreamStart: 0, StreamEnd: uint64(len(request.Real.Payload)),
		InputBytes: len(request.Real.Payload), Writes: len(plan.Writes), GeneratedBytes: plan.GeneratedBytes,
		ProcessedMark: request.Real.ProcessedMark,
	})
	plan.Token = token
	if token.Suppressed || realRetransmission {
		return plan, ErrRetransmission
	}
	return plan, nil
}

func validateFakeMixRequest(request FakeMixRequest) error {
	if strings.TrimSpace(request.StrategyID) == "" || request.Profile.Profile.ID == "" {
		return ErrFakeMixInvalid
	}
	if request.Mode != FakeMixSplit && request.Mode != FakeMixDisorder {
		return fmt.Errorf("%w: mode %q", ErrFakeMixInvalid, request.Mode)
	}
	if request.Order != FakeThenReal && request.Order != RealThenFake {
		return ErrHostFakeOrder
	}
	if request.MinConfidence == 0 || request.Confidence < request.MinConfidence {
		return fmt.Errorf("%w: confidence=%d minimum=%d", ErrFakeMixPrecondition, request.Confidence, request.MinConfidence)
	}
	if strings.TrimSpace(request.TCPPhase) == "" || !containsString(request.AllowedTCPPhases, request.TCPPhase) {
		return fmt.Errorf("%w: TCP FSM phase %q is not allowed", ErrFakeMixPrecondition, request.TCPPhase)
	}
	if request.Real.ProcessedMark == 0 || len(request.Real.Payload) == 0 {
		return ErrInvalidPacket
	}
	if !request.Real.Markers.Complete || request.Real.Markers.ECH || !request.Real.Markers.HostMarkersAvailable() {
		return fmt.Errorf("%w: complete clear-SNI host markers are required", ErrFakeMixPrecondition)
	}
	if len(request.RealPositions) == 0 {
		return fmt.Errorf("%w: real split positions are required", ErrFakeMixInvalid)
	}
	if request.Mode == FakeMixSplit && request.FakeSegmentOrder != "" && request.FakeSegmentOrder != OrderForward {
		return fmt.Errorf("%w: fakedsplit requires forward fake segments", ErrFakeMixInvalid)
	}
	if request.Mode == FakeMixDisorder && request.FakeSegmentOrder == OrderForward {
		return fmt.Errorf("%w: fakeddisorder requires non-forward fake segments", ErrFakeMixInvalid)
	}
	return nil
}

func fakeSegmentOrder(request FakeMixRequest) ([]int, error) {
	order := request.FakeSegmentOrder
	if order == "" {
		order = OrderForward
	}
	return resolveSegmentOrder(StrategyDefinition{SegmentOrder: order, CustomOrder: request.FakeCustomOrder}, resolveFakeOffsets(request.FakePositions))
}

// resolveFakeOffsets is only used for segment-count validation. Actual
// offsets are resolved and validated against the profile before this helper
// is called; preserving the count here avoids trusting caller ordering.
func resolveFakeOffsets(positions []SplitPositionSpec) []uint64 {
	offsets := make([]uint64, len(positions))
	for i := range offsets {
		offsets[i] = uint64(i + 1)
	}
	return offsets
}
