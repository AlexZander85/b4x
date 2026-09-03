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

type FakeRealOrder string

const (
	FakeThenReal FakeRealOrder = "fake-then-real"
	RealThenFake FakeRealOrder = "real-then-fake"
)

type HostFakeSplitRequest struct {
	StrategyID       string
	Real             PlanInput
	RealPositions    []SplitPositionSpec
	FakePositions    []SplitPositionSpec
	Profile          lab.CompiledArtifact
	Confidence       uint8
	MinConfidence    uint8
	TCPPhase         string
	AllowedTCPPhases []string
	Order            FakeRealOrder
	Budgets          ActionBudgets
	FlowHash         uint64
	ClientHelloID    uint64
	ConfigGen        uint64
	Tokens           *ActionTokenStore
}

type FakeWriteKind string

const (
	FakeWrite FakeWriteKind = "fake"
	RealWrite FakeWriteKind = "real"
)

type HostFakeWrite struct {
	Kind FakeWriteKind
	PlannedWrite
	EndpointVisible bool
	ProcessedMark   uint32
}

type HostFakeSplitPlan struct {
	Valid           bool
	DryRun          bool
	StrategyID      string
	ProfileID       string
	Order           FakeRealOrder
	FakeWrites      []HostFakeWrite
	RealWrites      []HostFakeWrite
	Writes          []HostFakeWrite
	EndpointPayload []byte
	EndpointSHA256  string
	TotalBytes      int
	GeneratedBytes  int
	Token           ActionTokenResult
	Reason          string
}

var (
	ErrHostFakeInvalid      = errors.New("invalid hostfakesplit request")
	ErrHostFakePrecondition = errors.New("hostfakesplit precondition failed")
	ErrHostFakeProfile      = errors.New("hostfakesplit profile is invalid")
	ErrHostFakeOrder        = errors.New("hostfakesplit fake/real order is required")
)

// PlanHostFakeSplit creates explicit fake and real write intents. Fake writes
// are marked endpoint-invisible; the endpoint stream is always copied from
// the original clear ClientHello, never from the fake profile. The function
// does not send packets and has no default strategy selection.
func PlanHostFakeSplit(request HostFakeSplitRequest) (HostFakeSplitPlan, error) {
	plan := HostFakeSplitPlan{DryRun: request.Real.DryRun, StrategyID: request.StrategyID, ProfileID: request.Profile.Profile.ID, Order: request.Order}
	if err := validateHostFakeRequest(request); err != nil {
		return plan, err
	}
	if err := request.Profile.Validate(); err != nil {
		return plan, fmt.Errorf("%w: %v", ErrHostFakeProfile, err)
	}
	realMeta := sni.ParseTLSClientHelloMetadata(request.Real.Payload)
	fakeMeta := sni.ParseTLSClientHelloMetadata(request.Profile.Bytes())
	if !realMeta.Complete || realMeta.ParseError != "" || realMeta.SNI == "" || !fakeMeta.Complete || fakeMeta.ParseError != "" || fakeMeta.SNI == "" {
		return plan, ErrHostFakeProfile
	}
	if !strings.EqualFold(realMeta.SNI, request.Real.Markers.Host) {
		return plan, fmt.Errorf("%w: reassembled SNI does not match host marker", ErrHostFakePrecondition)
	}
	if strings.EqualFold(realMeta.SNI, fakeMeta.SNI) {
		return plan, fmt.Errorf("%w: fake profile did not structurally replace SNI", ErrHostFakeProfile)
	}

	realOffsets, err := resolveStrategyOffsets(request.RealPositions, request.Real.Markers, len(request.Real.Payload))
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
	fakeOffsets, err := resolveAbsoluteOnlyPositions(request.FakePositions, len(request.Profile.Bytes()))
	if err != nil {
		return plan, err
	}
	fakeInput := PlanInput{
		BaseSequence:   request.Real.BaseSequence,
		Payload:        request.Profile.Bytes(),
		SplitPositions: splitPositionsFromOffsets(fakeOffsets),
		MTU:            request.Real.MTU,
		IPHeaderLen:    request.Real.IPHeaderLen,
		TCPHeaderLen:   request.Real.TCPHeaderLen,
		ProcessedMark:  request.Real.ProcessedMark,
		MaxWrites:      request.Real.MaxWrites,
		MaxBytes:       request.Real.MaxBytes,
		DryRun:         true,
	}
	fakePlan, err := Plan(fakeInput)
	if err != nil {
		return plan, err
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
	plan.TotalBytes = realPlan.TotalBytes
	plan.GeneratedBytes = len(request.Profile.Bytes())
	plan.Reason = "confidence-gated hostfakesplit plan preserves original endpoint stream"
	plan.Valid = true
	if request.Real.DryRun {
		return plan, nil
	}
	if realRetransmission && request.Tokens == nil {
		return plan, ErrStrategyTokenRequired
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
	if token.Suppressed {
		return plan, ErrRetransmission
	}
	if realRetransmission {
		return plan, ErrRetransmission
	}
	return plan, nil
}

func validateHostFakeRequest(request HostFakeSplitRequest) error {
	if strings.TrimSpace(request.StrategyID) == "" || request.Profile.Profile.ID == "" {
		return ErrHostFakeInvalid
	}
	if request.Order != FakeThenReal && request.Order != RealThenFake {
		return ErrHostFakeOrder
	}
	if request.MinConfidence == 0 || request.Confidence < request.MinConfidence {
		return fmt.Errorf("%w: confidence=%d minimum=%d", ErrHostFakePrecondition, request.Confidence, request.MinConfidence)
	}
	if strings.TrimSpace(request.TCPPhase) == "" || !containsString(request.AllowedTCPPhases, request.TCPPhase) {
		return fmt.Errorf("%w: TCP FSM phase %q is not allowed", ErrHostFakePrecondition, request.TCPPhase)
	}
	if request.Real.ProcessedMark == 0 || len(request.Real.Payload) == 0 {
		return ErrInvalidPacket
	}
	if !request.Real.Markers.Complete || request.Real.Markers.ECH || !request.Real.Markers.HostMarkersAvailable() {
		return fmt.Errorf("%w: complete clear SNI host markers are required", ErrHostFakePrecondition)
	}
	if len(request.RealPositions) == 0 {
		return fmt.Errorf("%w: real split positions must be explicit", ErrHostFakeInvalid)
	}
	return nil
}

func resolveAbsoluteOnlyPositions(positions []SplitPositionSpec, payloadLength int) ([]uint64, error) {
	for _, position := range positions {
		if position.Absolute == nil || position.Marker != "" {
			return nil, fmt.Errorf("%w: fake positions must be absolute", ErrHostFakeInvalid)
		}
	}
	return resolveStrategyOffsets(positions, MarkerSet{}, payloadLength)
}

func splitPositionsFromOffsets(offsets []uint64) []SplitPosition {
	result := make([]SplitPosition, len(offsets))
	for i, offset := range offsets {
		result[i] = SplitPosition{Offset: offset, Reason: "explicit hostfakesplit position"}
	}
	return result
}

func hostFakeWrites(kind FakeWriteKind, writes []PlannedWrite, processedMark uint32, endpointVisible bool) []HostFakeWrite {
	result := make([]HostFakeWrite, len(writes))
	for i, write := range writes {
		write.Payload = append([]byte(nil), write.Payload...)
		result[i] = HostFakeWrite{Kind: kind, PlannedWrite: write, EndpointVisible: endpointVisible, ProcessedMark: processedMark}
	}
	return result
}

func orderedHostFakeWrites(fake, real []HostFakeWrite, order FakeRealOrder) []HostFakeWrite {
	result := make([]HostFakeWrite, 0, len(fake)+len(real))
	if order == FakeThenReal {
		result = append(result, fake...)
		result = append(result, real...)
	} else {
		result = append(result, real...)
		result = append(result, fake...)
	}
	for i := range result {
		result[i].Order = i
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
