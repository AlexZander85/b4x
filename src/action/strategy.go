package action

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Technique string

const (
	TechniqueMultiSplit     Technique = "multisplit"
	TechniqueMultiDisorder  Technique = "multidisorder"
	TechniqueFakeSplit      Technique = "fakedsplit"
	TechniqueFakeDisorder   Technique = "fakeddisorder"
	TechniqueTLSRecordSplit Technique = "tls-record-split"
)

type SegmentOrder string

const (
	OrderForward SegmentOrder = "forward"
	OrderReverse SegmentOrder = "reverse"
	OrderCustom  SegmentOrder = "custom"
)

type SplitPositionSpec struct {
	Absolute *uint64           `json:"absolute,omitempty"`
	Marker   LogicalMarkerKind `json:"marker,omitempty"`
	Delta    int32             `json:"delta,omitempty"`
}

type StrategyPreconditions struct {
	MinConfidence      uint8    `json:"min_confidence"`
	RequiresClearSNI   bool     `json:"requires_clear_sni"`
	RequiresCompleteCH bool     `json:"requires_complete_clienthello"`
	AllowedTCPPhases   []string `json:"allowed_tcp_phases,omitempty"`
	FirstFlightOnly    bool     `json:"first_flight_only"`
	ECHAllowed         bool     `json:"ech_allowed"`
}

type StrategyDefinition struct {
	ID            string                `json:"id"`
	Technique     Technique             `json:"technique"`
	Positions     []SplitPositionSpec   `json:"positions"`
	SegmentOrder  SegmentOrder          `json:"segment_order"`
	CustomOrder   []int                 `json:"custom_order,omitempty"`
	Preconditions StrategyPreconditions `json:"preconditions"`
	Budgets       ActionBudgets         `json:"budgets"`
}

type StrategyRequest struct {
	Input               PlanInput
	Definition          StrategyDefinition
	Confidence          uint8
	TCPPhase            string
	CompleteClientHello bool
	FlowHash            uint64
	ClientHelloID       uint64
	ConfigGen           uint64
	Tokens              *ActionTokenStore
}

type StrategyPlan struct {
	ActionPlan      ActionPlan
	StrategyID      string
	Technique       Technique
	ResolvedOffsets []uint64
	Order           []int
	Token           ActionTokenResult
	DryRun          bool
	Reason          string
}

var (
	ErrStrategyInvalid       = errors.New("invalid strategy definition")
	ErrStrategyPrecondition  = errors.New("strategy precondition failed")
	ErrStrategyOrder         = errors.New("invalid strategy segment order")
	ErrStrategyTokenRequired = errors.New("first-flight strategy requires an action token store")
)

// PlanStrategy resolves a bounded semantic strategy into stream-offset writes.
// It never invents host markers: ECH and incomplete ClientHello inputs fail
// closed for strategies that declare clear-SNI/complete-hello preconditions.
func PlanStrategy(request StrategyRequest) (StrategyPlan, error) {
	definition := request.Definition
	plan := StrategyPlan{StrategyID: definition.ID, Technique: definition.Technique, DryRun: request.Input.DryRun}
	if err := validateStrategyDefinition(definition); err != nil {
		return plan, err
	}
	if err := checkStrategyPreconditions(request); err != nil {
		return plan, err
	}
	offsets, err := resolveStrategyOffsets(definition.Positions, request.Input.Markers, len(request.Input.Payload))
	if err != nil {
		return plan, err
	}
	input := request.Input
	retransmission := input.Retransmission
	// Plan builds the canonical stream map for a retransmission as well; the
	// token claim below is what suppresses the action without losing the
	// diagnostic dry-run shape.
	input.Retransmission = false
	input.SplitPositions = make([]SplitPosition, len(offsets))
	for i, offset := range offsets {
		input.SplitPositions[i] = SplitPosition{Offset: offset, Reason: "strategy position"}
	}
	input.MaxWrites = boundedMaxWrites(input.MaxWrites, definition.Budgets)
	basePlan, err := Plan(input)
	if err != nil {
		return plan, err
	}
	basePlan.StrategyID = definition.ID
	order, err := resolveSegmentOrder(definition, offsets)
	if err != nil {
		return plan, err
	}
	basePlan.Writes = reorderWrites(basePlan.Writes, order, offsets)
	for i := range basePlan.Writes {
		basePlan.Writes[i].Order = i
	}
	if err := definition.Budgets.Check(len(input.Payload), len(basePlan.Writes), 0); err != nil {
		return plan, err
	}

	plan.ActionPlan = basePlan
	plan.ResolvedOffsets = append([]uint64(nil), offsets...)
	plan.Order = append([]int(nil), order...)
	plan.Reason = "bounded stream-preserving strategy plan is valid"
	if request.Input.DryRun {
		return plan, nil
	}
	if retransmission && request.Tokens == nil {
		return plan, ErrRetransmission
	}
	if definition.Preconditions.FirstFlightOnly && request.Tokens == nil {
		return plan, ErrStrategyTokenRequired
	}
	if request.Tokens != nil {
		token := request.Tokens.Claim(ActionTokenRequest{
			FlowHash: request.FlowHash, ClientHelloID: request.ClientHelloID, StrategyID: definition.ID,
			ConfigGen: request.ConfigGen, StreamStart: 0, StreamEnd: uint64(len(input.Payload)),
			InputBytes: len(input.Payload), Writes: len(basePlan.Writes), GeneratedBytes: 0,
			ProcessedMark: input.ProcessedMark,
		})
		plan.Token = token
		if token.Suppressed {
			return plan, ErrRetransmission
		}
	}
	if retransmission {
		return plan, ErrRetransmission
	}
	return plan, nil
}

func validateStrategyDefinition(definition StrategyDefinition) error {
	if strings.TrimSpace(definition.ID) == "" {
		return ErrStrategyInvalid
	}
	if definition.Technique != TechniqueMultiSplit && definition.Technique != TechniqueMultiDisorder {
		return fmt.Errorf("%w: unsupported technique %q", ErrStrategyInvalid, definition.Technique)
	}
	if len(definition.Positions) == 0 || len(definition.Positions) > 8 {
		return fmt.Errorf("%w: positions must contain 1..8 entries", ErrStrategyInvalid)
	}
	if definition.SegmentOrder == "" {
		definition.SegmentOrder = OrderForward
	}
	if definition.SegmentOrder != OrderForward && definition.SegmentOrder != OrderReverse && definition.SegmentOrder != OrderCustom {
		return fmt.Errorf("%w: unsupported segment order %q", ErrStrategyInvalid, definition.SegmentOrder)
	}
	for _, position := range definition.Positions {
		if position.Absolute == nil && position.Marker == "" {
			return fmt.Errorf("%w: position needs absolute or marker", ErrStrategyInvalid)
		}
		if position.Absolute != nil && position.Marker != "" {
			return fmt.Errorf("%w: position cannot have both absolute and marker", ErrStrategyInvalid)
		}
	}
	return nil
}

func checkStrategyPreconditions(request StrategyRequest) error {
	preconditions := request.Definition.Preconditions
	if request.Confidence < preconditions.MinConfidence {
		return fmt.Errorf("%w: confidence=%d minimum=%d", ErrStrategyPrecondition, request.Confidence, preconditions.MinConfidence)
	}
	if preconditions.RequiresCompleteCH && (!request.CompleteClientHello || !request.Input.Markers.Complete) {
		return fmt.Errorf("%w: complete ClientHello is required", ErrStrategyPrecondition)
	}
	if request.Input.Markers.ECH && !preconditions.ECHAllowed {
		return fmt.Errorf("%w: ECH is not allowed", ErrStrategyPrecondition)
	}
	if preconditions.RequiresClearSNI && (request.Input.Markers.ECH || request.Input.Markers.Host == "") {
		return fmt.Errorf("%w: clear SNI is required", ErrStrategyPrecondition)
	}
	if len(preconditions.AllowedTCPPhases) > 0 {
		allowed := false
		for _, phase := range preconditions.AllowedTCPPhases {
			if phase == request.TCPPhase {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: TCP phase %q is not allowed", ErrStrategyPrecondition, request.TCPPhase)
		}
	}
	return nil
}

func resolveStrategyOffsets(positions []SplitPositionSpec, markers MarkerSet, payloadLength int) ([]uint64, error) {
	offsets := make([]uint64, 0, len(positions))
	for _, position := range positions {
		var offset int64
		if position.Absolute != nil {
			offset = int64(*position.Absolute)
		} else {
			marker, ok := markers.Find(position.Marker)
			if !ok || !marker.Available {
				return nil, fmt.Errorf("%w: marker %q is unavailable", ErrMarkerUnavailable, position.Marker)
			}
			offset = int64(marker.Offset) + int64(position.Delta)
		}
		if offset <= 0 || offset >= int64(payloadLength) {
			return nil, ErrInvalidStreamRange
		}
		offsets = append(offsets, uint64(offset))
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	for i := 1; i < len(offsets); i++ {
		if offsets[i] == offsets[i-1] {
			return nil, ErrInvalidStreamRange
		}
	}
	return offsets, nil
}

func resolveSegmentOrder(definition StrategyDefinition, offsets []uint64) ([]int, error) {
	segmentCount := len(offsets) + 1
	order := make([]int, 0, segmentCount)
	switch definition.SegmentOrder {
	case "", OrderForward:
		for i := 0; i < segmentCount; i++ {
			order = append(order, i)
		}
	case OrderReverse:
		for i := segmentCount - 1; i >= 0; i-- {
			order = append(order, i)
		}
	case OrderCustom:
		if len(definition.CustomOrder) != segmentCount {
			return nil, ErrStrategyOrder
		}
		seen := make(map[int]struct{}, segmentCount)
		for _, index := range definition.CustomOrder {
			if index < 0 || index >= segmentCount {
				return nil, ErrStrategyOrder
			}
			if _, exists := seen[index]; exists {
				return nil, ErrStrategyOrder
			}
			seen[index] = struct{}{}
			order = append(order, index)
		}
	}
	return order, nil
}

func reorderWrites(writes []PlannedWrite, order []int, offsets []uint64) []PlannedWrite {
	segmentWrites := make([][]PlannedWrite, len(offsets)+1)
	for _, write := range writes {
		segment := sort.Search(len(offsets), func(i int) bool { return write.StreamStart < offsets[i] })
		segmentWrites[segment] = append(segmentWrites[segment], write)
	}
	result := make([]PlannedWrite, 0, len(writes))
	for _, segment := range order {
		result = append(result, segmentWrites[segment]...)
	}
	return result
}

func boundedMaxWrites(requested int, budgets ActionBudgets) int {
	if requested > 0 {
		return requested
	}
	if budgets.MaxWritesPerHello > 0 {
		return int(budgets.MaxWritesPerHello)
	}
	return int(DefaultActionBudgets().MaxWritesPerHello)
}

// InitialMarkerStrategyCatalog is intentionally read-only. Callers must
// select a definition explicitly and still pass all preconditions/token/budget
// checks through PlanStrategy; no catalog item is auto-activated.
func InitialMarkerStrategyCatalog() []StrategyDefinition {
	clearFirstFlight := StrategyPreconditions{MinConfidence: 80, RequiresClearSNI: true, RequiresCompleteCH: true, FirstFlightOnly: true}
	absolute := func(offset uint64) SplitPositionSpec { return SplitPositionSpec{Absolute: &offset} }
	marker := func(kind LogicalMarkerKind) SplitPositionSpec { return SplitPositionSpec{Marker: kind} }
	return []StrategyDefinition{
		{ID: "marker-split-at-1", Technique: TechniqueMultiSplit, Positions: []SplitPositionSpec{absolute(1)}, SegmentOrder: OrderForward, Preconditions: clearFirstFlight, Budgets: DefaultActionBudgets()},
		{ID: "marker-around-sni", Technique: TechniqueMultiSplit, Positions: []SplitPositionSpec{marker(MarkerSNIExtensionStart)}, SegmentOrder: OrderForward, Preconditions: clearFirstFlight, Budgets: DefaultActionBudgets()},
		{ID: "marker-host-start-end", Technique: TechniqueMultiSplit, Positions: []SplitPositionSpec{marker(MarkerHostStart), marker(MarkerHostEnd)}, SegmentOrder: OrderForward, Preconditions: clearFirstFlight, Budgets: DefaultActionBudgets()},
		{ID: "marker-sld-middle", Technique: TechniqueMultiSplit, Positions: []SplitPositionSpec{marker(MarkerSLDMiddle)}, SegmentOrder: OrderForward, Preconditions: clearFirstFlight, Budgets: DefaultActionBudgets()},
		{ID: "marker-small-reverse", Technique: TechniqueMultiDisorder, Positions: []SplitPositionSpec{absolute(1), marker(MarkerHostStart)}, SegmentOrder: OrderReverse, Preconditions: clearFirstFlight, Budgets: DefaultActionBudgets()},
	}
}
