package action

import (
	"strconv"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/observability"
)

type PacketRepresentation uint8

const (
	RepresentationAny PacketRepresentation = iota
	RepresentationNormalTCP
	RepresentationGSOSafe
)

type SplitPosition struct {
	Offset uint64
	Reason string
}

type PlannedWrite struct {
	StreamStart uint64
	StreamEnd   uint64
	Sequence    uint32
	Payload     []byte
	Delay       time.Duration
	Order       int
}

type PlanInput struct {
	BaseSequence         uint32
	Payload              []byte
	SplitPositions       []SplitPosition
	Markers              MarkerSet
	MTU                  int
	IPHeaderLen          int
	TCPHeaderLen         int
	ProcessedMark        uint32
	MaxWrites            int
	MaxBytes             int
	DryRun               bool
	Retransmission       bool
	RequireHostMarkers   bool
	RequireAuthorization bool
	Authorization        *classifier.ActionAuthorization
	FlowKey              classifier.FlowKey
	Client               classifier.ClientKey
	SetID                string
	ConfigGen            uint64
	DestinationPort      uint16
	L4Proto              uint8
}

type ActionPlan struct {
	Valid                bool
	Representation       PacketRepresentation
	DryRun               bool
	StrategyID           string
	ProcessedMark        uint32
	HostMarkersAvailable bool
	Writes               []PlannedWrite
	TotalBytes           int
	Reason               string
}

func Plan(input PlanInput) (ActionPlan, error) {
	plan := ActionPlan{DryRun: input.DryRun, Representation: RepresentationNormalTCP, ProcessedMark: input.ProcessedMark, HostMarkersAvailable: input.Markers.HostMarkersAvailable(), Writes: make([]PlannedWrite, 0)}
	if input.Retransmission {
		return plan, ErrRetransmission
	}
	if input.RequireAuthorization {
		if input.Authorization == nil || !input.Authorization.ValidFor(input.FlowKey, input.Client, input.SetID, input.ConfigGen, input.DestinationPort, input.L4Proto, time.Now()) {
			plan.Reason = "missing or invalid action authorization"
			return plan, ErrAuthorizationRequired
		}
	}
	if input.ProcessedMark == 0 {
		return plan, ErrInvalidPacket
	}
	if len(input.Payload) == 0 {
		return plan, ErrInvalidStreamRange
	}
	if input.MTU <= 0 || input.IPHeaderLen < 20 || input.TCPHeaderLen < 20 || input.MTU <= input.IPHeaderLen+input.TCPHeaderLen {
		return plan, ErrMTU
	}
	if input.RequireHostMarkers && !plan.HostMarkersAvailable {
		return plan, ErrMarkerUnavailable
	}
	maxWrites := input.MaxWrites
	if maxWrites <= 0 {
		maxWrites = 16
	}
	maxBytes := input.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	positions := make([]uint64, 0, len(input.SplitPositions)+2)
	positions = append(positions, 0)
	for _, split := range input.SplitPositions {
		if split.Offset == 0 || split.Offset >= uint64(len(input.Payload)) {
			return plan, ErrInvalidStreamRange
		}
		if split.Offset <= positions[len(positions)-1] {
			return plan, ErrInvalidStreamRange
		}
		positions = append(positions, split.Offset)
	}
	positions = append(positions, uint64(len(input.Payload)))
	maxPayload := input.MTU - input.IPHeaderLen - input.TCPHeaderLen
	for i := 0; i+1 < len(positions); i++ {
		start, end := positions[i], positions[i+1]
		for start < end {
			chunkEnd := end
			if chunkEnd-start > uint64(maxPayload) {
				chunkEnd = start + uint64(maxPayload)
			}
			if len(plan.Writes) >= maxWrites || plan.TotalBytes+int(chunkEnd-start) > maxBytes {
				return ActionPlan{}, ErrPlanBudget
			}
			sequence := input.BaseSequence + uint32(start)
			payload := append([]byte(nil), input.Payload[start:chunkEnd]...)
			plan.Writes = append(plan.Writes, PlannedWrite{StreamStart: start, StreamEnd: chunkEnd, Sequence: sequence, Payload: payload, Order: len(plan.Writes)})
			plan.TotalBytes += len(payload)
			start = chunkEnd
		}
	}
	plan.Valid = true
	plan.Reason = "stream-offset action plan is valid"
	observability.Default().Metrics.Inc(observability.MetricTCPActionPlanned, map[string]string{"dry_run": strconv.FormatBool(plan.DryRun)}, 1)
	return plan, nil
}
