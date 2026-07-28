package action

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/daniellavrushin/b4/sni"
)

const maxTLSRecordSplitRecords = 16

type tlsRecordSpan struct {
	Start uint64
	End   uint64
	Type  byte
}

var (
	ErrTLSRecordSplitInvalid   = errors.New("invalid TLS record split request")
	ErrTLSRecordSplitMalformed = errors.New("malformed TLS record stream")
	ErrTLSRecordSplitBoundary  = errors.New("TLS record split boundary is outside ClientHello")
)

// TLSRecordSplitRequest is a separate technique from generic multisplit. It
// validates the TLS record envelope, then permits only semantic marker
// offsets within the first complete ClientHello. Payload bytes and all
// records after ClientHello remain byte-for-byte unchanged.
type TLSRecordSplitRequest struct {
	Enabled       bool
	StrategyID    string
	Input         PlanInput
	Positions     []SplitPositionSpec
	Preconditions StrategyPreconditions
	Budgets       ActionBudgets
	Confidence    uint8
	TCPPhase      string
	FlowHash      uint64
	ClientHelloID uint64
	ConfigGen     uint64
	Tokens        *ActionTokenStore
}

type TLSRecordSplitPlan struct {
	Valid            bool
	DryRun           bool
	StrategyID       string
	Technique        Technique
	ActionPlan       ActionPlan
	ResolvedOffsets  []uint64
	ClientHelloStart uint64
	ClientHelloEnd   uint64
	FirstRecordEnd   uint64
	RecordCount      int
	TrailingBytes    int
	Token            ActionTokenResult
	Reason           string
}

// PlanTLSRecordSplit creates a stream-offset action plan without editing TLS
// bytes. The caller must opt in through Enabled and FirstFlightOnly; all
// failures are returned before any sender can be reached.
func PlanTLSRecordSplit(request TLSRecordSplitRequest) (TLSRecordSplitPlan, error) {
	plan := TLSRecordSplitPlan{DryRun: request.Input.DryRun, StrategyID: request.StrategyID, Technique: TechniqueTLSRecordSplit}
	if !request.Enabled {
		return plan, ErrTechniqueDisabled
	}
	if err := validateTLSRecordSplitRequest(request); err != nil {
		return plan, err
	}
	records, helloEnd, err := inspectTLSRecordStream(request.Input.Payload)
	if err != nil {
		return plan, err
	}
	if err := checkStrategyPreconditions(StrategyRequest{
		Input: request.Input, Confidence: request.Confidence, TCPPhase: request.TCPPhase,
		CompleteClientHello: request.Input.Markers.Complete,
		Definition:          StrategyDefinition{Preconditions: request.Preconditions},
	}); err != nil {
		return plan, err
	}
	if len(records) == 0 {
		return plan, ErrTLSRecordSplitMalformed
	}
	first := records[0]
	plan.ClientHelloStart = first.Start
	plan.ClientHelloEnd = helloEnd
	plan.FirstRecordEnd = first.End
	plan.RecordCount = len(records)
	plan.TrailingBytes = len(request.Input.Payload) - int(helloEnd)

	if !request.Input.Markers.Complete {
		return plan, fmt.Errorf("%w: complete reassembled markers are required", ErrTLSRecordSplitInvalid)
	}
	startMarker, startOK := request.Input.Markers.Find(MarkerClientHelloStart)
	endMarker, endOK := request.Input.Markers.Find(MarkerClientHelloEnd)
	if !startOK || startMarker.Offset != first.Start || !endOK || endMarker.Offset != helloEnd {
		return plan, fmt.Errorf("%w: ClientHello markers do not match record parser", ErrTLSRecordSplitInvalid)
	}
	if len(request.Positions) == 0 || len(request.Positions) > 8 {
		return plan, fmt.Errorf("%w: 1..8 marker positions are required", ErrTLSRecordSplitInvalid)
	}
	offsets, err := resolveTLSRecordSplitOffsets(request.Positions, request.Input.Markers, helloEnd, uint64(len(request.Input.Payload)))
	if err != nil {
		return plan, err
	}
	input := request.Input
	retransmission := input.Retransmission
	input.Retransmission = false
	input.SplitPositions = splitPositionsFromOffsets(offsets)
	basePlan, err := Plan(input)
	if err != nil {
		return plan, err
	}
	basePlan.StrategyID = request.StrategyID
	if err := request.Budgets.Check(len(input.Payload), len(basePlan.Writes), 0); err != nil {
		return plan, err
	}
	plan.ActionPlan = basePlan
	plan.ResolvedOffsets = append([]uint64(nil), offsets...)
	plan.Valid = true
	plan.Reason = "validated TLS ClientHello marker split preserves all record bytes"
	if input.DryRun {
		return plan, nil
	}
	if request.Tokens == nil {
		return plan, ErrStrategyTokenRequired
	}
	token := request.Tokens.Claim(ActionTokenRequest{
		FlowHash: request.FlowHash, ClientHelloID: request.ClientHelloID, StrategyID: request.StrategyID,
		ConfigGen: request.ConfigGen, StreamStart: first.Start, StreamEnd: helloEnd,
		InputBytes: len(input.Payload), Writes: len(basePlan.Writes), GeneratedBytes: 0,
		ProcessedMark: input.ProcessedMark,
	})
	plan.Token = token
	if token.Suppressed || retransmission {
		return plan, ErrRetransmission
	}
	return plan, nil
}

func validateTLSRecordSplitRequest(request TLSRecordSplitRequest) error {
	if strings.TrimSpace(request.StrategyID) == "" || request.Input.ProcessedMark == 0 || len(request.Input.Payload) == 0 {
		return ErrTLSRecordSplitInvalid
	}
	if request.Confidence < request.Preconditions.MinConfidence || request.Preconditions.MinConfidence == 0 {
		return fmt.Errorf("%w: high-confidence precondition failed", ErrTLSRecordSplitInvalid)
	}
	if !request.Preconditions.FirstFlightOnly {
		return fmt.Errorf("%w: first-flight-only precondition is required", ErrTLSRecordSplitInvalid)
	}
	if strings.TrimSpace(request.TCPPhase) == "" || !containsString(request.Preconditions.AllowedTCPPhases, request.TCPPhase) {
		return fmt.Errorf("%w: TCP FSM phase %q is not allowed", ErrTLSRecordSplitInvalid, request.TCPPhase)
	}
	return nil
}

func resolveTLSRecordSplitOffsets(positions []SplitPositionSpec, markers MarkerSet, helloEnd, payloadEnd uint64) ([]uint64, error) {
	offsets := make([]uint64, 0, len(positions))
	for _, position := range positions {
		if position.Absolute != nil || position.Marker == "" {
			return nil, fmt.Errorf("%w: marker-only boundaries are required", ErrTLSRecordSplitInvalid)
		}
		marker, ok := markers.Find(position.Marker)
		if !ok || !marker.Available {
			return nil, fmt.Errorf("%w: marker %q is unavailable", ErrMarkerUnavailable, position.Marker)
		}
		offset := int64(marker.Offset) + int64(position.Delta)
		if offset <= 0 || uint64(offset) >= payloadEnd || uint64(offset) > helloEnd {
			return nil, ErrTLSRecordSplitBoundary
		}
		offsets = append(offsets, uint64(offset))
	}
	for i := 1; i < len(offsets); i++ {
		if offsets[i] <= offsets[i-1] {
			return nil, ErrInvalidStreamRange
		}
	}
	return offsets, nil
}

// inspectTLSRecordStream validates every record envelope but intentionally
// does not inspect or rewrite records after the first complete ClientHello.
func inspectTLSRecordStream(payload []byte) ([]tlsRecordSpan, uint64, error) {
	if len(payload) == 0 || len(payload) > sni.TLSClientHelloMetadataMaxBytes {
		return nil, 0, ErrTLSRecordSplitMalformed
	}
	records := make([]tlsRecordSpan, 0, 4)
	for offset := 0; offset < len(payload); {
		if len(records) >= maxTLSRecordSplitRecords || offset+5 > len(payload) {
			return nil, 0, ErrTLSRecordSplitMalformed
		}
		length := int(binary.BigEndian.Uint16(payload[offset+3 : offset+5]))
		version := binary.BigEndian.Uint16(payload[offset+1 : offset+3])
		contentType := payload[offset]
		if contentType < 0x14 || contentType > 0x17 || version < 0x0300 || version > 0x0304 || length <= 0 || length > 16384 || offset+5+length > len(payload) {
			return nil, 0, ErrTLSRecordSplitMalformed
		}
		records = append(records, tlsRecordSpan{Start: uint64(offset), End: uint64(offset + 5 + length), Type: payload[offset]})
		offset += 5 + length
	}
	first := records[0]
	if first.Type != 0x16 || first.End-first.Start < 9 {
		return nil, 0, ErrTLSRecordSplitMalformed
	}
	firstPayload := payload[first.Start+5 : first.End]
	if firstPayload[0] != 1 {
		return nil, 0, ErrTLSRecordSplitMalformed
	}
	helloLength := int(firstPayload[1])<<16 | int(firstPayload[2])<<8 | int(firstPayload[3])
	helloEnd := first.Start + 9 + uint64(helloLength)
	if helloEnd > first.End || helloEnd > uint64(len(payload)) {
		return nil, 0, ErrTLSRecordSplitMalformed
	}
	return records, helloEnd, nil
}
