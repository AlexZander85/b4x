package action

import (
	"errors"
	"fmt"
)

var ErrClientHelloPadding = errors.New("invalid bounded ClientHello padding")

// ApplyClientHelloPadding adds bounded same-sequence prefix/suffix writes from
// the first complete ClientHello. The extra writes contain only bytes already
// present at the exact same stream offsets, so they can change the observed
// packet layout without changing the endpoint-visible logical byte stream.
// It is a pure ActionPlan transform and never sends packets itself.
func ApplyClientHelloPadding(plan ActionPlan, input PlanInput, preBytes, postBytes int) (ActionPlan, int, error) {
	if !plan.Valid || !input.Markers.Complete || len(input.Payload) == 0 {
		return ActionPlan{}, 0, ErrClientHelloPadding
	}
	if !validPaddingBytes(preBytes) || !validPaddingBytes(postBytes) || (preBytes == 0 && postBytes == 0) {
		return ActionPlan{}, 0, ErrClientHelloPadding
	}
	start, startOK := input.Markers.Find(MarkerClientHelloStart)
	end, endOK := input.Markers.Find(MarkerClientHelloEnd)
	if !startOK || !endOK || end.Offset <= start.Offset || end.Offset > uint64(len(input.Payload)) {
		return ActionPlan{}, 0, fmt.Errorf("%w: complete first ClientHello markers required", ErrClientHelloPadding)
	}
	helloLen := int(end.Offset - start.Offset)
	if preBytes > helloLen || postBytes > helloLen {
		return ActionPlan{}, 0, fmt.Errorf("%w: padding exceeds first ClientHello", ErrClientHelloPadding)
	}

	extraWrites := 0
	generated := preBytes + postBytes
	if preBytes > 0 {
		extraWrites++
	}
	if postBytes > 0 {
		extraWrites++
	}
	maxWrites := input.MaxWrites
	if maxWrites <= 0 {
		maxWrites = 16
	}
	if len(plan.Writes)+extraWrites > maxWrites {
		return ActionPlan{}, 0, ErrPlanBudget
	}
	maxBytes := input.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	if plan.TotalBytes+generated > maxBytes {
		return ActionPlan{}, 0, ErrPlanBudget
	}

	writes := make([]PlannedWrite, 0, len(plan.Writes)+extraWrites)
	if preBytes > 0 {
		from := start.Offset
		to := from + uint64(preBytes)
		writes = append(writes, PlannedWrite{
			StreamStart: from,
			StreamEnd:   to,
			Sequence:    input.BaseSequence + uint32(from),
			Payload:     append([]byte(nil), input.Payload[from:to]...),
		})
	}
	writes = append(writes, clonePlannedWrites(plan.Writes)...)
	if postBytes > 0 {
		to := end.Offset
		from := to - uint64(postBytes)
		writes = append(writes, PlannedWrite{
			StreamStart: from,
			StreamEnd:   to,
			Sequence:    input.BaseSequence + uint32(from),
			Payload:     append([]byte(nil), input.Payload[from:to]...),
		})
	}
	for i := range writes {
		writes[i].Order = i
	}
	plan.Writes = writes
	plan.TotalBytes += generated
	plan.Reason = "bounded same-sequence ClientHello padding preserves endpoint stream"
	return plan, generated, nil
}

func validPaddingBytes(value int) bool {
	switch value {
	case 0, 1, 4, 8, 16, 32:
		return true
	default:
		return false
	}
}

func clonePlannedWrites(in []PlannedWrite) []PlannedWrite {
	out := make([]PlannedWrite, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Payload = append([]byte(nil), in[i].Payload...)
	}
	return out
}
