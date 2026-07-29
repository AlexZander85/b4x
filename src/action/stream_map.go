// Package action contains pure stream-offset planning and packet construction
// primitives. It does not own NFQUEUE verdicts or raw sockets.
package action

import (
	"errors"
	"math"
)

var (
	ErrInvalidStreamRange    = errors.New("invalid stream range")
	ErrStreamGap             = errors.New("stream range has a gap")
	ErrSequenceOverflow      = errors.New("stream sequence offset exceeds uint32")
	ErrRetransmission        = errors.New("retransmission is not eligible for a new action")
	ErrPlanBudget            = errors.New("action plan budget exceeded")
	ErrMTU                   = errors.New("planned packet exceeds MTU")
	ErrMarkerUnavailable     = errors.New("required semantic marker is unavailable")
	ErrInvalidPacket         = errors.New("invalid packet")
	ErrAuthorizationRequired = errors.New("domain-scoped action authorization is required")
)

type StreamRange struct {
	Start uint64
	Data  []byte
}

func (r StreamRange) End() uint64 { return r.Start + uint64(len(r.Data)) }

type PacketSpan struct {
	StreamStart uint64
	StreamEnd   uint64
	Sequence    uint32
}

type StreamMap struct {
	BaseSequence uint32
	Ranges       []StreamRange
}

func NewStreamMap(baseSequence uint32, ranges []StreamRange) (StreamMap, error) {
	if len(ranges) == 0 {
		return StreamMap{BaseSequence: baseSequence}, nil
	}
	copyRanges := make([]StreamRange, len(ranges))
	copy(copyRanges, ranges)
	for i := range copyRanges {
		if len(copyRanges[i].Data) == 0 || copyRanges[i].End() < copyRanges[i].Start {
			return StreamMap{}, ErrInvalidStreamRange
		}
		copyRanges[i].Data = append([]byte(nil), copyRanges[i].Data...)
		if i > 0 {
			previous := copyRanges[i-1]
			if copyRanges[i].Start < previous.End() {
				return StreamMap{}, ErrInvalidStreamRange
			}
			if copyRanges[i].Start != previous.End() {
				return StreamMap{}, ErrStreamGap
			}
		}
	}
	return StreamMap{BaseSequence: baseSequence, Ranges: copyRanges}, nil
}

func (m StreamMap) Len() uint64 {
	if len(m.Ranges) == 0 {
		return 0
	}
	return m.Ranges[len(m.Ranges)-1].End() - m.Ranges[0].Start
}

func (m StreamMap) SequenceAt(offset uint64) (uint32, error) {
	if offset > math.MaxUint32 {
		return 0, ErrSequenceOverflow
	}
	return m.BaseSequence + uint32(offset), nil
}

func (m StreamMap) Spans(offsets []uint64) ([]PacketSpan, error) {
	if len(m.Ranges) == 0 {
		return nil, nil
	}
	start := m.Ranges[0].Start
	end := m.Ranges[len(m.Ranges)-1].End()
	if len(offsets) == 0 {
		offsets = []uint64{start, end}
	}
	if offsets[0] != start {
		offsets = append([]uint64{start}, offsets...)
	}
	if offsets[len(offsets)-1] != end {
		offsets = append(append([]uint64(nil), offsets...), end)
	}
	spans := make([]PacketSpan, 0, len(offsets)-1)
	for i := 0; i+1 < len(offsets); i++ {
		if offsets[i] < start || offsets[i] >= offsets[i+1] || offsets[i+1] > end {
			return nil, ErrInvalidStreamRange
		}
		sequence, err := m.SequenceAt(offsets[i])
		if err != nil {
			return nil, err
		}
		spans = append(spans, PacketSpan{StreamStart: offsets[i], StreamEnd: offsets[i+1], Sequence: sequence})
	}
	return spans, nil
}
