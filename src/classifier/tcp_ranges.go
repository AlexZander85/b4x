package classifier

import (
	"bytes"
	"errors"
)

var (
	ErrRangeBudget   = errors.New("tcp range budget exceeded")
	ErrRangeConflict = errors.New("conflicting tcp range overlap")
	ErrRangeOverflow = errors.New("tcp range offset overflow")
)

// ByteRange is a non-overlapping, sorted stream range retained by RangeSet.
// Data is owned by the RangeSet and never aliases caller packet buffers.
type ByteRange struct {
	Start uint64
	Data  []byte
}

func (r ByteRange) End() uint64 { return r.Start + uint64(len(r.Data)) }

type RangeInsertResult struct {
	Accepted           bool
	NewBytes           int
	IdenticalOverlap   bool
	ConflictingOverlap bool
	Reason             string
}

// RangeSet stores bounded, sorted non-overlapping stream ranges. It is not
// synchronized; TCPReassemblyStore owns synchronization at the flow level.
type RangeSet struct {
	ranges    []ByteRange
	bytes     int
	maxBytes  int
	maxRanges int
}

func NewRangeSet(maxBytes, maxRanges int) *RangeSet {
	if maxBytes <= 0 {
		maxBytes = 32 * 1024
	}
	if maxRanges <= 0 {
		maxRanges = 64
	}
	return &RangeSet{ranges: make([]ByteRange, 0, minRangeInt(maxRanges, 8)), maxBytes: maxBytes, maxRanges: maxRanges}
}

func (s *RangeSet) Bytes() int { return s.bytes }

func (s *RangeSet) Len() int { return len(s.ranges) }

func (s *RangeSet) Ranges() []ByteRange {
	out := make([]ByteRange, len(s.ranges))
	for i, r := range s.ranges {
		out[i] = ByteRange{Start: r.Start, Data: append([]byte(nil), r.Data...)}
	}
	return out
}

// EstimateNewBytes performs the overlap comparison without changing state.
// It is used by the global budget gate before accepting a packet.
func (s *RangeSet) EstimateNewBytes(start uint64, payload []byte) (newBytes int, identical, conflicting bool, err error) {
	if len(payload) == 0 {
		return 0, false, false, nil
	}
	end := start + uint64(len(payload))
	if end < start {
		return 0, false, false, ErrRangeOverflow
	}
	overlapped := 0
	for _, r := range s.ranges {
		if r.End() <= start || r.Start >= end {
			continue
		}
		overlapStart := maxRangeUint(start, r.Start)
		overlapEnd := minRangeUint(end, r.End())
		if !bytes.Equal(payload[overlapStart-start:overlapEnd-start], r.Data[overlapStart-r.Start:overlapEnd-r.Start]) {
			conflicting = true
		}
		overlapped += int(overlapEnd - overlapStart)
		identical = true
	}
	if overlapped > len(payload) {
		overlapped = len(payload)
	}
	return len(payload) - overlapped, identical, conflicting, nil
}

func (s *RangeSet) Insert(start uint64, payload []byte) RangeInsertResult {
	if len(payload) == 0 {
		return RangeInsertResult{Accepted: true, Reason: "empty payload"}
	}
	newBytes, identical, conflicting, err := s.EstimateNewBytes(start, payload)
	if err != nil {
		return RangeInsertResult{Reason: err.Error()}
	}
	if conflicting {
		return RangeInsertResult{ConflictingOverlap: true, IdenticalOverlap: identical, Reason: ErrRangeConflict.Error()}
	}
	if s.bytes+newBytes > s.maxBytes {
		return RangeInsertResult{IdenticalOverlap: identical, NewBytes: newBytes, Reason: ErrRangeBudget.Error()}
	}

	end := start + uint64(len(payload))
	mergeStart, mergeEnd := start, end
	for _, r := range s.ranges {
		if r.End() < mergeStart || r.Start > mergeEnd {
			continue
		}
		if r.Start < mergeStart {
			mergeStart = r.Start
		}
		if r.End() > mergeEnd {
			mergeEnd = r.End()
		}
	}
	mergedLen := int(mergeEnd - mergeStart)
	if mergedLen < 0 || mergedLen > s.maxBytes {
		return RangeInsertResult{IdenticalOverlap: identical, NewBytes: newBytes, Reason: ErrRangeBudget.Error()}
	}
	merged := make([]byte, mergedLen)
	for _, r := range s.ranges {
		if r.End() < mergeStart || r.Start > mergeEnd {
			continue
		}
		copy(merged[r.Start-mergeStart:], r.Data)
	}
	copy(merged[start-mergeStart:], payload)

	newRanges := make([]ByteRange, 0, len(s.ranges)+1)
	inserted := false
	for _, r := range s.ranges {
		if r.End() < mergeStart || r.Start > mergeEnd {
			if !inserted && r.Start > mergeEnd {
				newRanges = append(newRanges, ByteRange{Start: mergeStart, Data: merged})
				inserted = true
			}
			newRanges = append(newRanges, r)
		}
	}
	if !inserted {
		newRanges = append(newRanges, ByteRange{Start: mergeStart, Data: merged})
	}
	if len(newRanges) > s.maxRanges {
		return RangeInsertResult{IdenticalOverlap: identical, NewBytes: newBytes, Reason: ErrRangeBudget.Error()}
	}
	s.ranges = newRanges
	s.bytes += newBytes
	return RangeInsertResult{Accepted: true, NewBytes: newBytes, IdenticalOverlap: identical, Reason: "range accepted"}
}

// Contiguous returns a copy beginning at base and ending at the first gap or
// limit. It is bounded by limit and never exposes internal range storage.
func (s *RangeSet) Contiguous(base uint64, limit int) []byte {
	if limit <= 0 {
		return nil
	}
	out := make([]byte, 0, minRangeInt(limit, s.bytes))
	next := base
	for _, r := range s.ranges {
		if r.End() <= next {
			continue
		}
		if r.Start > next {
			break
		}
		offset := int(next - r.Start)
		available := len(r.Data) - offset
		if available <= 0 {
			continue
		}
		if available > limit-len(out) {
			available = limit - len(out)
		}
		out = append(out, r.Data[offset:offset+available]...)
		next += uint64(available)
		if len(out) == limit || available == 0 {
			break
		}
	}
	return out
}

func (s *RangeSet) Reset() {
	s.ranges = s.ranges[:0]
	s.bytes = 0
}

func minRangeInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minRangeUint(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxRangeUint(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
