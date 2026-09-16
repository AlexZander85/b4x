package action

import (
	"bytes"
	"errors"
	"testing"

	"github.com/daniellavrushin/b4/fixtures"
)

func TestApplyClientHelloPaddingPreservesLogicalStream(t *testing.T) {
	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	input := PlanInput{
		BaseSequence:  7000,
		Payload:       payload,
		Markers:       DiscoverTLSMarkers(payload),
		MTU:           1500,
		IPHeaderLen:   20,
		TCPHeaderLen:  20,
		ProcessedMark: 1 << 29,
		MaxWrites:     16,
	}
	base, err := Plan(input)
	if err != nil {
		t.Fatal(err)
	}
	padded, generated, err := ApplyClientHelloPadding(base, input, 8, 4)
	if err != nil {
		t.Fatal(err)
	}
	if generated != 12 || len(padded.Writes) != len(base.Writes)+2 || padded.TotalBytes != base.TotalBytes+12 {
		t.Fatalf("unexpected padded plan: generated=%d writes=%d total=%d", generated, len(padded.Writes), padded.TotalBytes)
	}
	start, _ := input.Markers.Find(MarkerClientHelloStart)
	end, _ := input.Markers.Find(MarkerClientHelloEnd)
	pre := padded.Writes[0]
	post := padded.Writes[len(padded.Writes)-1]
	if pre.Sequence != input.BaseSequence+uint32(start.Offset) || !bytes.Equal(pre.Payload, payload[start.Offset:start.Offset+8]) {
		t.Fatalf("pre-padding write does not duplicate original prefix: %+v", pre)
	}
	if post.Sequence != input.BaseSequence+uint32(end.Offset-4) || !bytes.Equal(post.Payload, payload[end.Offset-4:end.Offset]) {
		t.Fatalf("post-padding write does not duplicate original suffix: %+v", post)
	}

	// Dropping the two duplicate padding writes leaves the exact original
	// stream plan byte-for-byte; the added writes reuse the same sequence
	// ranges and therefore do not introduce new logical stream bytes.
	reassembled := make([]byte, 0, len(payload))
	for _, write := range padded.Writes[1 : len(padded.Writes)-1] {
		reassembled = append(reassembled, write.Payload...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatal("padding transform changed the original logical stream")
	}
}

func TestApplyClientHelloPaddingRejectsUnsafeOrIncompleteInputs(t *testing.T) {
	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	input := PlanInput{BaseSequence: 7000, Payload: payload, Markers: DiscoverTLSMarkers(payload), MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1 << 29, MaxWrites: 16}
	base, err := Plan(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ApplyClientHelloPadding(base, input, 3, 0); !errors.Is(err, ErrClientHelloPadding) {
		t.Fatalf("non-registry padding accepted: %v", err)
	}
	incomplete := input
	incomplete.Markers.Complete = false
	if _, _, err := ApplyClientHelloPadding(base, incomplete, 8, 0); !errors.Is(err, ErrClientHelloPadding) {
		t.Fatalf("incomplete ClientHello padding accepted: %v", err)
	}
	limited := input
	limited.MaxWrites = len(base.Writes)
	if _, _, err := ApplyClientHelloPadding(base, limited, 8, 0); !errors.Is(err, ErrPlanBudget) {
		t.Fatalf("write budget escape accepted: %v", err)
	}
}
