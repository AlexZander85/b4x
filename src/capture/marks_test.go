package capture

import "testing"

func TestProcessedMarkContract(t *testing.T) {
	legacy := uint(0x8000)
	generated := ProcessedMarkFor(legacy)
	if generated == uint32(legacy) || generated&ProcessedMarkMask != ProcessedMarkBit {
		t.Fatalf("generated mark = %#x", generated)
	}
	if !IsProcessedMark(generated, legacy) {
		t.Fatal("generated mark was not recognized")
	}
	if !IsProcessedMark(uint32(legacy), legacy) {
		t.Fatal("legacy mark was not accepted during migration")
	}
	if IsProcessedMark(uint32(legacy)|1, legacy) {
		t.Fatal("unrelated mark was accepted")
	}
	if MatchesMark(generated, generated, ProcessedMarkMask) != true {
		t.Fatal("masked generated mark was not recognized")
	}
}
