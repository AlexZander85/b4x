package nfq

import "testing"

func TestBoundComboSplitsCapsLargeECH(t *testing.T) {
	got := uniqueSorted(boundComboSplits(nil, 1891), 1891)
	if len(got) < 3 {
		t.Fatalf("expected several splits, got %v", got)
	}
	prev := 0
	for _, s := range got {
		if s-prev > 400 {
			t.Fatalf("piece %d..%d exceeds 400", prev, s)
		}
		prev = s
	}
	if 1891-got[len(got)-1] > 400 {
		t.Fatalf("tail piece too large: last split %d of %d", got[len(got)-1], 1891)
	}
}

func TestBoundComboSplitsLeavesSmallCH(t *testing.T) {
	got := boundComboSplits([]int{40}, 189)
	if len(got) != 1 || got[0] != 40 {
		t.Fatalf("small CH should stay untouched, got %v", got)
	}
}