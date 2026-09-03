package tproxy

import "testing"

const bypassBit uint32 = 0x8000

func TestMarkForSet_RangeNeverHitsBypassBit(t *testing.T) {
	if MarkBase&bypassBit != 0 {
		t.Fatalf("MarkBase %#x collides with bypass bit %#x", MarkBase, bypassBit)
	}
	if (MarkBase+MarkRange-1)&bypassBit != 0 {
		t.Fatalf("mark range [%#x,%#x) overlaps bypass bit %#x",
			MarkBase, MarkBase+MarkRange, bypassBit)
	}
}

func TestMarkForSet_PinnedReturnsAsIs(t *testing.T) {
	cases := []uint32{1, 0x100, 0x12345, 0xDEADBEEF}
	for _, want := range cases {
		if got := MarkForSet("any-id", want); got != want {
			t.Fatalf("pinned mark: got %#x, want %#x", got, want)
		}
	}
}

func TestMarkForSet_DeterministicForSameID(t *testing.T) {
	id := "718e0020-ee8d-4055-851c-b99deeeb5abf"
	first := MarkForSet(id, 0)
	if got := MarkForSet(id, 0); got != first {
		t.Fatalf("MarkForSet not deterministic: got %#x, want %#x", got, first)
	}
}

func TestMarkForSet_RegressionOriginalFailingUUID(t *testing.T) {
	id := "718e0020-ee8d-4055-851c-b99deeeb5abf"
	m := MarkForSet(id, 0)
	if m&bypassBit != 0 {
		t.Fatalf("regression: mark %#x for the original failing UUID still hits bypass bit %#x", m, bypassBit)
	}
}
