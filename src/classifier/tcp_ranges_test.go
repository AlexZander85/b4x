package classifier

import "testing"

func TestRangeSetOutOfOrderRetransmissionAndConflict(t *testing.T) {
	ranges := NewRangeSet(32, 8)
	if result := ranges.Insert(0, []byte("abc")); !result.Accepted || result.NewBytes != 3 {
		t.Fatalf("first insert = %+v", result)
	}
	if result := ranges.Insert(6, []byte("ghi")); !result.Accepted || ranges.Len() != 2 {
		t.Fatalf("out-of-order insert = %+v ranges=%+v", result, ranges.Ranges())
	}
	if got := string(ranges.Contiguous(0, 32)); got != "abc" {
		t.Fatalf("contiguous prefix across gap = %q", got)
	}
	if result := ranges.Insert(3, []byte("def")); !result.Accepted || ranges.Len() != 1 {
		t.Fatalf("gap fill = %+v ranges=%+v", result, ranges.Ranges())
	}
	if got := string(ranges.Contiguous(0, 32)); got != "abcdefghi" {
		t.Fatalf("assembled stream = %q", got)
	}
	if result := ranges.Insert(0, []byte("abc")); !result.Accepted || result.NewBytes != 0 || !result.IdenticalOverlap {
		t.Fatalf("retransmission = %+v", result)
	}
	if result := ranges.Insert(1, []byte("X")); result.Accepted || !result.ConflictingOverlap || ranges.Bytes() != 9 {
		t.Fatalf("conflicting overlap = %+v ranges=%+v", result, ranges.Ranges())
	}
}

func TestRangeSetBoundsAndContiguousLimit(t *testing.T) {
	ranges := NewRangeSet(4, 2)
	if result := ranges.Insert(0, []byte("abcd")); !result.Accepted {
		t.Fatalf("bounded insert = %+v", result)
	}
	if result := ranges.Insert(8, []byte("ef")); result.Accepted || result.Reason != ErrRangeBudget.Error() {
		t.Fatalf("byte budget result = %+v", result)
	}
	if got := string(ranges.Contiguous(0, 2)); got != "ab" {
		t.Fatalf("contiguous limit = %q", got)
	}
	if result := ranges.Insert(8, []byte("ef")); result.Accepted {
		t.Fatalf("range budget accepted second disjoint range: %+v", result)
	}
}

func FuzzRangeSetNeverPanics(f *testing.F) {
	f.Add(uint64(0), []byte("hello"))
	f.Add(uint64(100), []byte(nil))
	f.Fuzz(func(t *testing.T, start uint64, payload []byte) {
		ranges := NewRangeSet(1024, 16)
		_ = ranges.Insert(start, payload)
		_ = ranges.Contiguous(start, 1024)
	})
}
