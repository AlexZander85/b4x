package clock

import (
	"testing"
	"time"
)

func TestFixedClockDeterministicAdvance(t *testing.T) {
	start := time.Unix(100, 0).UTC()
	c := NewFixed(start)
	if got := c.Now(); !got.Equal(start) {
		t.Fatalf("initial time = %v, want %v", got, start)
	}
	c.Advance(250 * time.Millisecond)
	want := start.Add(250 * time.Millisecond)
	if got := c.Now(); !got.Equal(want) {
		t.Fatalf("advanced time = %v, want %v", got, want)
	}
}
