package protonservice

import (
	"testing"
	"time"
)

// TestKeyGateYield pins the b4x-077 yield seam: one probe at a time, the key
// is refused while a probe is in flight, and yield() stops the in-flight probe
// and returns as soon as it released the key.
func TestKeyGateYield(t *testing.T) {
	var g keyGate

	stop, ok := g.begin()
	if !ok {
		t.Fatal("first begin must reserve the key")
	}
	if _, ok2 := g.begin(); ok2 {
		t.Fatal("second begin must refuse while a probe is in flight")
	}
	if stop() {
		t.Fatal("stop must be false before yield")
	}

	done := make(chan struct{})
	go func() {
		g.yield(time.Second)
		close(done)
	}()
	// Simulate the probe observing the yield and releasing the key.
	for !stop() {
		time.Sleep(5 * time.Millisecond)
	}
	g.end()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("yield must return once the probe released the key")
	}
	if !stop() {
		t.Fatal("stop must report true after yield")
	}

	g.end()
	if _, ok3 := g.begin(); !ok3 {
		t.Fatal("begin must succeed again after end")
	}
	g.end()
}

// TestKeyGateYieldNoop: yield with no probe in flight is a no-op (never blocks).
func TestKeyGateYieldNoop(t *testing.T) {
	var g keyGate
	start := time.Now()
	g.yield(time.Second)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("idle yield took %v, want instant", elapsed)
	}
}
