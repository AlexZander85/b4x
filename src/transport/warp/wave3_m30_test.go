package transportwarp

import (
	"bytes"
	"sync"
	"testing"
)

// TestM30FanOutGivesPrivateCopy covers M-30: fanOut must deliver a private
// copy per subscriber. Subscriber 1 mutates its received slice; subscriber 2
// must still observe the pristine original payload.
func TestM30FanOutGivesPrivateCopy(t *testing.T) {
	s := &Session{
		subs: make(map[chan []byte]struct{}),
	}

	ch1 := make(chan []byte, 4)
	ch2 := make(chan []byte, 4)
	s.subs[ch1] = struct{}{}
	s.subs[ch2] = struct{}{}

	// No concurrent writers, so the lock/unlock here mirrors fanOut's own
	// contract without racing.
	payload := []byte("m30-verify-isolation")
	s.fanOut(payload)

	var wg sync.WaitGroup
	wg.Add(2)
	var b1, b2 []byte
	go func() { b1 = <-ch1; wg.Done() }()
	go func() { b2 = <-ch2; wg.Done() }()
	wg.Wait()

	// Subscriber 1 mutates its copy aggressively.
	for i := range b1 {
		b1[i] = 0xAA
	}

	// Original payload object must be untouched too (fanOut copies from pkt;
	// the caller owns pkt after fanOut returns).
	if !bytes.Equal(payload, []byte("m30-verify-isolation")) {
		t.Fatalf("fanOut mutated the caller's payload: %q", payload)
	}
	// Subscriber 2 sees pristine data.
	if want := []byte("m30-verify-isolation"); !bytes.Equal(b2, want) {
		t.Fatalf("subscriber2 payload = %q want %q (copy not isolated)", b2, want)
	}
	// And the two subscribers never share a backing array.
	if len(b1) > 0 && &b1[0] == &b2[0] {
		t.Fatal("subscribers share the same backing array; mutation is not isolated")
	}
}
