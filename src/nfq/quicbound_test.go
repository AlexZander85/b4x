package nfq

import (
	"strings"
	"testing"
	"time"
)

func TestQuicboundOpenCorrelatesRecentQUIC(t *testing.T) {
	s := newQuicboundStore()
	now := time.Now()

	// No QUIC seen -> not near.
	o1 := s.openTCP("aa", "1.2.3.4", 40000, now)
	if o1.quicNear {
		t.Fatal("open without prior QUIC must not be marked near")
	}

	// QUIC 10 s before the open -> near.
	s.noteQUIC("aa", "1.2.3.4", now)
	o2 := s.openTCP("aa", "1.2.3.4", 40001, now.Add(10*time.Second))
	if !o2.quicNear {
		t.Fatal("open 10s after QUIC must be marked near")
	}

	// QUIC 61 s before the open -> outside the +-60 s window.
	s.noteQUIC("aa", "1.2.3.5", now)
	o3 := s.openTCP("aa", "1.2.3.5", 40002, now.Add(61*time.Second))
	if o3.quicNear {
		t.Fatal("open 61s after QUIC must not be marked near")
	}
}

func TestQuicboundConfirmCreatesOpenWithoutSyn(t *testing.T) {
	s := newQuicboundStore()
	now := time.Now()

	// Common field case: the set only becomes resolvable after the CH, so
	// confirmECH itself registers the doomed open (with QUIC proximity).
	s.noteQUIC("aa", "1.2.3.4", now)
	s.confirmECH("1.2.3.4", 40100, "rr1---sn-x.googlevideo.com", now.Add(2*time.Second))

	k := s.keys["1.2.3.4"]
	if len(k.opens) != 1 {
		t.Fatalf("confirm must create an open record, got %d", len(k.opens))
	}
	o := k.opens[0]
	if !o.echSeen || !o.quicNear || !o.newOrigin {
		t.Fatalf("created open mismatch: %+v", o)
	}
}

func TestQuicboundFatesAndTimeout(t *testing.T) {
	s := newQuicboundStore()
	now := time.Now()
	s.openTCP("aa", "1.2.3.4", 40010, now)
	s.confirmECH("1.2.3.4", 40010, "rr1---sn-x.googlevideo.com", now.Add(80*time.Millisecond))
	s.replay("1.2.3.4", 40010)
	s.replay("1.2.3.4", 40010)

	// FIN from the mirrored inbound path closes with fate=fin.
	s.closeTCP("1.2.3.4", 40010, "fin", now.Add(30*time.Second))

	k := s.keys["1.2.3.4"]
	o := k.opens[len(k.opens)-1]
	if !o.closed || o.fate != "fin" || o.closeTs.Sub(o.ts) != 30*time.Second {
		t.Fatalf("fin fate mismatch: %+v", o)
	}
	if !o.echSeen || o.replays != 2 {
		t.Fatalf("ech/replays mismatch: %+v", o)
	}
	hostFirst, seen := s.hosts["rr1---sn-x.googlevideo.com"]
	if !seen || hostFirst.IsZero() {
		t.Fatal("host must be recorded on confirm")
	}

	// Second open never closed -> sweep marks timeout after qbOpenTimeout.
	s2 := newQuicboundStore()
	s2.openTCP("bb", "5.6.7.8", 40011, now)
	s2.sweep(now.Add(qbOpenTimeout + time.Second))
	o2 := s2.keys["5.6.7.8"].opens[0]
	if o2.fate != "timeout" || !o2.closed {
		t.Fatalf("stale open must become timeout: %+v", o2)
	}
}

func TestQuicboundFallbackStamping(t *testing.T) {
	s := newQuicboundStore()
	now := time.Now()
	s.openTCP("cc", "9.9.9.9", 40012, now)
	s.confirmECH("9.9.9.9", 40012, "", now.Add(50*time.Millisecond))

	// First follow-up QUIC burst stamps fallback; later ones do not.
	s.noteQUIC("cc", "9.9.9.9", now.Add(12*time.Second))
	s.noteQUIC("cc", "9.9.9.9", now.Add(40*time.Second))

	o := s.keys["9.9.9.9"].opens[0]
	if !o.hasFB || o.fallback != 12*time.Second {
		t.Fatalf("fallback stamp mismatch: %+v", o)
	}
}

func TestQuicboundSummaryShape(t *testing.T) {
	s := newQuicboundStore()
	now := time.Now()
	s.started = now.Add(-qbSummaryEvery)

	s.noteQUIC("dd", "7.7.7.7", now)
	s.openTCP("dd", "7.7.7.7", 40013, now.Add(time.Second))
	s.confirmECH("7.7.7.7", 40013, "rr2---sn-y.googlevideo.com", now.Add(time.Second+90*time.Millisecond))
	s.closeTCP("7.7.7.7", 40013, "rst", now.Add(25*time.Second))

	s.openTCP("ee", "7.7.7.8", 40014, now.Add(2*time.Second)) // no ECH, no close

	out := func() string { s.mu.Lock(); defer s.mu.Unlock(); return s.summaryLocked(now.Add(time.Minute)) }()
	for _, want := range []string{"[quicbound]", "opens=2", "parallelQUIC(60s)=50%"} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary %q missing %q", out, want)
		}
	}
}

func TestQuicboundHooksAreNoopWhenDisabled(t *testing.T) {
	if quicboundEnabled {
		t.Skip("enabled in quicbound builds")
	}
	w := &Worker{}
	// nil store guards: these must not panic in default builds.
	w.quicboundNoteQUIC(nil)
	w.quicboundObserveHandshake(nil, nil, false)
	w.quicboundObserveIncoming(nil, "", 0, false, false)
}
