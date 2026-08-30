// PATCH-18 (E13/E11) + PATCH-19 (E15/E21) acceptance tests.
package nested

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// TestMasqueRuntimePropagatesOuterMTU (PATCH-18/E13): a declared outer MTU
// reaches the carrier — a payload that fits the old hardcoded 1280 default
// but exceeds the REAL outer MTU must be rejected by the carrier's gate.
func TestMasqueRuntimePropagatesOuterMTU(t *testing.T) {
	plane := newFakePlane()
	pair := validPair()
	pair.Outer.MTU = 1240 // below the 1280 default
	rt, err := NewMasqueAwgRuntime(MasqueAwgConfig{
		Pair:       pair,
		Plane:      plane,
		LocalV4:    localV4(),
		InnerIdent: testInnerIdentity(),
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer rt.Stop()

	// 1240 - 28 = 1212 is the biggest payload the outer can carry.
	if err := rt.carrier.InjectUDPDatagram(
		netip.MustParseAddrPort("10.66.66.1:51820"), make([]byte, 1220)); err == nil {
		t.Fatal("1220-byte payload accepted: outer MTU 1240 was NOT propagated (still the 1280 default)")
	}
}

// TestPairConfigRejectsMTUInvariantViolation (PATCH-18/E13): when both MTUs
// are declared, inner + datagram overhead must fit the outer.
func TestPairConfigRejectsMTUInvariantViolation(t *testing.T) {
	p := validPair()
	p.Outer.MTU = 1200 // < 1200 + 28: the invariant is what can fail here
	p.Inner.MTU = 1200 // at the inner cap; 1200 + 28 > 1200
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds outer mtu") {
		t.Fatalf("inner+overhead > outer accepted: %v", err)
	}
	p.Outer.MTU = 1228 // 1200 + 28 == 1228: boundary holds
	if err := p.Validate(); err != nil {
		t.Fatalf("boundary outer mtu rejected: %v", err)
	}
}

// TestMasqueCarrierCloseSecondFlowSurvives (PATCH-18/E11): the collision-
// aware sport selection keeps both flows distinct, and closing the FIRST
// flow must not remove the SECOND flow's registration.
func TestMasqueCarrierCloseSecondFlowSurvives(t *testing.T) {
	fp := newFakePlane()
	c, err := NewMasqueDatagramCarrier(MasqueCarrierConfig{
		Plane:   fp,
		LocalV4: [4]byte{198, 51, 100, 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	orig := randomPortFn
	randomPortFn = func() uint16 { return 23456 } // force the collision path
	defer func() { randomPortFn = orig }()

	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 66, 66, 1}), 51820)
	f1, err := c.DialUDPThrough(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := c.DialUDPThrough(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := f1.Close(); err != nil {
		t.Fatal(err)
	}
	// The second flow must still be registered and demuxable.
	k2 := f2.(*flowConn).key
	c.mu.Lock()
	_, ok := c.flows[k2]
	c.mu.Unlock()
	if !ok {
		t.Fatal("E11: closing flow 1 removed flow 2's registration")
	}
}

// TestPumpNotStartedAfterCarrierClose (PATCH-19/E21): StartPumping on a
// closed carrier must not subscribe to the plane.
func TestPumpNotStartedAfterCarrierClose(t *testing.T) {
	fp := newFakePlane()
	c, err := NewMasqueDatagramCarrier(MasqueCarrierConfig{
		Plane:   fp,
		LocalV4: [4]byte{198, 51, 100, 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.StartPumping() // must be a no-op
	if subs := fp.subCount(); subs != 0 {
		t.Fatalf("plane subscriptions = %d, want 0 (pump-after-close subscribed)", subs)
	}
}

// TestRuntimeStopBeforeStartReturnsImmediately (PATCH-19/E15): Stop on a
// never-started runtime completes without deadlock, for BOTH runtimes.
func TestRuntimeStopBeforeStartReturnsImmediately(t *testing.T) {
	done := make(chan struct{})
	go func() {
		mwRT, err := NewMasqueAwgRuntime(MasqueAwgConfig{
			Pair:       validPair(),
			Plane:      newFakePlane(),
			LocalV4:    localV4(),
			InnerIdent: testInnerIdentity(),
		})
		if err != nil {
			t.Error(err)
			done <- struct{}{}
			return
		}
		mwRT.Stop() // old code: deadlocked here on <-r.done

		wmRT, err := NewWgMasqueRuntime(WgMasqueConfig{
			Pair:          validWMPair(),
			OuterIdent:    wmTestIdentity(t),
			InnerEnroll:   &twarp.EnrollClient{},
			InnerSlotPath: t.TempDir() + "/secondary.json",
		})
		if err != nil {
			t.Error(err)
			done <- struct{}{}
			return
		}
		wmRT.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("E15: Stop-before-Start did not return (deadlock)")
	}
}

// TestRuntimeStartAfterStopRejected (PATCH-19/E15): Start after Stop is a
// structural error instead of a silent zombie.
func TestRuntimeStartAfterStopRejected(t *testing.T) {
	mwRT, err := NewMasqueAwgRuntime(MasqueAwgConfig{
		Pair:       validPair(),
		Plane:      newFakePlane(),
		LocalV4:    localV4(),
		InnerIdent: testInnerIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	mwRT.Stop()
	if err := mwRT.Start(context.Background()); err == nil {
		t.Fatal("M+W: Start-after-Stop must be rejected (zombie contract)")
	}

	wmRT, err := NewWgMasqueRuntime(WgMasqueConfig{
		Pair:          validWMPair(),
		OuterIdent:    wmTestIdentity(t),
		InnerEnroll:   &twarp.EnrollClient{},
		InnerSlotPath: t.TempDir() + "/secondary.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	wmRT.Stop()
	if err := wmRT.Start(context.Background()); err == nil {
		t.Fatal("W+M: Start-after-Stop must be rejected")
	}
}

// TestFakePlaneSubscriptionCounter is a tiny helper assertion for E21: the
// fake plane counts active subscriptions.
func TestFakePlaneSubscriptionCounter(t *testing.T) {
	fp := newFakePlane()
	if fp.subCount() != 0 {
		t.Fatal("fresh plane must have zero subscriptions")
	}
	ch, cancel := fp.SubscribePackets()
	if fp.subCount() != 1 {
		t.Fatalf("subscriptions after subscribe = %d, want 1", fp.subCount())
	}
	cancel()
	if fp.subCount() != 0 {
		t.Fatalf("subscriptions after cancel = %d, want 0", fp.subCount())
	}
	var _ = ch
}
