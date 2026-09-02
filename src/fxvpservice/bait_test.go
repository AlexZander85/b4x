// bait_test.go: FX-M3 pins — the NFQ bait seam is honest (configured but
// inactive until the tables layer confirms), the direct egress policy
// carries MarkFxvpnEgress while the carrier-nested leg stays unmarked.
package fxvpservice

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/daniellavrushin/b4/packetmark"
)

// TestBaitSeamHonestStatus pins §7.8.5: the bait reports inactive until the
// tables layer confirms the OUTPUT rule, and never lies after teardown.
func TestBaitSeamHonestStatus(t *testing.T) {
	fx := newLiveFixture(t, 15)
	if fx.rt.Status().BaitActive {
		t.Fatal("bait must start inactive (not configured)")
	}

	// Not configured: SetBaitActive is a no-op.
	fx.rt.SetBaitActive(true)
	if fx.rt.Status().BaitActive {
		t.Fatal("unconfigured bait must never report active")
	}

	// Configure via the master switch.
	fx.rt.cfg.Masquerade.PreflightFake = true
	fx.rt.bait = &baitState{configured: true}
	if fx.rt.Status().BaitActive {
		t.Fatal("configured bait must stay inactive until tables confirm")
	}
	fx.rt.SetBaitActive(true)
	if !fx.rt.Status().BaitActive {
		t.Fatal("confirmed bait must report active")
	}
	fx.rt.SetBaitActive(false)
	if fx.rt.Status().BaitActive {
		t.Fatal("bait must report inactive after teardown")
	}
}

// TestBaitMarksDirectEgressOnly pins the §7.8.3 split: DIRECT egress
// carries MarkFxvpnEgress (the OUTPUT bait rule picks the first flight up),
// while the carrier-nested leg stays unmarked — double obfuscation would
// be a marker of its own.
func TestBaitMarksDirectEgressOnly(t *testing.T) {
	fx := newLiveFixture(t, 15)
	fx.rt.bait = &baitState{configured: true}
	fx.rt.carrierDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("carrier stand")
	}

	direct := fx.rt.dialPolicyFor(false)
	if direct.FwMark != packetmark.MarkFxvpnEgress {
		t.Fatal("direct policy must carry MarkFxvpnEgress")
	}
	if direct.BaseDial != nil {
		t.Fatal("direct policy must not dial through the carrier")
	}

	nested := fx.rt.dialPolicyFor(true)
	if nested.FwMark != 0 {
		t.Fatal("carrier-nested leg must NOT be marked (§7.8.3)")
	}
	if nested.BaseDial == nil {
		t.Fatal("nested policy must dial through the carrier")
	}
}
