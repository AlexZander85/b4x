package detector

import (
	"testing"
	"time"
)

func TestL4PacketAndByteProfilesRemainIndependent(t *testing.T) {
	now := time.Unix(15000, 0)
	scope := monitorScopeForDetector()
	es := []L4Experiment{{Scope: scope, TargetID: "t", Dimension: DimensionPacket, Direction: DirectionDownlink, Mode: FreshFlow, Packets: 25, Success: false, ObservedAt: now}, {Scope: scope, TargetID: "t", Dimension: DimensionPacket, Direction: DirectionDownlink, Mode: FreshFlow, Packets: 30, Success: false, ObservedAt: now}, {Scope: scope, TargetID: "t", Dimension: DimensionByte, Direction: DirectionDownlink, Mode: FreshFlow, UniqueBytes: 25000, Success: false, ObservedAt: now}, {Scope: scope, TargetID: "t", Dimension: DimensionByte, Direction: DirectionDownlink, Mode: FreshFlow, UniqueBytes: 30000, Success: false, ObservedAt: now}}
	p, err := BuildL4ThresholdProfile(scope, "t", es, now)
	if err != nil {
		t.Fatal(err)
	}
	if !p.PacketClaim() || !p.ByteClaim() {
		t.Fatalf("claims not formed: %+v", p)
	}
	if p.Intervals[0].Lower == p.Intervals[1].Lower {
		t.Fatal("dimensions collapsed")
	}
}

func TestL4ServerLimitSuppressesClaim(t *testing.T) {
	now := time.Unix(15000, 0)
	scope := monitorScopeForDetector()
	es := []L4Experiment{{Scope: scope, TargetID: "t", Dimension: DimensionByte, Direction: DirectionDownlink, Mode: FreshFlow, UniqueBytes: 10000, ServerLimit: true, ObservedAt: now}, {Scope: scope, TargetID: "t", Dimension: DimensionByte, Direction: DirectionDownlink, Mode: FreshFlow, UniqueBytes: 12000, ServerLimit: true, ObservedAt: now}}
	p, err := BuildL4ThresholdProfile(scope, "t", es, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.ByteClaim() {
		t.Fatal("server-limited samples became byte claim")
	}
}
