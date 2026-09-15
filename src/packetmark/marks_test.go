package packetmark

import "testing"

func TestReservedMarkContractIsDisjoint(t *testing.T) {
	if ProcessedBit&CanaryControlMask != 0 {
		t.Fatal("processed provenance bit overlaps canary control mask")
	}
	if MarkOperaEgress&(ProcessedBit|CanaryControlMask) != 0 {
		t.Fatal("opera egress mark overlaps provenance/canary bits")
	}
	if MarkOperaEgress == 0 || MarkOperaEgress&(MarkOperaEgress-1) != 0 {
		t.Fatal("opera egress mark must be a single bit")
	}
	if CanarySelectedBit&CanaryDirectBit != 0 || CanarySelectedBit&CanaryInjectedBit != 0 || CanaryDirectBit&CanaryInjectedBit != 0 {
		t.Fatal("canary control bits overlap")
	}
	if !IsProcessed(ProcessedFor(0x8000), 0x8000) {
		t.Fatal("generated mark was not recognized")
	}
	if IsProcessed(CanarySelectedBit, 0x8000) {
		t.Fatal("selected-flow control mark was treated as generated provenance")
	}
}

// E-TOR (design §9.1): MarkTorEgress takes bit 21, the next free egress
// bit after opera (23) and fxvpn (22), and stays disjoint from the engine
// contract bits.
func TestMarkTorEgressBitContract(t *testing.T) {
	if MarkTorEgress != 1<<21 {
		t.Fatalf("MarkTorEgress = %#x, want 1<<21", MarkTorEgress)
	}
	if MarkTorEgress == MarkOperaEgress || MarkTorEgress == MarkFxvpnEgress {
		t.Fatal("tor egress mark must be disjoint from opera/fxvpn marks")
	}
	if MarkTorEgress&ProcessedMask != 0 || MarkTorEgress&CanaryControlMask != 0 {
		t.Fatal("tor egress mark must stay disjoint from ProcessedBit and the canary mask")
	}
	all := MarkOperaEgress | MarkFxvpnEgress | MarkTorEgress
	if all&(ProcessedMask|CanaryControlMask) != 0 {
		t.Fatal("egress marks collectively must not collide with the engine contract bits")
	}
}
