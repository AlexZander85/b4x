package packetmark

import "testing"

func TestReservedMarkContractIsDisjoint(t *testing.T) {
	if ProcessedBit&CanaryControlMask != 0 {
		t.Fatal("processed provenance bit overlaps canary control mask")
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
