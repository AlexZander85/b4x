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
