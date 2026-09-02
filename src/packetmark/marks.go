// Package packetmark defines the dependency-free kernel mark contract shared
// by config validation, capture rules and packet generators.
package packetmark

const ProcessedBit uint32 = 1 << 27
const ProcessedMask uint32 = ProcessedBit

const (
	CanarySelectedBit uint32 = 1 << 26
	CanaryDirectBit   uint32 = 1 << 25
	CanaryInjectedBit uint32 = 1 << 24
	CanaryControlMask uint32 = CanarySelectedBit | CanaryDirectBit | CanaryInjectedBit
)

// MarkOperaEgress (bit 23) tags the Opera reserve transport's own egress
// sockets (SO_MARK via net.Dialer.Control). An OUTPUT mangle rule routes
// the marked packets into the existing action queue, where the standard
// fakedsplit/fakeddisorder strategies apply the fake first flight — the
// amnezia-I1 semantics ported to TCP (review E-OPERA §7.4.3, OP-M3).
// Bit 23 is disjoint from ProcessedBit (27) and the canary control mask
// (24-26); bits {0-14, 17} stay reserved for the queue contract.
const MarkOperaEgress uint32 = 1 << 23

func ProcessedFor(legacyMark uint) uint32 {
	return uint32(legacyMark) | ProcessedBit
}

func Matches(mark, value, mask uint32) bool {
	return mask != 0 && mark&mask == value&mask
}

func IsProcessed(mark uint32, legacyMark uint) bool {
	return mark&ProcessedMask == ProcessedBit || mark == uint32(legacyMark)
}
