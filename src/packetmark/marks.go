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

func ProcessedFor(legacyMark uint) uint32 {
	return uint32(legacyMark) | ProcessedBit
}

func Matches(mark, value, mask uint32) bool {
	return mask != 0 && mark&mask == value&mask
}

func IsProcessed(mark uint32, legacyMark uint) bool {
	return mark&ProcessedMask == ProcessedBit || mark == uint32(legacyMark)
}
