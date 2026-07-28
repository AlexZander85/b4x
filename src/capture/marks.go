package capture

import "github.com/daniellavrushin/b4/packetmark"

// Re-export the versioned packet-mark contract from a dependency-free package
// so existing capture/action callers keep a stable API.
const (
	ProcessedMarkBit      = packetmark.ProcessedBit
	ProcessedMarkMask     = packetmark.ProcessedMask
	CanarySelectedMarkBit = packetmark.CanarySelectedBit
	CanaryDirectMarkBit   = packetmark.CanaryDirectBit
	CanaryInjectedMarkBit = packetmark.CanaryInjectedBit
	CanaryControlMarkMask = packetmark.CanaryControlMask
)

func ProcessedMarkFor(legacyMark uint) uint32   { return packetmark.ProcessedFor(legacyMark) }
func MatchesMark(mark, value, mask uint32) bool { return packetmark.Matches(mark, value, mask) }
func IsProcessedMark(mark uint32, legacyMark uint) bool {
	return packetmark.IsProcessed(mark, legacyMark)
}
