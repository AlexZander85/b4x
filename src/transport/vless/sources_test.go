package vless

import (
	"strings"
	"testing"
)

// The curated bundled list must carry the measured-good upstreams and must not
// silently regress to the dead/mirror ones (b4x-n5b0).
func TestBundledSourcesCurated(t *testing.T) {
	all := strings.Join(BundledSources(), "\n")
	want := []string{"iboxz.github.io", "0xRadikal", "barry-far", "peasoft", "ALIILAPRO"}
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Fatalf("bundledSources missing %q", w)
		}
	}
	gone := []string{"mahdibland", "ts-sf", "freefq", "Epodonios"}
	for _, g := range gone {
		if strings.Contains(all, g) {
			t.Fatalf("bundledSources still carries stale source %q", g)
		}
	}
}
