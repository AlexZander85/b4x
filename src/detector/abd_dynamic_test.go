package detector

import (
	"testing"
	"time"
)

func TestDynamicProviderBoundsAndCaches(t *testing.T) {
	now := time.Unix(16000, 0)
	src := StaticTargetSource{{ID: "2", IPHash: "b", Provenance: "signed"}, {ID: "1", IPHash: "a", Provenance: "signed"}, {ID: "3", IPHash: "c", Provenance: "signed"}}
	p := NewDynamicControlTargetProvider(DynamicProviderConfig{MaxTargets: 2, TTL: time.Minute, SampleSeed: 1}, src)
	a, err := p.Targets(DynamicSelector{Service: "web"}, now)
	if err != nil || len(a) != 2 {
		t.Fatalf("bounded load failed: %+v %v", a, err)
	}
	b, err := p.Targets(DynamicSelector{Service: "web"}, now.Add(time.Second))
	if err != nil || len(b) != 2 || a[0].ID != b[0].ID || a[1].ID != b[1].ID {
		t.Fatalf("cache/sample not deterministic: %+v %+v", a, b)
	}
}

func TestDynamicProviderFiltersExpiredAndUnprovenanced(t *testing.T) {
	now := time.Unix(16000, 0)
	src := StaticTargetSource{{ID: "expired", IPHash: "x", Provenance: "signed", ValidUntil: now.Add(-time.Second)}, {ID: "raw", IPHash: "y"}}
	p := NewDynamicControlTargetProvider(DynamicProviderConfig{MaxTargets: 4}, src)
	a, err := p.Targets(DynamicSelector{}, now)
	if err != nil || len(a) != 0 {
		t.Fatalf("invalid dynamic targets accepted: %+v %v", a, err)
	}
}
