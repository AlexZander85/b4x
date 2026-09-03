package discovery

import (
	"strings"

	"github.com/daniellavrushin/b4/lab"
	"github.com/daniellavrushin/b4/nfq"
)

// fakeProfileSource adapts the compiled fake profile catalog to the Level C
// fake-profile loader consumed by nfq workers. The catalog keeps profiles
// inactive until promotion, so every returned artifact is already schema
// validated, hash-consistent and never auto-promotes.
type fakeProfileSource struct {
	catalog *FakeProfileCatalog
}

// NewFakeProfileSource builds the nfq-facing fake profile loader over the
// compiled catalog. A nil catalog yields a source that always misses, which
// keeps the Level C fake techniques fail-open.
func NewFakeProfileSource(catalog *FakeProfileCatalog) nfq.FakeProfileSource {
	return &fakeProfileSource{catalog: catalog}
}

// SelectFakeProfile returns the highest-scored verified compiled profile for
// the observed target, gated on promotion eligibility: a profile becomes
// usable at runtime only after it accumulated enough stable, canary-passed
// evidence across targets. This is the promotion gate — compiled profiles are
// never auto-promoted, and a profile with only incidental observations
// misses and fails open to the caller's legacy path.
func (s *fakeProfileSource) SelectFakeProfile(target string) (lab.CompiledArtifact, bool) {
	if s == nil || s.catalog == nil || strings.TrimSpace(target) == "" {
		return lab.CompiledArtifact{}, false
	}
	candidates := s.catalog.Select(ProfileSelectionRequest{
		TargetProfile:    strings.ToLower(strings.TrimSpace(target)),
		MinSamples:       1,
		RequirePromotion: true,
		MaxCandidates:    1,
	})
	if len(candidates) == 0 {
		return lab.CompiledArtifact{}, false
	}
	artifact := candidates[0].Compiled()
	if artifact.Profile.ID == "" {
		return lab.CompiledArtifact{}, false
	}
	return artifact, true
}
