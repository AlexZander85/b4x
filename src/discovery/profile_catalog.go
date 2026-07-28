package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/lab"
)

type FakeProfileKind string

const (
	ProfileGeneratedNeutral FakeProfileKind = "generated-neutral-tls"
	ProfileGoogleLike       FakeProfileKind = "google-like"
	ProfileAndroidCaptured  FakeProfileKind = "android-captured"
	ProfileQUICInitial      FakeProfileKind = "quic-initial"
)

const (
	MaxFakeCatalogEntries = 128
	MaxProfileTargets     = 16
	MaxProfileSamples     = 1000000
)

var (
	ErrProfileCatalogFull = errors.New("fake profile catalog is full")
	ErrProfileInvalid     = errors.New("invalid fake profile registration")
	ErrProfileLicense     = errors.New("fake profile license/provenance is not reviewed")
	ErrProfileNotFound    = errors.New("fake profile is not found")
	ErrProfileEvidence    = errors.New("invalid fake profile evidence")
)

// CatalogProfile is metadata only. It intentionally contains no raw or
// compiled bytes so JSON/API exports stay privacy-safe.
type CatalogProfile struct {
	ID              string          `json:"id"`
	Kind            FakeProfileKind `json:"kind"`
	Template        string          `json:"template"`
	Source          string          `json:"source"`
	Provenance      string          `json:"provenance"`
	License         string          `json:"license"`
	LicenseReviewed bool            `json:"license_reviewed"`
	SHA256          string          `json:"sha256"`
	Size            int             `json:"size"`
	TLSVersion      uint16          `json:"tls_version"`
	ALPN            []string        `json:"alpn,omitempty"`
	ECHPresent      bool            `json:"ech_present"`
	Active          bool            `json:"active"`
	CreatedAt       time.Time       `json:"created_at"`
}

type ProfileRegistration struct {
	ID              string
	Kind            FakeProfileKind
	Template        string
	Source          string
	Provenance      string
	License         string
	LicenseReviewed bool
	SHA256          string
	Size            int
	TLSVersion      uint16
	ALPN            []string
	ECHPresent      bool
}

type ProfileObservation struct {
	TargetProfile   string
	Samples         uint64
	Successful      uint64
	StableSuccesses uint64
	CanaryPassed    bool
	Amplification   float64
	ObservedAt      time.Time
}

type ProfileEvidence struct {
	Samples         uint64    `json:"samples"`
	Successful      uint64    `json:"successful"`
	StableSuccesses uint64    `json:"stable_successes"`
	CanaryPassed    bool      `json:"canary_passed"`
	Amplification   float64   `json:"amplification,omitempty"`
	LastObservedAt  time.Time `json:"last_observed_at"`
}

type ProfileCandidate struct {
	Profile           CatalogProfile `json:"profile"`
	TechniqueID       string         `json:"technique_id,omitempty"`
	TargetProfile     string         `json:"target_profile"`
	Score             float64        `json:"score"`
	Samples           uint64         `json:"samples"`
	StableSuccesses   uint64         `json:"stable_successes"`
	PromotionEligible bool           `json:"promotion_eligible"`
	artifact          lab.CompiledArtifact
}

func (c ProfileCandidate) Compiled() lab.CompiledArtifact { return c.artifact }

type profileEntry struct {
	profile  CatalogProfile
	artifact lab.CompiledArtifact
	evidence map[string]ProfileEvidence
}

type FakeProfileCatalog struct {
	mu      sync.Mutex
	max     int
	entries map[string]*profileEntry
	order   []string
}

func NewFakeProfileCatalog(max int) *FakeProfileCatalog {
	if max <= 0 {
		max = MaxFakeCatalogEntries
	}
	if max > MaxFakeCatalogEntries {
		max = MaxFakeCatalogEntries
	}
	return &FakeProfileCatalog{max: max, entries: make(map[string]*profileEntry, max)}
}

func (c *FakeProfileCatalog) AddCompiled(registration ProfileRegistration, artifact lab.CompiledArtifact) error {
	if c == nil {
		return ErrProfileInvalid
	}
	if err := artifact.Validate(); err != nil {
		return fmt.Errorf("%w: compiled artifact: %v", ErrProfileInvalid, err)
	}
	if registration.ID == "" {
		registration.ID = artifact.Profile.ID
	}
	if registration.SHA256 == "" {
		registration.SHA256 = artifact.Profile.SHA256
	}
	if registration.Size == 0 {
		registration.Size = artifact.Profile.Size
	}
	if registration.TLSVersion == 0 {
		registration.TLSVersion = artifact.Profile.TLSVersion
	}
	if registration.ALPN == nil {
		registration.ALPN = append([]string(nil), artifact.Profile.ALPN...)
	}
	registration.ECHPresent = artifact.Profile.ECHPresent
	if registration.Source == "" {
		registration.Source = artifact.Profile.Provenance
	}
	return c.add(registration, artifact)
}

// AddDescriptor registers a metadata-only candidate such as a QUIC Initial
// reference. It cannot be returned as an executable compiled artifact until a
// local artifact is added with AddCompiled using the same ID/hash.
func (c *FakeProfileCatalog) AddDescriptor(registration ProfileRegistration) error {
	return c.add(registration, lab.CompiledArtifact{})
}

func (c *FakeProfileCatalog) add(registration ProfileRegistration, artifact lab.CompiledArtifact) error {
	registration.ID = strings.TrimSpace(registration.ID)
	registration.Source = strings.TrimSpace(registration.Source)
	registration.Provenance = strings.TrimSpace(registration.Provenance)
	registration.License = strings.TrimSpace(registration.License)
	if registration.ID == "" || !validProfileKind(registration.Kind) || registration.Source == "" || registration.Provenance == "" || registration.License == "" || !registration.LicenseReviewed || registration.SHA256 == "" || registration.Size <= 0 {
		if registration.License == "" || !registration.LicenseReviewed {
			return ErrProfileLicense
		}
		return ErrProfileInvalid
	}
	if len(registration.ID) > 128 || len(registration.Provenance) > 256 || len(registration.Source) > 128 || len(registration.License) > 128 {
		return ErrProfileInvalid
	}
	if artifact.Profile.ID != "" && (artifact.Profile.ID != registration.ID || artifact.Profile.SHA256 != registration.SHA256 || artifact.Profile.Size != registration.Size) {
		return ErrProfileInvalid
	}
	profile := CatalogProfile{ID: registration.ID, Kind: registration.Kind, Template: limitString(registration.Template, 128), Source: registration.Source, Provenance: limitString(registration.Provenance, 256), License: registration.License, LicenseReviewed: registration.LicenseReviewed, SHA256: registration.SHA256, Size: registration.Size, TLSVersion: registration.TLSVersion, ALPN: append([]string(nil), registration.ALPN...), ECHPresent: registration.ECHPresent, Active: false, CreatedAt: time.Now()}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[profile.ID]; !exists && len(c.entries) >= c.max {
		return ErrProfileCatalogFull
	}
	if _, exists := c.entries[profile.ID]; !exists {
		c.order = append(c.order, profile.ID)
	}
	c.entries[profile.ID] = &profileEntry{profile: profile, artifact: artifact, evidence: make(map[string]ProfileEvidence)}
	return nil
}

func (c *FakeProfileCatalog) RecordOutcome(id string, observation ProfileObservation) error {
	if c == nil {
		return ErrProfileNotFound
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(observation.TargetProfile) == "" || observation.Samples == 0 || observation.Samples > MaxProfileSamples || observation.Successful > observation.Samples || observation.StableSuccesses > observation.Samples || observation.Amplification < 0 || math.IsNaN(observation.Amplification) || math.IsInf(observation.Amplification, 0) {
		return ErrProfileEvidence
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[id]
	if entry == nil {
		return ErrProfileNotFound
	}
	if _, exists := entry.evidence[observation.TargetProfile]; !exists && len(entry.evidence) >= MaxProfileTargets {
		return ErrProfileEvidence
	}
	current := entry.evidence[observation.TargetProfile]
	if current.Samples > MaxProfileSamples-observation.Samples {
		return ErrProfileEvidence
	}
	current.Samples += observation.Samples
	current.Successful += observation.Successful
	current.StableSuccesses += observation.StableSuccesses
	if observation.CanaryPassed {
		current.CanaryPassed = true
	}
	if observation.Amplification > current.Amplification {
		current.Amplification = observation.Amplification
	}
	if observation.ObservedAt.After(current.LastObservedAt) {
		current.LastObservedAt = observation.ObservedAt
	}
	entry.evidence[observation.TargetProfile] = current
	return nil
}

type ProfileSelectionRequest struct {
	TargetProfile string
	TechniqueID   string
	Kind          FakeProfileKind
	MinSamples    uint64
	RequireCanary bool
	AllowECH      bool
	MaxCandidates int
}

func (c *FakeProfileCatalog) Select(request ProfileSelectionRequest) []ProfileCandidate {
	if c == nil || strings.TrimSpace(request.TargetProfile) == "" {
		return nil
	}
	if request.MinSamples == 0 {
		request.MinSamples = 2
	}
	if request.MaxCandidates <= 0 {
		request.MaxCandidates = 8
	}
	if request.MaxCandidates > 16 {
		request.MaxCandidates = 16
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]ProfileCandidate, 0, request.MaxCandidates)
	for _, id := range c.order {
		entry := c.entries[id]
		if entry == nil || entry.profile.Active || (request.Kind != "" && entry.profile.Kind != request.Kind) || (entry.profile.ECHPresent && !request.AllowECH) || entry.artifact.Profile.ID == "" {
			continue
		}
		evidence, ok := entry.evidence[request.TargetProfile]
		if !ok || evidence.Samples < request.MinSamples || (request.RequireCanary && !evidence.CanaryPassed) {
			continue
		}
		result = append(result, ProfileCandidate{Profile: cloneCatalogProfile(entry.profile), TechniqueID: limitString(request.TechniqueID, 128), TargetProfile: request.TargetProfile, Score: profileScore(evidence), Samples: evidence.Samples, StableSuccesses: evidence.StableSuccesses, PromotionEligible: promotionEligible(entry.evidence), artifact: entry.artifact})
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		return result[i].Profile.ID < result[j].Profile.ID
	})
	if len(result) > request.MaxCandidates {
		result = result[:request.MaxCandidates]
	}
	return result
}

func (c *FakeProfileCatalog) Profiles() []CatalogProfile {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]CatalogProfile, 0, len(c.entries))
	for _, id := range c.order {
		if entry := c.entries[id]; entry != nil {
			result = append(result, cloneCatalogProfile(entry.profile))
		}
	}
	return result
}

func (c *FakeProfileCatalog) Evidence(id string) map[string]ProfileEvidence {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[id]
	if entry == nil {
		return nil
	}
	result := make(map[string]ProfileEvidence, len(entry.evidence))
	for target, evidence := range entry.evidence {
		result[target] = evidence
	}
	return result
}

func (c *FakeProfileCatalog) ExportMetadata() ([]byte, error) {
	profiles := c.Profiles()
	return json.Marshal(profiles)
}

func profileScore(evidence ProfileEvidence) float64 {
	if evidence.Samples == 0 {
		return 0
	}
	successRate := float64(evidence.Successful) / float64(evidence.Samples)
	stableRate := float64(evidence.StableSuccesses) / float64(evidence.Samples)
	canary := 0.0
	if evidence.CanaryPassed {
		canary = 1
	}
	return successRate*60 + stableRate*30 + canary*10
}

func promotionEligible(evidence map[string]ProfileEvidence) bool {
	if len(evidence) < 2 {
		return false
	}
	var samples, stable uint64
	canary := false
	for _, value := range evidence {
		samples += value.Samples
		stable += value.StableSuccesses
		canary = canary || value.CanaryPassed
	}
	return samples >= 3 && stable >= 2 && canary
}

func cloneCatalogProfile(profile CatalogProfile) CatalogProfile {
	profile.ALPN = append([]string(nil), profile.ALPN...)
	return profile
}

func validProfileKind(kind FakeProfileKind) bool {
	switch kind {
	case ProfileGeneratedNeutral, ProfileGoogleLike, ProfileAndroidCaptured, ProfileQUICInitial:
		return true
	default:
		return false
	}
}

func limitString(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}
