package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type StrategyOperatorFamily string

const (
	OperatorTCPSplit              StrategyOperatorFamily = "tcp_split"
	OperatorTLSRecordSplit        StrategyOperatorFamily = "tls_record_split"
	OperatorBoundedDisorder       StrategyOperatorFamily = "bounded_disorder"
	OperatorSafeDuplicateOriginal StrategyOperatorFamily = "safe_duplicate_original"
	OperatorPrePadding            StrategyOperatorFamily = "pre_padding"
	OperatorPostPadding           StrategyOperatorFamily = "post_padding"
	OperatorPerFlowJitter         StrategyOperatorFamily = "per_flow_jitter"
	OperatorSafeFakeProfile       StrategyOperatorFamily = "safe_fake_profile"
)

type BehaviorFeature struct {
	FeatureID    string
	Group        string
	State        string
	Confidence   float64
	Supports     []StrategyOperatorFamily
	Penalizes    []StrategyOperatorFamily
	Excludes     []StrategyOperatorFamily
	EvidenceRefs []string
}

type BehaviorOutcome string

const (
	BehaviorOutcomeOK           BehaviorOutcome = "ok"
	BehaviorOutcomeFail         BehaviorOutcome = "fail"
	BehaviorOutcomeReset        BehaviorOutcome = "reset"
	BehaviorOutcomeStall        BehaviorOutcome = "stall"
	BehaviorOutcomeInconclusive BehaviorOutcome = "inconclusive"
)

type BehaviorAttemptSummary struct {
	ProbeID           string
	Attempt           uint8
	OperatorFamily    StrategyOperatorFamily
	ReferenceBaseline BehaviorOutcome
	TargetBaseline    BehaviorOutcome
	ReferenceMutated  BehaviorOutcome
	TargetMutated     BehaviorOutcome
	Interpretation    string
	Conclusive        bool
	ObservedAt        time.Time
	EvidenceRefs      []string
}

func (a BehaviorAttemptSummary) Valid() bool {
	return a.ProbeID != "" && a.Attempt > 0 && a.OperatorFamily != "" && a.ReferenceBaseline != "" && a.TargetBaseline != "" && a.ReferenceMutated != "" && a.TargetMutated != "" && !a.ObservedAt.IsZero()
}

// ClassifyFourWayBehavior implements the minimum R1/R2/R3/R4 differential
// required by the AFS addendum. The result is evidence only; it never selects
// or executes a strategy.
func ClassifyFourWayBehavior(referenceBaseline, targetBaseline, referenceMutated, targetMutated BehaviorOutcome) (string, bool) {
	if referenceBaseline != BehaviorOutcomeOK {
		return "control-unhealthy", false
	}
	if targetBaseline != BehaviorOutcomeOK && referenceMutated == BehaviorOutcomeOK && targetMutated == BehaviorOutcomeOK {
		return "mutation-bypass-signal", true
	}
	if targetBaseline != BehaviorOutcomeOK && referenceMutated != BehaviorOutcomeOK && targetMutated != BehaviorOutcomeOK {
		return "mutation-breaks-control", false
	}
	if targetBaseline == BehaviorOutcomeOK && referenceMutated == BehaviorOutcomeOK && targetMutated != BehaviorOutcomeOK {
		return "mutation-target-regression", true
	}
	return "inconclusive", false
}

type BehavioralFingerprintEvidence struct {
	EvidenceID          string
	Scope               monitor.MonitorScopeKey
	NetworkContextID    string
	ConfigGeneration    uint64
	ProbeCatalogVersion string
	PanelHash           string
	FeatureVectorHash   string

	Features  []BehaviorFeature
	Attempts  []BehaviorAttemptSummary
	Confidence float64
	NoiseScore float64

	ConclusiveCount   uint16
	InconclusiveCount uint16
	CreatedAt         time.Time
	ValidUntil        time.Time
	EvidenceRefs      []string
}

func (e BehavioralFingerprintEvidence) Valid(now time.Time) bool {
	if e.EvidenceID == "" || !e.Scope.Valid() || e.NetworkContextID == "" || e.ConfigGeneration == 0 || e.ProbeCatalogVersion == "" || e.PanelHash == "" || e.FeatureVectorHash == "" || e.CreatedAt.IsZero() {
		return false
	}
	if e.NetworkContextID != e.Scope.NetworkContextID || e.ConfigGeneration != e.Scope.ConfigGeneration {
		return false
	}
	if e.Confidence < 0 || e.Confidence > 1 || e.NoiseScore < 0 || e.NoiseScore > 1 {
		return false
	}
	if len(e.Features) == 0 || e.ConclusiveCount == 0 || int(e.ConclusiveCount)+int(e.InconclusiveCount) != len(e.Attempts) {
		return false
	}
	for _, a := range e.Attempts {
		if !a.Valid() {
			return false
		}
	}
	return e.ValidUntil.IsZero() || now.Before(e.ValidUntil)
}

func NewBehavioralFingerprintEvidence(scope monitor.MonitorScopeKey, catalogVersion string, features []BehaviorFeature, attempts []BehaviorAttemptSummary, confidence, noise float64, validUntil, now time.Time) BehavioralFingerprintEvidence {
	features = normalizeBehaviorFeatures(features)
	attempts = normalizeBehaviorAttempts(attempts)
	featureRaw, _ := json.Marshal(features)
	featureHashRaw := sha256.Sum256(featureRaw)
	featureHash := hex.EncodeToString(featureHashRaw[:])

	panelIDs := make([]string, 0, len(attempts))
	var conclusive, inconclusive uint16
	refs := make([]string, 0)
	for _, a := range attempts {
		panelIDs = append(panelIDs, a.ProbeID)
		if a.Conclusive {
			conclusive++
		} else {
			inconclusive++
		}
		refs = append(refs, a.EvidenceRefs...)
	}
	panelIDs = uniqueStrings(panelIDs)
	panelRaw, _ := json.Marshal(struct {
		Catalog string
		Probes  []string
	}{catalogVersion, panelIDs})
	panelHashRaw := sha256.Sum256(panelRaw)
	panelHash := hex.EncodeToString(panelHashRaw[:])

	idRaw, _ := json.Marshal(struct {
		Scope       monitor.MonitorScopeKey
		Catalog     string
		PanelHash   string
		FeatureHash string
	}{scope, catalogVersion, panelHash, featureHash})
	idHash := sha256.Sum256(idRaw)

	for _, f := range features {
		refs = append(refs, f.EvidenceRefs...)
	}
	return BehavioralFingerprintEvidence{
		EvidenceID:          "bf-" + hex.EncodeToString(idHash[:8]),
		Scope:               scope,
		NetworkContextID:    scope.NetworkContextID,
		ConfigGeneration:    scope.ConfigGeneration,
		ProbeCatalogVersion: catalogVersion,
		PanelHash:           panelHash,
		FeatureVectorHash:   featureHash,
		Features:            features,
		Attempts:            attempts,
		Confidence:          confidence,
		NoiseScore:          noise,
		ConclusiveCount:     conclusive,
		InconclusiveCount:   inconclusive,
		CreatedAt:           now,
		ValidUntil:          validUntil,
		EvidenceRefs:        uniqueStrings(refs),
	}
}

func normalizeBehaviorFeatures(in []BehaviorFeature) []BehaviorFeature {
	out := append([]BehaviorFeature(nil), in...)
	for i := range out {
		out[i].Supports = uniqueOperatorFamilies(out[i].Supports)
		out[i].Penalizes = uniqueOperatorFamilies(out[i].Penalizes)
		out[i].Excludes = uniqueOperatorFamilies(out[i].Excludes)
		out[i].EvidenceRefs = uniqueStrings(out[i].EvidenceRefs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FeatureID < out[j].FeatureID })
	return out
}

func normalizeBehaviorAttempts(in []BehaviorAttemptSummary) []BehaviorAttemptSummary {
	out := append([]BehaviorAttemptSummary(nil), in...)
	for i := range out {
		out[i].EvidenceRefs = uniqueStrings(out[i].EvidenceRefs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProbeID != out[j].ProbeID {
			return out[i].ProbeID < out[j].ProbeID
		}
		return out[i].Attempt < out[j].Attempt
	})
	return out
}

func uniqueOperatorFamilies(in []StrategyOperatorFamily) []StrategyOperatorFamily {
	seen := map[StrategyOperatorFamily]struct{}{}
	out := make([]StrategyOperatorFamily, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
