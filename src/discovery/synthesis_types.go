package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

const (
	SynthesisGrammarV1      = "afs-grammar-v1"
	SynthesisEngineVersion  = "afs-synth-v1"
	SynthesisProvenanceKind = "synthesized"
)

type SynthesisLimits struct {
	MaxCandidates    uint16
	MaxGenerations   uint8
	MaxActions       uint8
	MaxBranches      uint8
	MaxAmplification float64
	AllowSafeFake    bool
	AllowDisorder    bool
	AllowJitter      bool
}

func DefaultSynthesisLimits() SynthesisLimits {
	return SynthesisLimits{MaxCandidates: 24, MaxGenerations: 3, MaxActions: 4, MaxBranches: 1, MaxAmplification: 1.5, AllowDisorder: true, AllowJitter: true}
}

func (l SynthesisLimits) normalized() SynthesisLimits {
	d := DefaultSynthesisLimits()
	if l.MaxCandidates == 0 {
		l.MaxCandidates = d.MaxCandidates
	}
	if l.MaxGenerations == 0 {
		l.MaxGenerations = d.MaxGenerations
	}
	if l.MaxActions == 0 {
		l.MaxActions = d.MaxActions
	}
	if l.MaxBranches == 0 {
		l.MaxBranches = d.MaxBranches
	}
	if l.MaxAmplification == 0 {
		l.MaxAmplification = d.MaxAmplification
	}
	return l
}

type SynthesisRequest struct {
	RequestID             string
	Scope                 monitor.MonitorScopeKey
	ConfigGeneration      uint64
	BlockingProfileID     string
	BehavioralEvidenceID  string
	FailedCandidateIDs    []string
	BaselineCandidateIDs  []string
	SafeFakeProfileIDs    []string
	AllowedGrammarVersion string
	ResourceBudget        AdaptivePolicy
	Limits                SynthesisLimits
	RequestedAt           time.Time
	ExpiresAt             time.Time
	DeterministicSeed     int64
}

func (r SynthesisRequest) Valid(now time.Time) bool {
	if r.RequestID == "" || !r.Scope.Valid() || r.ConfigGeneration == 0 || r.ConfigGeneration != r.Scope.ConfigGeneration || r.BlockingProfileID == "" || r.BehavioralEvidenceID == "" || r.AllowedGrammarVersion != SynthesisGrammarV1 || r.RequestedAt.IsZero() {
		return false
	}
	if len(r.SafeFakeProfileIDs) > 4 {
		return false
	}
	for _, profileID := range r.SafeFakeProfileIDs {
		if profileID == "" || len(profileID) > 128 {
			return false
		}
	}
	return r.ExpiresAt.IsZero() || now.Before(r.ExpiresAt)
}

type CandidateTrigger struct {
	Phase  string `json:"phase"`
	Marker string `json:"marker,omitempty"`
}

type CandidateOperation struct {
	Family detector.StrategyOperatorFamily `json:"family"`
	Params map[string]string               `json:"params,omitempty"`
}

type CandidateCost struct {
	Actions            uint8   `json:"actions"`
	Branches           uint8   `json:"branches"`
	EstimatedPackets   uint16  `json:"estimated_packets"`
	Amplification      float64 `json:"amplification"`
	HeldBytes          uint32  `json:"held_bytes"`
	CPUUnits           uint32  `json:"cpu_units"`
	LatencyPenaltyMS   uint32  `json:"latency_penalty_ms"`
	RepresentationCost string  `json:"representation_cost"`
}

type CandidateRisk struct {
	Tier        string   `json:"tier"`
	Flags       []string `json:"flags,omitempty"`
	AutomaticOK bool     `json:"automatic_ok"`
}

type CandidateProvenance struct {
	Kind                  string   `json:"kind"`
	FingerprintEvidenceID string   `json:"fingerprint_evidence_id"`
	BlockingProfileID     string   `json:"blocking_profile_id"`
	SeedIDs               []string `json:"seed_ids,omitempty"`
	MutationTrace         []string `json:"mutation_trace,omitempty"`
	SynthesizerVersion    string   `json:"synthesizer_version"`
}

type SynthesizedCandidatePlan struct {
	CandidateID      string                      `json:"candidate_id"`
	Scope            monitor.MonitorScopeKey     `json:"scope"`
	ConfigGeneration uint64                      `json:"config_generation"`
	GrammarVersion   string                      `json:"grammar_version"`
	ParentIDs        []string                    `json:"parent_ids,omitempty"`
	Generation       uint8                       `json:"generation"`
	Trigger          CandidateTrigger            `json:"trigger"`
	Operations       []CandidateOperation        `json:"operations"`
	Representation   action.PacketRepresentation `json:"representation"`
	Preconditions    []string                    `json:"preconditions,omitempty"`
	StaticCost       CandidateCost               `json:"static_cost"`
	Risk             CandidateRisk               `json:"risk"`
	CanonicalHash    string                      `json:"canonical_hash"`
	Provenance       CandidateProvenance         `json:"provenance"`
	CreatedAt        time.Time                   `json:"created_at"`
}

func (p SynthesizedCandidatePlan) ValidIdentity() bool {
	if p.CandidateID == "" || p.CanonicalHash == "" || p.GrammarVersion == "" || !p.Scope.Valid() || p.ConfigGeneration != p.Scope.ConfigGeneration || len(p.Operations) == 0 {
		return false
	}
	h, err := CanonicalCandidateHash(p.GrammarVersion, p.Trigger, p.Operations, p.Representation)
	return err == nil && h == p.CanonicalHash && p.CandidateID == h
}

type canonicalOperation struct {
	Family detector.StrategyOperatorFamily `json:"family"`
	Params [][2]string                     `json:"params,omitempty"`
}

func CanonicalCandidateHash(grammar string, trigger CandidateTrigger, operations []CandidateOperation, representation action.PacketRepresentation) (string, error) {
	if grammar == "" || trigger.Phase == "" || len(operations) == 0 {
		return "", errors.New("incomplete candidate identity")
	}
	canonical := make([]canonicalOperation, 0, len(operations))
	for _, op := range operations {
		if op.Family == "" {
			return "", errors.New("operator family required")
		}
		keys := make([]string, 0, len(op.Params))
		for k := range op.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([][2]string, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, [2]string{k, op.Params[k]})
		}
		canonical = append(canonical, canonicalOperation{Family: op.Family, Params: pairs})
	}
	payload := struct {
		Grammar        string                      `json:"grammar"`
		Trigger        CandidateTrigger            `json:"trigger"`
		Operations     []canonicalOperation        `json:"operations"`
		Representation action.PacketRepresentation `json:"representation"`
	}{grammar, trigger, canonical, representation}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func newSynthesizedCandidate(req SynthesisRequest, generation uint8, parents []string, trigger CandidateTrigger, operations []CandidateOperation, representation action.PacketRepresentation, preconditions []string, cost CandidateCost, risk CandidateRisk, trace []string, now time.Time) (SynthesizedCandidatePlan, error) {
	hash, err := CanonicalCandidateHash(req.AllowedGrammarVersion, trigger, operations, representation)
	if err != nil {
		return SynthesizedCandidatePlan{}, err
	}
	parents = stableUniqueStrings(parents)
	preconditions = stableUniqueStrings(preconditions)
	trace = append([]string(nil), trace...)
	return SynthesizedCandidatePlan{
		CandidateID: hash, Scope: req.Scope, ConfigGeneration: req.ConfigGeneration, GrammarVersion: req.AllowedGrammarVersion,
		ParentIDs: parents, Generation: generation, Trigger: trigger, Operations: cloneCandidateOperations(operations), Representation: representation,
		Preconditions: preconditions, StaticCost: cost, Risk: risk, CanonicalHash: hash,
		Provenance: CandidateProvenance{Kind: SynthesisProvenanceKind, FingerprintEvidenceID: req.BehavioralEvidenceID, BlockingProfileID: req.BlockingProfileID, SeedIDs: parents, MutationTrace: trace, SynthesizerVersion: SynthesisEngineVersion},
		CreatedAt:  now,
	}, nil
}

func cloneCandidateOperations(in []CandidateOperation) []CandidateOperation {
	out := make([]CandidateOperation, len(in))
	for i, op := range in {
		out[i].Family = op.Family
		if op.Params != nil {
			out[i].Params = make(map[string]string, len(op.Params))
			for k, v := range op.Params {
				out[i].Params[k] = v
			}
		}
	}
	return out
}

func stableUniqueStrings(in []string) []string {
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
