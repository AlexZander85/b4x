package detector

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/monitor"
)

type BehavioralProbeMutation struct {
	ProbeID string
	Family  StrategyOperatorFamily
	Params  map[string]string
}

func (p BehavioralProbeMutation) Valid() bool {
	return p.ProbeID != "" && p.Family != ""
}

type BehavioralProbeCase struct {
	ProbeID string
	Attempt uint8
	Role    string // reference | target
	Mutated bool
	Family  StrategyOperatorFamily
	Params  map[string]string
}

type BehavioralProbeResult struct {
	Outcome     BehaviorOutcome
	EvidenceRef string
	ObservedAt  time.Time
}

type BehavioralProbeRunner func(context.Context, BehavioralProbeCase) (BehavioralProbeResult, error)

// RunBehavioralPanel orchestrates the addendum's R1/R2/R3/R4 differential
// over an injected existing probe runner. It does not own sockets, packet
// execution, sandbox resources or strategy selection.
func RunBehavioralPanel(ctx context.Context, scope monitor.MonitorScopeKey, catalogVersion string, mutations []BehavioralProbeMutation, policy config.BehavioralFingerprintingConfig, validUntil, now time.Time, runner BehavioralProbeRunner) (BehavioralFingerprintEvidence, error) {
	if ctx == nil {
		return BehavioralFingerprintEvidence{}, errors.New("behavioral panel context required")
	}
	if !scope.Valid() || catalogVersion == "" || runner == nil {
		return BehavioralFingerprintEvidence{}, errors.New("behavioral panel scope, catalog and runner are required")
	}
	if policy.MaxProbes == 0 || policy.AttemptsPerProbe == 0 || policy.MaxDuration <= 0 {
		return BehavioralFingerprintEvidence{}, errors.New("behavioral panel requires bounded policy")
	}
	if policy.Concurrency != 1 {
		return BehavioralFingerprintEvidence{}, errors.New("automatic behavioral panel requires concurrency=1")
	}
	if len(mutations) == 0 {
		return BehavioralFingerprintEvidence{}, errors.New("behavioral panel has no mutations")
	}
	if len(mutations) > int(policy.MaxProbes) {
		mutations = append([]BehavioralProbeMutation(nil), mutations[:policy.MaxProbes]...)
	} else {
		mutations = append([]BehavioralProbeMutation(nil), mutations...)
	}
	for _, mutation := range mutations {
		if !mutation.Valid() {
			return BehavioralFingerprintEvidence{}, errors.New("behavioral panel contains invalid mutation")
		}
	}
	sort.SliceStable(mutations, func(i, j int) bool { return mutations[i].ProbeID < mutations[j].ProbeID })

	panelCtx, cancel := context.WithTimeout(ctx, policy.MaxDuration)
	defer cancel()
	attempts := make([]BehaviorAttemptSummary, 0, len(mutations)*int(policy.AttemptsPerProbe))
	for _, mutation := range mutations {
		for attempt := uint8(1); attempt <= policy.AttemptsPerProbe; attempt++ {
			if err := panelCtx.Err(); err != nil {
				return BehavioralFingerprintEvidence{}, fmt.Errorf("behavioral panel bounded execution: %w", err)
			}
			r1, err := runBehaviorCase(panelCtx, runner, mutation, attempt, "reference", false)
			if err != nil {
				return BehavioralFingerprintEvidence{}, err
			}
			if err := waitBehavioralDelay(panelCtx, policy.InterProbeDelay); err != nil {
				return BehavioralFingerprintEvidence{}, err
			}
			r2, err := runBehaviorCase(panelCtx, runner, mutation, attempt, "target", false)
			if err != nil {
				return BehavioralFingerprintEvidence{}, err
			}
			if err := waitBehavioralDelay(panelCtx, policy.InterProbeDelay); err != nil {
				return BehavioralFingerprintEvidence{}, err
			}
			r3, err := runBehaviorCase(panelCtx, runner, mutation, attempt, "reference", true)
			if err != nil {
				return BehavioralFingerprintEvidence{}, err
			}
			if err := waitBehavioralDelay(panelCtx, policy.InterProbeDelay); err != nil {
				return BehavioralFingerprintEvidence{}, err
			}
			r4, err := runBehaviorCase(panelCtx, runner, mutation, attempt, "target", true)
			if err != nil {
				return BehavioralFingerprintEvidence{}, err
			}
			interpretation, conclusive := ClassifyFourWayBehavior(r1.Outcome, r2.Outcome, r3.Outcome, r4.Outcome)
			observedAt := latestBehaviorTime(r1.ObservedAt, r2.ObservedAt, r3.ObservedAt, r4.ObservedAt)
			attempts = append(attempts, BehaviorAttemptSummary{
				ProbeID: mutation.ProbeID, Attempt: attempt, OperatorFamily: mutation.Family,
				ReferenceBaseline: r1.Outcome, TargetBaseline: r2.Outcome,
				ReferenceMutated: r3.Outcome, TargetMutated: r4.Outcome,
				Interpretation: interpretation, Conclusive: conclusive, ObservedAt: observedAt,
				EvidenceRefs: uniqueStrings([]string{r1.EvidenceRef, r2.EvidenceRef, r3.EvidenceRef, r4.EvidenceRef}),
			})
			if err := waitBehavioralDelay(panelCtx, policy.InterProbeDelay); err != nil {
				return BehavioralFingerprintEvidence{}, err
			}
		}
	}

	features, confidence, noise := behaviorFeaturesFromAttempts(attempts)
	if len(features) == 0 {
		return BehavioralFingerprintEvidence{}, errors.New("behavioral panel produced no conclusive operator features")
	}
	if noise > policy.MaxInconclusiveRatio {
		return BehavioralFingerprintEvidence{}, fmt.Errorf("behavioral panel noise %.3f exceeds bound %.3f", noise, policy.MaxInconclusiveRatio)
	}
	evidence := NewBehavioralFingerprintEvidence(scope, catalogVersion, features, attempts, confidence, noise, validUntil, now)
	if !evidence.Valid(now) {
		return BehavioralFingerprintEvidence{}, errors.New("behavioral panel produced invalid evidence")
	}
	return evidence, nil
}

func runBehaviorCase(ctx context.Context, runner BehavioralProbeRunner, mutation BehavioralProbeMutation, attempt uint8, role string, mutated bool) (BehavioralProbeResult, error) {
	result, err := runner(ctx, BehavioralProbeCase{ProbeID: mutation.ProbeID, Attempt: attempt, Role: role, Mutated: mutated, Family: mutation.Family, Params: cloneStringMap(mutation.Params)})
	if err != nil {
		return BehavioralProbeResult{}, fmt.Errorf("behavioral probe %s attempt %d role=%s mutated=%t: %w", mutation.ProbeID, attempt, role, mutated, err)
	}
	if result.Outcome == "" || result.ObservedAt.IsZero() || result.EvidenceRef == "" {
		return BehavioralProbeResult{}, errors.New("behavioral probe returned incomplete result")
	}
	return result, nil
}

func waitBehavioralDelay(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func behaviorFeaturesFromAttempts(attempts []BehaviorAttemptSummary) ([]BehaviorFeature, float64, float64) {
	type aggregate struct {
		family                                       StrategyOperatorFamily
		support, penalty, exclude, conclusive, total int
		refs                                         []string
	}
	byFamily := map[StrategyOperatorFamily]*aggregate{}
	inconclusive := 0
	for _, attempt := range attempts {
		a := byFamily[attempt.OperatorFamily]
		if a == nil {
			a = &aggregate{family: attempt.OperatorFamily}
			byFamily[attempt.OperatorFamily] = a
		}
		a.total++
		a.refs = append(a.refs, attempt.EvidenceRefs...)
		if !attempt.Conclusive {
			inconclusive++
			continue
		}
		a.conclusive++
		switch attempt.Interpretation {
		case "mutation-bypass-signal":
			a.support++
		case "mutation-target-regression":
			a.exclude++
		case "mutation-breaks-control":
			a.penalty++
		}
	}
	families := make([]StrategyOperatorFamily, 0, len(byFamily))
	for family := range byFamily {
		families = append(families, family)
	}
	sort.Slice(families, func(i, j int) bool { return families[i] < families[j] })
	features := make([]BehaviorFeature, 0, len(families))
	totalConclusive := 0
	for _, family := range families {
		a := byFamily[family]
		if a.conclusive == 0 {
			continue
		}
		feature := BehaviorFeature{FeatureID: "operator-response/" + string(family), Group: "operator-response", Confidence: float64(a.conclusive) / float64(a.total), EvidenceRefs: uniqueStrings(a.refs)}
		switch {
		case a.exclude > 0:
			feature.State = "target-regression"
			feature.Excludes = []StrategyOperatorFamily{family}
		case a.support > 0:
			feature.State = "bypass-signal"
			feature.Supports = []StrategyOperatorFamily{family}
		case a.penalty > 0:
			feature.State = "control-sensitive"
			feature.Penalizes = []StrategyOperatorFamily{family}
		default:
			continue
		}
		features = append(features, feature)
		totalConclusive += a.conclusive
	}
	if len(attempts) == 0 {
		return features, 0, 1
	}
	noise := float64(inconclusive) / float64(len(attempts))
	confidence := float64(totalConclusive) / float64(len(attempts))
	return features, confidence, noise
}

func latestBehaviorTime(values ...time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if value.After(latest) {
			latest = value
		}
	}
	return latest
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
