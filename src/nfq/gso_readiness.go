package nfq

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/observability"
	"github.com/google/uuid"
)

// GSOReadinessState is the current-generation GSO_CLASSIFY_READY verdict.
type GSOReadinessState string

const (
	GSOReadinessReady   GSOReadinessState = "READY"
	GSOReadinessUnknown GSOReadinessState = "UNKNOWN"
	GSOReadinessStale   GSOReadinessState = "STALE"
	GSOReadinessFail    GSOReadinessState = "FAIL"
)

// GSOReadinessSnapshot is the NFQ/runtime-owned, current-generation readiness
// contract consumed by the validation API and the local control plane. It is
// a value snapshot: classification is allowed only while State == READY, and
// any UNKNOWN/STALE/FAIL verdict forces an automatic classify-to-observe
// downgrade. Classify readiness never authorizes normalization or mutation.
type GSOReadinessSnapshot struct {
	State                        GSOReadinessState `json:"state"`
	ConfigGeneration             uint64            `json:"config_generation"`
	ProcessInstanceID            string            `json:"process_instance_id"`
	EvidenceHash                 string            `json:"evidence_hash"`
	EvaluatedAt                  time.Time         `json:"evaluated_at"`
	Reasons                      []string          `json:"reasons,omitempty"`
	MetadataEnvelopeReady        bool              `json:"metadata_envelope_ready"`
	RepresentationParityReady    bool              `json:"representation_parity_ready"`
	IPv4Ready                    bool              `json:"ipv4_ready"`
	IPv6State                    string            `json:"ipv6_state"`
	RetransmissionReady          bool              `json:"retransmission_ready"`
	ResourceBudgetsReady         bool              `json:"resource_budgets_ready"`
	QueueDropBudgetReady         bool              `json:"queue_drop_budget_ready"`
	PPEVisibilityState           string            `json:"ppe_visibility_state"`
	ProductionEntryPointVerified bool              `json:"production_entry_point_verified"`
}

// GSOReadinessEvidence carries the observable signals evaluated for the
// GSO_CLASSIFY_READY verdict of the current configuration generation.
//
// Wire observations (packet path) are sticky: once an envelope is seen, a
// truncation or a checksum-not-ready is observed, or a budget violation is
// reported, the fact survives every later Set. Static proof (parity, budgets,
// visibility, entry point) is provided by the operator/control plane.
type GSOReadinessEvidence struct {
	Generation uint64
	// Wire observations (packet path / runtime).
	MetadataEnvelopeSeen     bool
	TruncationObserved       bool
	ChecksumNotReadyObserved bool
	ResourceBudgetViolated   bool
	QueueDropBudgetViolated  bool
	// Static proof (operator/control plane).
	RepresentationParityProven   bool
	IPv4Ready                    bool
	IPv6State                    string // "proven", "unsupported", or "" (not proven)
	RetransmissionProven         bool
	ResourceBudgetsProven        bool
	QueueDropBudgetProven        bool
	PPEVisibilityState           string // "complete", "incomplete", "not-required", or "" (unknown)
	ProductionEntryPointVerified bool
}

// defaultGSOReadinessStaleness is the maximum age of the evaluated evidence
// before the gate treats the verdict as stale and downgrades to observe.
const defaultGSOReadinessStaleness = 30 * time.Second

// EvaluateGSOClassifyReadiness derives the current-generation verdict from
// the evidence. Observed violations (truncation, checksum-not-ready, budget
// violations, incomplete PPE visibility) yield FAIL; missing proof yields
// UNKNOWN; a fully proven envelope yields READY.
func EvaluateGSOClassifyReadiness(evidence GSOReadinessEvidence, now time.Time) GSOReadinessSnapshot {
	reasons := collectGSOReadinessReasons(evidence)
	state := GSOReadinessReady
	if len(reasons) > 0 {
		if gsoReadinessHasHardFailure(evidence) {
			state = GSOReadinessFail
		} else {
			state = GSOReadinessUnknown
		}
	}
	return GSOReadinessSnapshot{
		State:                        state,
		ConfigGeneration:             evidence.Generation,
		EvidenceHash:                 gsoReadinessEvidenceHash(evidence),
		EvaluatedAt:                  now,
		Reasons:                      reasons,
		MetadataEnvelopeReady:        evidence.MetadataEnvelopeSeen && !evidence.TruncationObserved && !evidence.ChecksumNotReadyObserved,
		RepresentationParityReady:    evidence.RepresentationParityProven,
		IPv4Ready:                    evidence.IPv4Ready,
		IPv6State:                    evidence.IPv6State,
		RetransmissionReady:          evidence.RetransmissionProven,
		ResourceBudgetsReady:         evidence.ResourceBudgetsProven && !evidence.ResourceBudgetViolated,
		QueueDropBudgetReady:         evidence.QueueDropBudgetProven && !evidence.QueueDropBudgetViolated,
		PPEVisibilityState:           evidence.PPEVisibilityState,
		ProductionEntryPointVerified: evidence.ProductionEntryPointVerified,
	}
}

// collectGSOReadinessReasons lists every unsatisfied readiness requirement.
func collectGSOReadinessReasons(evidence GSOReadinessEvidence) []string {
	reasons := make([]string, 0, 12)
	if !evidence.MetadataEnvelopeSeen {
		reasons = append(reasons, "no NFQUEUE GSO metadata envelope observed")
	}
	if evidence.TruncationObserved {
		reasons = append(reasons, "truncation/length ambiguity observed")
	}
	if evidence.ChecksumNotReadyObserved {
		reasons = append(reasons, "checksum-not-ready observed")
	}
	if !evidence.RepresentationParityProven {
		reasons = append(reasons, "GSO/MSS representation parity not proven")
	}
	if !evidence.IPv4Ready {
		reasons = append(reasons, "IPv4 classification readiness not proven")
	}
	if evidence.IPv6State == "" {
		reasons = append(reasons, "IPv6 coverage not proven")
	}
	if !evidence.RetransmissionProven {
		reasons = append(reasons, "retransmission/out-of-order idempotency not proven")
	}
	if evidence.ResourceBudgetViolated {
		reasons = append(reasons, "resource budget violation observed")
	} else if !evidence.ResourceBudgetsProven {
		reasons = append(reasons, "resource budgets not proven")
	}
	if evidence.QueueDropBudgetViolated {
		reasons = append(reasons, "queue/user drop budget violation observed")
	} else if !evidence.QueueDropBudgetProven {
		reasons = append(reasons, "queue/user drop budgets not proven")
	}
	switch evidence.PPEVisibilityState {
	case "complete", "not-required":
	case "incomplete":
		reasons = append(reasons, "PPE capture visibility incomplete")
	default:
		reasons = append(reasons, "PPE visibility unknown")
	}
	if !evidence.ProductionEntryPointVerified {
		reasons = append(reasons, "production packet entry point not verified")
	}
	return reasons
}

// gsoReadinessHasHardFailure reports observed violations that must never be
// classified away: anything seen on the wire or reported by the runtime that
// contradicts the envelope.
func gsoReadinessHasHardFailure(evidence GSOReadinessEvidence) bool {
	return evidence.TruncationObserved || evidence.ChecksumNotReadyObserved ||
		evidence.ResourceBudgetViolated || evidence.QueueDropBudgetViolated ||
		evidence.PPEVisibilityState == "incomplete"
}

// gsoReadinessEvidenceHash is a deterministic digest of the evaluated
// evidence; identical evidence always yields the identical hash.
func gsoReadinessEvidenceHash(evidence GSOReadinessEvidence) string {
	var b strings.Builder
	fmt.Fprintf(&b, "gen=%d|env=%t|trunc=%t|csum=%t|parity=%t|v4=%t|v6=%s|retrans=%t|budget=%t|budgetv=%t|drop=%t|dropv=%t|ppe=%s|entry=%t",
		evidence.Generation, evidence.MetadataEnvelopeSeen, evidence.TruncationObserved, evidence.ChecksumNotReadyObserved,
		evidence.RepresentationParityProven, evidence.IPv4Ready, evidence.IPv6State, evidence.RetransmissionProven,
		evidence.ResourceBudgetsProven, evidence.ResourceBudgetViolated, evidence.QueueDropBudgetProven,
		evidence.QueueDropBudgetViolated, evidence.PPEVisibilityState, evidence.ProductionEntryPointVerified)
	sum := sha256.Sum256([]byte(b.String()))
	return "gso-" + hex.EncodeToString(sum[:12])
}

// SetGSOReadinessEvidence records the static (operator/control-plane) part of
// the readiness evidence and re-evaluates the snapshot. Wire observations
// made so far are merged in: they are sticky and survive every later Set.
func (w *Worker) SetGSOReadinessEvidence(evidence GSOReadinessEvidence) GSOReadinessSnapshot {
	if w == nil {
		return GSOReadinessSnapshot{State: GSOReadinessUnknown}
	}
	w.gsoReadinessMu.Lock()
	defer w.gsoReadinessMu.Unlock()
	merged := evidence
	merged.MetadataEnvelopeSeen = w.gsoReadinessEv.MetadataEnvelopeSeen || evidence.MetadataEnvelopeSeen
	merged.TruncationObserved = w.gsoReadinessEv.TruncationObserved || evidence.TruncationObserved
	merged.ChecksumNotReadyObserved = w.gsoReadinessEv.ChecksumNotReadyObserved || evidence.ChecksumNotReadyObserved
	merged.ResourceBudgetViolated = w.gsoReadinessEv.ResourceBudgetViolated || evidence.ResourceBudgetViolated
	merged.QueueDropBudgetViolated = w.gsoReadinessEv.QueueDropBudgetViolated || evidence.QueueDropBudgetViolated
	w.gsoReadinessEv = merged
	return w.rebuildGSOReadinessSnapshotLocked(time.Now())
}

// observeGSOReadinessMetadata folds one packet-path capture envelope into the
// evidence and re-evaluates the snapshot.
func (w *Worker) observeGSOReadinessMetadata(metadata OffloadMetadata) {
	if w == nil {
		return
	}
	w.gsoReadinessMu.Lock()
	defer w.gsoReadinessMu.Unlock()
	ev := w.gsoReadinessEv
	ev.MetadataEnvelopeSeen = true
	if metadata.Truncated {
		ev.TruncationObserved = true
	}
	if metadata.ChecksumNotReady {
		ev.ChecksumNotReadyObserved = true
	}
	w.gsoReadinessEv = ev
	w.rebuildGSOReadinessSnapshotLocked(time.Now())
}

// GSOReadinessSnapshot returns the current snapshot. A worker that never
// received evidence reports UNKNOWN with an empty process instance id.
func (w *Worker) GSOReadinessSnapshot() GSOReadinessSnapshot {
	if w == nil {
		return GSOReadinessSnapshot{State: GSOReadinessUnknown}
	}
	w.gsoReadinessMu.Lock()
	defer w.gsoReadinessMu.Unlock()
	if w.gsoReadinessSnap.State == "" {
		w.gsoReadinessSnap = EvaluateGSOClassifyReadiness(w.gsoReadinessEv, time.Time{})
	}
	return w.gsoReadinessSnap
}

// gsoClassifyReady is the current-generation gate: classification is allowed
// only for a fresh READY verdict of the active configuration generation.
func (w *Worker) gsoClassifyReady(generation uint64) (bool, string) {
	if w == nil {
		return false, "GSO_CLASSIFY_READY UNKNOWN: worker unavailable"
	}
	w.gsoReadinessMu.Lock()
	defer w.gsoReadinessMu.Unlock()
	snap := w.gsoReadinessSnap
	if snap.State == "" {
		snap = EvaluateGSOClassifyReadiness(w.gsoReadinessEv, time.Time{})
		w.gsoReadinessSnap = snap
	}
	if snap.ConfigGeneration == 0 {
		return false, "GSO_CLASSIFY_READY UNKNOWN: no readiness evidence for the current process instance"
	}
	if snap.ConfigGeneration != generation {
		return false, "GSO_CLASSIFY_READY STALE: readiness generation " + strconv.FormatUint(snap.ConfigGeneration, 10) + ", active " + strconv.FormatUint(generation, 10)
	}
	if time.Since(snap.EvaluatedAt) > defaultGSOReadinessStaleness {
		return false, "GSO_CLASSIFY_READY STALE: evidence older than " + defaultGSOReadinessStaleness.String()
	}
	if snap.State != GSOReadinessReady {
		reasons := strings.Join(snap.Reasons, "; ")
		if reasons == "" {
			reasons = "insufficient evidence"
		}
		return false, "GSO_CLASSIFY_READY " + string(snap.State) + ": " + reasons
	}
	return true, ""
}

// downgradeGSOCapability performs the automatic classify-to-observe downgrade
// when the current-generation readiness verdict is not READY. Idempotent.
func (w *Worker) downgradeGSOCapability(reason string) {
	if w == nil {
		return
	}
	switch w.GSOCapabilityStatus().Level {
	case GSOCapabilityUnsupported, GSOCapabilitySupportedUnvalidated, GSOCapabilityObserveOnly, GSOCapabilityFailed:
		return
	}
	w.setGSOCapabilityStatus(GSOCapabilityObserveOnly, reason)
	observability.Default().Metrics.Inc(observability.MetricNFQueueGSOTransition, map[string]string{
		"transition": "classify-to-observe",
		"reason":     sanitizeGSOMetricReason(reason),
	}, 1)
}

func (w *Worker) rebuildGSOReadinessSnapshotLocked(evaluatedAt time.Time) GSOReadinessSnapshot {
	snap := EvaluateGSOClassifyReadiness(w.gsoReadinessEv, evaluatedAt)
	snap.ProcessInstanceID = w.gsoProcessInstanceIDLocked()
	w.gsoReadinessSnap = snap
	return snap
}

func (w *Worker) gsoProcessInstanceIDLocked() string {
	if w.gsoInstanceID == "" {
		w.gsoInstanceID = "b4-" + uuid.NewString()
	}
	return w.gsoInstanceID
}

// gsoReadinessRank orders verdicts from worst to best for pool aggregation.
func gsoReadinessRank(state GSOReadinessState) int {
	switch state {
	case GSOReadinessFail:
		return 0
	case GSOReadinessStale:
		return 1
	case GSOReadinessUnknown:
		return 2
	case GSOReadinessReady:
		return 3
	default:
		return 0
	}
}
