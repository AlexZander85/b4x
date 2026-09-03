package nfq

import (
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/fixtures"
)

func fullGSOReadinessEvidence(generation uint64) GSOReadinessEvidence {
	return GSOReadinessEvidence{
		Generation:                   generation,
		MetadataEnvelopeSeen:         true,
		RepresentationParityProven:   true,
		IPv4Ready:                    true,
		IPv6State:                    "proven",
		RetransmissionProven:         true,
		ResourceBudgetsProven:        true,
		QueueDropBudgetProven:        true,
		PPEVisibilityState:           "complete",
		ProductionEntryPointVerified: true,
	}
}

func TestEvaluateGSOClassifyReadinessReady(t *testing.T) {
	now := time.Now()
	snap := EvaluateGSOClassifyReadiness(fullGSOReadinessEvidence(7), now)
	if snap.State != GSOReadinessReady {
		t.Fatalf("state=%s want READY, reasons=%v", snap.State, snap.Reasons)
	}
	if len(snap.Reasons) != 0 {
		t.Fatalf("reasons=%v want none", snap.Reasons)
	}
	if snap.ConfigGeneration != 7 || snap.ProcessInstanceID != "" {
		t.Fatalf("generation=%d instance=%q", snap.ConfigGeneration, snap.ProcessInstanceID)
	}
	if snap.EvidenceHash == "" || snap.EvidenceHash[:4] != "gso-" {
		t.Fatalf("evidence hash=%q", snap.EvidenceHash)
	}
	if !snap.MetadataEnvelopeReady || !snap.RepresentationParityReady || !snap.IPv4Ready ||
		snap.IPv6State != "proven" || !snap.RetransmissionReady || !snap.ResourceBudgetsReady ||
		!snap.QueueDropBudgetReady || snap.PPEVisibilityState != "complete" || !snap.ProductionEntryPointVerified {
		t.Fatalf("ready flags not reflected: %+v", snap)
	}
	if !snap.EvaluatedAt.Equal(now) {
		t.Fatalf("evaluated_at=%v want %v", snap.EvaluatedAt, now)
	}
}

func TestEvaluateGSOClassifyReadinessUnknownWithoutProof(t *testing.T) {
	evidence := GSOReadinessEvidence{
		Generation:           7,
		MetadataEnvelopeSeen: true,
	}
	snap := EvaluateGSOClassifyReadiness(evidence, time.Now())
	if snap.State != GSOReadinessUnknown {
		t.Fatalf("state=%s want UNKNOWN, reasons=%v", snap.State, snap.Reasons)
	}
	if snap.MetadataEnvelopeReady != true {
		t.Fatalf("metadata envelope should be ready")
	}
	for _, want := range []string{"representation parity", "IPv4", "IPv6", "retransmission", "budgets", "entry point", "PPE"} {
		if !containsAny(snap.Reasons, want) {
			t.Fatalf("missing reason %q in %v", want, snap.Reasons)
		}
	}
}

func TestEvaluateGSOClassifyReadinessFail(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*GSOReadinessEvidence)
		failWord string
	}{
		{"truncation", func(e *GSOReadinessEvidence) { e.TruncationObserved = true }, "truncation"},
		{"checksum", func(e *GSOReadinessEvidence) { e.ChecksumNotReadyObserved = true }, "checksum"},
		{"budget-violation", func(e *GSOReadinessEvidence) { e.ResourceBudgetViolated = true }, "budget violation"},
		{"drop-budget-violation", func(e *GSOReadinessEvidence) { e.QueueDropBudgetViolated = true }, "drop budget violation"},
		{"ppe-incomplete", func(e *GSOReadinessEvidence) { e.PPEVisibilityState = "incomplete" }, "PPE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evidence := fullGSOReadinessEvidence(7)
			tc.mutate(&evidence)
			snap := EvaluateGSOClassifyReadiness(evidence, time.Now())
			if snap.State != GSOReadinessFail {
				t.Fatalf("state=%s want FAIL, reasons=%v", snap.State, snap.Reasons)
			}
			if !containsAny(snap.Reasons, tc.failWord) {
				t.Fatalf("missing fail reason %q in %v", tc.failWord, snap.Reasons)
			}
		})
	}
}

func TestEvaluateGSOClassifyReadinessIPv6UnsupportedAllowed(t *testing.T) {
	evidence := fullGSOReadinessEvidence(7)
	evidence.IPv6State = "unsupported"
	snap := EvaluateGSOClassifyReadiness(evidence, time.Now())
	if snap.State != GSOReadinessReady {
		t.Fatalf("state=%s want READY (IPv6 unsupported is a stack property), reasons=%v", snap.State, snap.Reasons)
	}
}

func TestEvaluateGSOReadinessDeterministicHash(t *testing.T) {
	a := fullGSOReadinessEvidence(9)
	b := fullGSOReadinessEvidence(9)
	if h1, h2 := gsoReadinessEvidenceHash(a), gsoReadinessEvidenceHash(b); h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	c := fullGSOReadinessEvidence(10)
	if h1, h3 := gsoReadinessEvidenceHash(a), gsoReadinessEvidenceHash(c); h1 == h3 {
		t.Fatalf("hash should differ across generations: %q", h1)
	}
}

func TestWorkerGSOClassifyReadyGateAndAutomaticDowngrade(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeFull, true, false)
	generation := dnsHintConfigGeneration(cfg)
	w := NewWorkerWithQueue(cfg, 0)
	w.setGSOCapabilityStatus(GSOCapabilityClassifyReady, "unit target capability")

	// Without evidence the gate must reject and downgrade to observe-only.
	if ok, reason := w.gsoClassifyReady(generation); ok || !containsAny([]string{reason}, "no readiness evidence") {
		t.Fatalf("gate ok=%t reason=%q want rejection without evidence", ok, reason)
	}
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1988)
	pkt := testGSOPacket(len(hello), 56000)
	vc := &verdictCtx{verdict: engine.VerdictAccept}
	handled, _, result := w.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 56000, 443, 12345, true)
	if !handled || result != gsoPathCapabilityFailOpen {
		t.Fatalf("handled=%t result=%s want capability-fail-open", handled, result)
	}
	if level := w.GSOCapabilityStatus().Level; level != GSOCapabilityObserveOnly {
		t.Fatalf("capability=%s want observe-only after automatic downgrade", level)
	}

	// A fresh full READY verdict re-enables classification.
	w.setGSOCapabilityStatus(GSOCapabilityClassifyReady, "unit target capability")
	w.SetGSOReadinessEvidence(fullGSOReadinessEvidence(generation))
	if ok, reason := w.gsoClassifyReady(generation); !ok {
		t.Fatalf("gate ok=false reason=%q want ready", reason)
	}

	// Hard failure observed on the wire downgrades again.
	bad := testGSOPacket(len(hello), 56000)
	bad.offload.Truncated = true
	bad.offload.OriginalLength = uint32(len(hello)) + 128
	w.observeGSOReadinessMetadata(bad.offload)
	if ok, _ := w.gsoClassifyReady(generation); ok {
		t.Fatalf("gate passed despite truncation evidence")
	}
	handled, _, result = w.handleGSOFastPath(vc, pkt, cfg, buildMatcher(cfg), hello, 56000, 443, 12345, true)
	if !handled || result != gsoPathCapabilityFailOpen {
		t.Fatalf("handled=%t result=%s want capability-fail-open after truncation", handled, result)
	}
	if level := w.GSOCapabilityStatus().Level; level != GSOCapabilityObserveOnly {
		t.Fatalf("capability=%s want observe-only after truncation downgrade", level)
	}
}

func TestWorkerGSOClassifyReadyGenerationMismatch(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeFull, true, false)
	w := NewWorkerWithQueue(cfg, 0)
	w.SetGSOReadinessEvidence(fullGSOReadinessEvidence(5))
	if ok, reason := w.gsoClassifyReady(5); !ok {
		t.Fatalf("same-generation gate ok=false reason=%q", reason)
	}
	if ok, reason := w.gsoClassifyReady(6); ok || !containsAny([]string{reason}, "STALE") {
		t.Fatalf("cross-generation gate ok=%t reason=%q want STALE", ok, reason)
	}
}

func TestWorkerGSOReadinessSnapshotInstanceAndEnvelope(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeFull, true, false)
	w := NewWorkerWithQueue(cfg, 0)
	first := w.GSOReadinessSnapshot()
	if first.State != GSOReadinessUnknown || first.ProcessInstanceID != "" {
		t.Fatalf("default snapshot state=%s instance=%q", first.State, first.ProcessInstanceID)
	}
	ev := fullGSOReadinessEvidence(dnsHintConfigGeneration(cfg))
	snap := w.SetGSOReadinessEvidence(ev)
	if snap.ProcessInstanceID == "" {
		t.Fatalf("process instance id empty")
	}
	if got := w.GSOReadinessSnapshot().ProcessInstanceID; got != snap.ProcessInstanceID {
		t.Fatalf("instance id unstable: %q vs %q", got, snap.ProcessInstanceID)
	}
	if !snap.MetadataEnvelopeReady || !snap.ProductionEntryPointVerified {
		t.Fatalf("snapshot flags: %+v", snap)
	}

	// Packet-path envelope observation must merge without dropping static proof.
	gso := testGSOPacket(100, 56000)
	w.observeGSOReadinessMetadata(gso.offload)
	snap = w.GSOReadinessSnapshot()
	if !snap.MetadataEnvelopeReady || !snap.RepresentationParityReady {
		t.Fatalf("merged snapshot lost static flags: %+v", snap)
	}
}

func TestWorkerGSOReadinessEvidenceMerge(t *testing.T) {
	cfg, _ := testGSOFastPathConfig(config.GSOModeFull, true, false)
	w := NewWorkerWithQueue(cfg, 0)
	// Truncation observed on the wire must survive a later operator Set.
	gso := testGSOPacket(100, 56000)
	gso.offload.Truncated = true
	gso.offload.OriginalLength = 200
	w.observeGSOReadinessMetadata(gso.offload)
	w.SetGSOReadinessEvidence(fullGSOReadinessEvidence(1))
	snap := w.GSOReadinessSnapshot()
	if snap.State != GSOReadinessFail {
		t.Fatalf("state=%s want FAIL after observed truncation, reasons=%v", snap.State, snap.Reasons)
	}
	if snap.MetadataEnvelopeReady {
		t.Fatalf("metadata envelope must not be ready after truncation")
	}
}

func containsAny(values []string, substring string) bool {
	for _, v := range values {
		if strings.Contains(v, substring) {
			return true
		}
	}
	return false
}
