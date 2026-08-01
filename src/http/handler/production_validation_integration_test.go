package handler

// Production-root integration test (FB-03 criterion 4): internal metrics
// snapshot <-> Prometheus /metrics <-> Validation API <-> Field Test/release
// report must expose identical values, labels, kinds, produced state, window
// baseline, delta and generation for the same TestSession/ValidationRun.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fieldtest"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/validation"
)

// promLine parses "name{labels} value" exposition lines (values only; HELP
// and TYPE lines are skipped).
var promLine = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)(\{[^}]*\})?\s+([0-9]+|[0-9]+[.][0-9]+)$`)

func prometheusValues(t *testing.T, body string) map[string]uint64 {
	t.Helper()
	out := make(map[string]uint64)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := promLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("unparsable prometheus line: %q", line)
		}
		value, err := strconv.ParseUint(m[3], 10, 64)
		if err != nil {
			t.Fatalf("value %q in line %q: %v", m[3], line, err)
		}
		out[m[1]+m[2]] = value
	}
	return out
}

func snapshotSeries(snap observability.MetricsSnapshot) map[string]uint64 {
	out := make(map[string]uint64, len(snap.Counters))
	for _, s := range snap.Counters {
		out[promSeriesKey(s.Name, s.Labels)] = s.Value
	}
	return out
}

func promSeriesKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	return name + prometheusLabels(labels)
}

func TestProductionValidationIntegrationSnapshotPrometheusAPIFieldTest(t *testing.T) {
	observability.Default().Metrics.Reset()
	validation.ResetProductionWindow()
	t.Cleanup(func() {
		observability.Default().Metrics.Reset()
		validation.ResetProductionWindow()
	})

	// Seed the internal metrics the way the real producers do (one series has
	// the mode label like the visibility-gate subscriber).
	reg := observability.Default().Metrics
	reg.Inc(observability.MetricUnrelatedControlAction, nil, 2)
	reg.Inc(observability.MetricClassifierLayoutParityFail, nil, 0)
	reg.Inc(observability.MetricPassiveRSTReconnectRegression, nil, 0)
	reg.Inc(observability.MetricNFQueueGSOTruncated, nil, 3)
	reg.Inc(observability.MetricNFQueueGSOCsumNotReady, nil, 2)
	reg.Inc(observability.MetricNFQueueGSOTokenMiss, nil, 1)
	reg.Inc(observability.MetricCaptureVisibilityDegrade, map[string]string{"mode": "incomplete"}, 2)
	reg.Inc(observability.MetricPassiveRSTFailOpen, nil, 5)
	reg.Inc(observability.MetricHoldDisabledVisibility, nil, 1)

	api, mux := newValidationGatesTestAPI(t)
	api.RegisterPrometheusAPI()

	// --- First evaluation: captures the baseline of the current window. ---
	snap1 := reg.Snapshot(time.Now().UTC())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, validationGatesAPIPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("validation API status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got1 gateSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got1); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	eval1 := got1.Evaluation
	if !eval1.WindowBaseline {
		t.Fatal("WindowBaseline must be true: production evaluates the session window")
	}
	if !got1.Window.Active {
		t.Fatalf("window info = %+v, want active", got1.Window)
	}
	// kinds: zero-tolerance in Violations, readiness inputs separate, telemetry separate.
	if len(eval1.Violations) != 0 {
		t.Fatalf("first call (baseline capture) must have zero window delta: %+v", eval1.Violations)
	}
	// readiness inputs are window deltas too: zero on the baseline capture,
	// even though the lifetime counters are non-zero.
	readiness := map[string]uint64{}
	for _, v := range eval1.ReadinessInputs {
		readiness[v.Metric] = v.Count
	}
	for _, name := range []string{"nfqueue_gso_truncated_total", "nfqueue_gso_csum_not_ready_total", "nfqueue_gso_token_miss_total", "b4_capture_visibility_degrade_total"} {
		if readiness[name] != 0 {
			t.Fatalf("readiness input %s = %d on baseline capture, want 0 (window delta)", name, readiness[name])
		}
	}

	// --- Prometheus /metrics must expose the same values and labels. ---
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, prometheusMetricsPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d", rec.Code)
	}
	prom := prometheusValues(t, rec.Body.String())
	series := snapshotSeries(snap1)
	if len(prom) == 0 {
		t.Fatal("prometheus export is empty")
	}
	for key, value := range series {
		if prom[key] != value {
			t.Fatalf("series %q: prometheus=%d snapshot=%d", key, prom[key], value)
		}
	}
	if prom["unrelated_control_action_total"] != 2 || prom["nfqueue_gso_truncated_total"] != 3 || prom["passive_rst_fail_open_total"] != 5 {
		t.Fatalf("prometheus key values mismatch: %+v", prom)
	}
	if prom["b4_capture_visibility_degrade_total{mode=\"incomplete\"}"] != 2 {
		t.Fatalf("labelled series missing/incorrect: %+v", prom)
	}

	// --- Same window, new events: evaluation uses the window delta. ---
	reg.Inc(observability.MetricUnrelatedControlAction, nil, 1) // lifetime 3
	reg.Inc(observability.MetricNFQueueGSOTruncated, nil, 1)    // lifetime 4
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, validationGatesAPIPath, nil))
	var got2 gateSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got2); err != nil {
		t.Fatalf("unmarshal second eval: %v", err)
	}
	if got2.Evaluation.Verdict != validation.GateFail {
		t.Fatalf("second eval verdict = %s, want FAIL (window delta violation)", got2.Evaluation.Verdict)
	}
	if len(got2.Evaluation.Violations) != 1 || got2.Evaluation.Violations[0].Count != 1 {
		t.Fatalf("second eval violations = %+v, want window delta 1 (baseline 2, not lifetime 3)", got2.Evaluation.Violations)
	}
	readiness2 := map[string]uint64{}
	for _, v := range got2.Evaluation.ReadinessInputs {
		readiness2[v.Metric] = v.Count
	}
	if readiness2["nfqueue_gso_truncated_total"] != 1 {
		t.Fatalf("truncated readiness delta = %d, want 1 (lifetime 4, baseline 3)", readiness2["nfqueue_gso_truncated_total"])
	}
	if readiness2["nfqueue_gso_csum_not_ready_total"] != 0 || readiness2["nfqueue_gso_token_miss_total"] != 0 || readiness2["b4_capture_visibility_degrade_total"] != 0 {
		t.Fatalf("unchanged readiness inputs must have zero delta: %+v", readiness2)
	}
	if got2.Window.StartedAt != got1.Window.StartedAt {
		t.Fatalf("window identity changed mid-session: %v -> %v", got1.Window.StartedAt, got2.Window.StartedAt)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, prometheusMetricsPath, nil))
	prom2 := prometheusValues(t, rec.Body.String())
	if prom2["unrelated_control_action_total"] != 3 || prom2["nfqueue_gso_truncated_total"] != 4 {
		t.Fatalf("prometheus after increment = %+v, want unrelated=3 truncated=4", prom2)
	}
	snap2 := reg.Snapshot(time.Now().UTC())
	if snapshotSeries(snap2)["unrelated_control_action_total"] != 3 || snapshotSeries(snap2)["nfqueue_gso_truncated_total"] != 4 {
		t.Fatalf("snapshot after increment = %+v", snapshotSeries(snap2))
	}

	// --- Field Test/release report attests the SAME evaluation as
	// PromotePending: a new generation starts a new window (baseline =
	// current counters), the unrelated-control delta is zero, and both the
	// promotion check and the report derive identical verdicts. ---
	cfg := config.NewConfig()
	cfg.System.Classifier.Flags.ClassifierV2Enabled = true
	promoteErr := checkHardGates(&cfg, "gen-2")
	if promoteErr == nil {
		t.Fatal("PromotePending hard-gate check must stay BLOCKED while warp producers are missing (fail-closed)")
	}
	if !strings.Contains(promoteErr.Error(), "0 violations") {
		t.Fatalf("new generation must start a fresh baseline (delta 0): %v", promoteErr)
	}
	counters := snapshotSeries(snap2)
	produced := make(map[string]bool, len(counters))
	for name := range counters {
		produced[name] = true
	}
	baseline := validation.BaselineForRun("gen-2", counters)
	reportScope := validation.ReleaseScope{WARPBase: true, CSI: true, RSTGSO: true, PPE: true}
	reportEval := fieldtest.EvaluateHardGatesWindow(
		reportScope, nil, "", validation.GenerationSet{}, counters, baseline, produced)
	if reportEval.Verdict != validation.GateBlocked {
		t.Fatalf("field-test report eval = %+v, want BLOCKED (same as promotion check)", reportEval)
	}
	if len(reportEval.Violations) != 0 {
		t.Fatalf("report eval violations = %+v, want zero delta on new-generation window", reportEval.Violations)
	}
	report := fieldtest.StageReport{
		Stage: "promotion", Verdict: string(fieldtest.PromotionBlocked), SourceAddendumHash: "abc",
		Requirements: []string{"r1"}, HardGates: []string{"unrelated_control_action_total"},
		GateVerdict: reportEval.Verdict,
	}
	if !report.Valid() {
		t.Fatalf("release report invalid: %+v", report)
	}
	if info := validation.ProductionWindowInfo(); !info.Active || info.Generation != "gen-2" {
		t.Fatalf("window after new generation = %+v, want gen-2", info)
	}

	// --- Readiness owner-state effect surfaces in the API snapshot. ---
	// On the second call the truncated delta (1) is a non-zero readiness
	// input: capture visibility is complete by default => safe => READY; the
	// GSO trio is a DEFERRED dependency (FB-27/PPE) => unknown => DEGRADED.
	if got2.Readiness.Verdict != validation.ReadinessDegraded {
		t.Fatalf("readiness verdict = %s, want DEGRADED (truncated delta unknown, visibility safe)", got2.Readiness.Verdict)
	}
	for _, g := range got2.Readiness.Gates {
		switch g.Metric {
		case "b4_capture_visibility_degrade_total":
			if g.Status != validation.ReadinessReady || g.Owner != validation.OwnerStateSafe {
				t.Fatalf("visibility gate = %+v, want READY/safe", g)
			}
		case "nfqueue_gso_truncated_total":
			if g.Input != 1 || g.Status != validation.ReadinessDegraded || g.Owner != validation.OwnerStateUnknown {
				t.Fatalf("truncated gate = %+v, want delta 1 DEGRADED/unknown (DEFERRED)", g)
			}
		case "nfqueue_gso_csum_not_ready_total", "nfqueue_gso_token_miss_total":
			if g.Input != 0 || g.Status != validation.ReadinessReady {
				t.Fatalf("unchanged GSO gate %s = %+v, want READY with zero delta", g.Metric, g)
			}
		default:
			t.Fatalf("unexpected readiness gate %s", g.Metric)
		}
	}
}
