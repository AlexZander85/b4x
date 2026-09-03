package observability

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMetricsRegistryIsBoundedAndDeterministic(t *testing.T) {
	registry := NewMetricsRegistry(2)
	registry.Inc("b", map[string]string{"source": "dns"}, 2)
	registry.Inc("a", map[string]string{"source": "tcp"}, 3)
	registry.Inc("dropped", map[string]string{"source": "other"}, 1)
	registry.Observe("latency", map[string]string{"source": "tcp"}, 7)

	snapshot := registry.Snapshot(time.Unix(10, 0))
	if len(snapshot.Counters)+len(snapshot.Histograms) != 2 {
		t.Fatalf("series limit not enforced: %+v", snapshot)
	}
	if len(snapshot.Counters) != 2 || snapshot.Counters[0].Name != "a" || snapshot.Counters[1].Name != "b" {
		t.Fatalf("counter ordering or values are not deterministic: %+v", snapshot.Counters)
	}

	copyRegistry := NewMetricsRegistry(4)
	labels := map[string]string{"source": "mutable"}
	copyRegistry.Inc("copy", labels, 1)
	labels["source"] = "changed"
	copySnapshot := copyRegistry.Snapshot(time.Unix(11, 0))
	for _, sample := range copySnapshot.Counters {
		if sample.Name == "copy" && sample.Labels["source"] != "mutable" {
			t.Fatalf("metric labels alias caller map: %+v", sample)
		}
	}
}

func TestTraceAndEvidenceArePrivacySafeAndBounded(t *testing.T) {
	recorder := NewRecorder()
	recorder.RecordEvidence(EvidenceSummary{Source: "dns_answer", SetID: "private-set", DomainID: "YouTube.Example.", Confidence: 88})
	for i := 0; i < 80; i++ {
		recorder.RecordProbeOutcome(ProbeOutcomeSummary{TargetProfile: "youtube-body", Verdict: "available", BodyBytes: uint64(i)})
	}
	recorder.Trace.Record(TraceEvent{
		Timestamp: time.Unix(20, 0),
		ClientID:  "192.0.2.10",
		FlowID:    "flow-with-192.0.2.10",
		Kind:      "classifier_decision",
		Fields: map[string]string{
			"domain":          "private.example",
			"ip":              "198.51.100.3",
			"mac":             "00:11:22:33:44:55",
			"client_identity": "full",
			"host_markers":    "false",
			"reason":          "clear SNI selected",
		},
	})
	bundle := recorder.Bundle(BundleMeta{Version: "test", Commit: "abc", ConfigHash: "hash", GeneratedAt: time.Unix(20, 0), Queue: QueueSummary{Status: "ok"}})
	encoded, err := bundle.JSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, raw := range []string{"192.0.2.10", "198.51.100.3", "00:11:22:33:44:55", "private.example", "private-set"} {
		if strings.Contains(text, raw) {
			t.Fatalf("raw identifier leaked in issue bundle: %q in %s", raw, text)
		}
	}
	if bundle.RawCapture {
		t.Fatal("issue bundle must not contain raw capture by default")
	}
	if bundle.SchemaVersion != SchemaVersion || len(bundle.Evidence) != 1 || len(bundle.Trace) != 1 || len(bundle.ProbeOutcomes) != 64 {
		t.Fatalf("incomplete issue bundle: %+v", bundle)
	}
	if bundle.Trace[0].Fields["reason"] != "clear SNI selected" {
		t.Fatalf("non-sensitive trace field was redacted: %+v", bundle.Trace[0])
	}
	if bundle.Trace[0].Fields["client_identity"] != "full" {
		t.Fatalf("client identity field unexpectedly changed: %+v", bundle.Trace[0])
	}
	if bundle.Trace[0].Fields["host_markers"] != "false" {
		t.Fatalf("host marker field unexpectedly changed: %+v", bundle.Trace[0])
	}
}

func TestIssueBundleTextAndJSONSchema(t *testing.T) {
	now := time.Unix(30, 0)
	bundle := NewRecorder().Bundle(BundleMeta{Version: "v", Commit: "c", ConfigHash: "h", GeneratedAt: now, Queue: QueueSummary{Ready: true, Status: "ok"}})
	if !strings.Contains(bundle.Text(), "schema="+SchemaVersion) || !strings.Contains(bundle.Text(), "raw_capture=false") {
		t.Fatalf("unexpected human-readable bundle: %s", bundle.Text())
	}
	var decoded map[string]interface{}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"schema_version", "generated_at", "versions", "metrics", "queue", "raw_capture"} {
		if _, ok := decoded[field]; !ok {
			t.Fatalf("missing issue bundle field %q: %s", field, data)
		}
	}
}

func FuzzRedactIdentifier(f *testing.F) {
	f.Add("192.0.2.1", "example.com")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, identifier, domain string) {
		if got := RedactIdentifier(identifier); identifier == "" && got != "" {
			t.Fatalf("empty identifier should remain empty: %q", got)
		}
		if got := RedactDomain(domain); domain == "" && got != "" {
			t.Fatalf("empty domain should remain empty: %q", got)
		}
	})
}

func BenchmarkMetricsInc(b *testing.B) {
	registry := NewMetricsRegistry(1024)
	labels := map[string]string{"phase": "resolved", "source": "dns_answer"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.Inc(MetricClassifierDecisions, labels, 1)
	}
}

func BenchmarkTraceRecord(b *testing.B) {
	recorder := NewTraceRecorder(512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder.Record(TraceEvent{Kind: "decision", ClientID: "192.0.2.1", FlowID: "flow", Fields: map[string]string{"phase": "resolved"}})
	}
}
