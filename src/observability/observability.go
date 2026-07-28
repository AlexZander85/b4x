// Package observability provides bounded, privacy-safe classifier/action
// metrics and trace snapshots. It intentionally has no packet or socket API.
package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const SchemaVersion = "b4-observability-v2"

const (
	MetricClassifierDecisions        = "classifier_decisions_total"
	MetricClassifierEvidence         = "classifier_evidence_candidates_total"
	MetricClassifierAmbiguous        = "classifier_ambiguous_total"
	MetricClassifierConfidence       = "classifier_confidence_histogram"
	MetricCapturePackets             = "capture_packets_total"
	MetricCaptureProcessedBypass     = "capture_processed_bypass_total"
	MetricCaptureQueueDrop           = "capture_queue_drop_total"
	MetricCaptureUserDrop            = "capture_user_drop_total"
	MetricCaptureOffloadSuspected    = "capture_offload_suspected_total"
	MetricTCPFlowPhase               = "tcp_flow_phase_total"
	MetricTCPReassemblyStarted       = "tcp_reassembly_started_total"
	MetricTCPReassemblyCompleted     = "tcp_reassembly_completed_total"
	MetricTCPReassemblyAborted       = "tcp_reassembly_aborted_total"
	MetricTCPActionPlanned           = "tcp_action_planned_total"
	MetricTCPActionApplied           = "tcp_action_applied_total"
	MetricTCPActionSuppressed        = "tcp_action_suppressed_total"
	MetricTCPActionTokenReuse        = "tcp_action_token_reuse_total"
	MetricTCPPacketAmplification     = "tcp_packet_amplification_histogram"
	MetricECHClientHello             = "ech_clienthello_total"
	MetricECHFallback                = "ech_fallback_total"
	MetricDiscoveryProbe             = "discovery_probe_total"
	MetricDiscoveryFailureOffset     = "discovery_failure_offset_histogram"
	MetricDiscoveryShadowProbe       = "discovery_shadow_probe_total"
	MetricDiscoveryCandidatePromote  = "discovery_candidate_promoted_total"
	MetricDiscoveryCandidateRollback = "discovery_candidate_rollback_total"
	MetricFailureCandidateObserved   = "failure_candidate_observed_total"
	MetricFailureCandidateExpired    = "failure_candidate_expired_total"
	MetricFailureCandidateRejected   = "failure_candidate_rejected_total"
)

type MetricSample struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Value  uint64            `json:"value"`
}

type HistogramBucket struct {
	Le    float64 `json:"le"`
	Count uint64  `json:"count"`
}

type HistogramSample struct {
	Name    string            `json:"name"`
	Labels  map[string]string `json:"labels,omitempty"`
	Count   uint64            `json:"count"`
	Sum     float64           `json:"sum"`
	Buckets []HistogramBucket `json:"buckets"`
}

type MetricsSnapshot struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Counters    []MetricSample    `json:"counters"`
	Histograms  []HistogramSample `json:"histograms"`
}

type metricKey struct {
	name   string
	labels string
}

type histogramState struct {
	name   string
	labels map[string]string
	bounds []float64
	counts []uint64
	count  uint64
	sum    float64
}

type MetricsRegistry struct {
	mu              sync.Mutex
	maxSeries       int
	counters        map[metricKey]MetricSample
	histograms      map[metricKey]*histogramState
	defaultHistCaps []float64
}

func NewMetricsRegistry(maxSeries int) *MetricsRegistry {
	if maxSeries <= 0 {
		maxSeries = 1024
	}
	return &MetricsRegistry{
		maxSeries:       maxSeries,
		counters:        make(map[metricKey]MetricSample, maxSeries),
		histograms:      make(map[metricKey]*histogramState, maxSeries),
		defaultHistCaps: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000},
	}
}

func (r *MetricsRegistry) Inc(name string, labels map[string]string, value uint64) {
	if r == nil || strings.TrimSpace(name) == "" {
		return
	}
	key := makeMetricKey(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	if sample, ok := r.counters[key]; ok {
		sample.Value += value
		r.counters[key] = sample
		return
	}
	if len(r.counters)+len(r.histograms) >= r.maxSeries {
		return
	}
	r.counters[key] = MetricSample{Name: name, Labels: copyLabels(labels), Value: value}
}

func (r *MetricsRegistry) Observe(name string, labels map[string]string, value float64) {
	if r == nil || strings.TrimSpace(name) == "" {
		return
	}
	key := makeMetricKey(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.histograms[key]
	if state == nil {
		if len(r.counters)+len(r.histograms) >= r.maxSeries {
			return
		}
		state = &histogramState{name: name, labels: copyLabels(labels), bounds: append([]float64(nil), r.defaultHistCaps...), counts: make([]uint64, len(r.defaultHistCaps))}
		r.histograms[key] = state
	}
	state.count++
	state.sum += value
	for i, bound := range state.bounds {
		if value <= bound {
			state.counts[i]++
		}
	}
}

func (r *MetricsRegistry) Snapshot(now time.Time) MetricsSnapshot {
	if r == nil {
		return MetricsSnapshot{GeneratedAt: now}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := MetricsSnapshot{GeneratedAt: now, Counters: make([]MetricSample, 0, len(r.counters)), Histograms: make([]HistogramSample, 0, len(r.histograms))}
	for _, sample := range r.counters {
		sample.Labels = copyLabels(sample.Labels)
		out.Counters = append(out.Counters, sample)
	}
	for _, state := range r.histograms {
		buckets := make([]HistogramBucket, len(state.bounds))
		for i := range state.bounds {
			buckets[i] = HistogramBucket{Le: state.bounds[i], Count: state.counts[i]}
		}
		out.Histograms = append(out.Histograms, HistogramSample{Name: state.name, Labels: copyLabels(state.labels), Count: state.count, Sum: state.sum, Buckets: buckets})
	}
	sort.Slice(out.Counters, func(i, j int) bool {
		return metricSampleKey(out.Counters[i].Name, out.Counters[i].Labels) < metricSampleKey(out.Counters[j].Name, out.Counters[j].Labels)
	})
	sort.Slice(out.Histograms, func(i, j int) bool {
		return metricSampleKey(out.Histograms[i].Name, out.Histograms[i].Labels) < metricSampleKey(out.Histograms[j].Name, out.Histograms[j].Labels)
	})
	return out
}

func (r *MetricsRegistry) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters = make(map[metricKey]MetricSample, r.maxSeries)
	r.histograms = make(map[metricKey]*histogramState, r.maxSeries)
}

type TraceEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	ClientID  string            `json:"client_id,omitempty"`
	FlowID    string            `json:"flow_id,omitempty"`
	Kind      string            `json:"kind"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type TraceRecorder struct {
	mu     sync.Mutex
	max    int
	events []TraceEvent
}

func NewTraceRecorder(maxEvents int) *TraceRecorder {
	if maxEvents <= 0 {
		maxEvents = 512
	}
	return &TraceRecorder{max: maxEvents, events: make([]TraceEvent, 0, maxEvents)}
}

func (r *TraceRecorder) Record(event TraceEvent) {
	if r == nil || strings.TrimSpace(event.Kind) == "" {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	event.ClientID = RedactIdentifier(event.ClientID)
	event.FlowID = RedactIdentifier(event.FlowID)
	event.Fields = sanitizeFields(event.Fields)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == r.max {
		copy(r.events, r.events[1:])
		r.events = r.events[:r.max-1]
	}
	event.Fields = copyLabels(event.Fields)
	r.events = append(r.events, event)
}

func (r *TraceRecorder) Snapshot() []TraceEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TraceEvent, len(r.events))
	for i, event := range r.events {
		out[i] = event
		out[i].Fields = copyLabels(event.Fields)
	}
	return out
}

func (r *TraceRecorder) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = r.events[:0]
}

type EvidenceSummary struct {
	Source     string `json:"source"`
	SetID      string `json:"set_id,omitempty"`
	DomainID   string `json:"domain_id,omitempty"`
	Confidence uint8  `json:"confidence"`
	ECH        bool   `json:"ech"`
	Fresh      bool   `json:"fresh"`
}

type QueueSummary struct {
	Ready                 bool   `json:"ready"`
	ProcessedMarkVerified bool   `json:"processed_mark_verified"`
	OffloadSuspected      bool   `json:"offload_suspected"`
	QueueDrops            uint64 `json:"queue_drops"`
	UserDrops             uint64 `json:"user_drops"`
	Status                string `json:"status"`
}

type ProbeOutcomeSummary struct {
	TargetProfile string `json:"target_profile,omitempty"`
	Verdict       string `json:"verdict"`
	FailureStage  string `json:"failure_stage,omitempty"`
	FailureOffset int64  `json:"failure_offset,omitempty"`
	BodyBytes     uint64 `json:"body_bytes"`
	ThroughputBPS uint64 `json:"throughput_bps"`
}

type BundleMeta struct {
	Version       string
	Commit        string
	ConfigHash    string
	GeneratedAt   time.Time
	Queue         QueueSummary
	Evidence      []EvidenceSummary
	ProbeOutcomes []ProbeOutcomeSummary
}

type IssueBundle struct {
	SchemaVersion string                `json:"schema_version"`
	GeneratedAt   time.Time             `json:"generated_at"`
	Versions      map[string]string     `json:"versions"`
	Metrics       MetricsSnapshot       `json:"metrics"`
	Evidence      []EvidenceSummary     `json:"evidence,omitempty"`
	Trace         []TraceEvent          `json:"trace,omitempty"`
	Queue         QueueSummary          `json:"queue"`
	ProbeOutcomes []ProbeOutcomeSummary `json:"probe_outcomes,omitempty"`
	RawCapture    bool                  `json:"raw_capture"`
}

type Recorder struct {
	Metrics          *MetricsRegistry
	Trace            *TraceRecorder
	mu               sync.Mutex
	evidence         []EvidenceSummary
	probeOutcomes    []ProbeOutcomeSummary
	maxEvidence      int
	maxProbeOutcomes int
}

func NewRecorder() *Recorder {
	return &Recorder{Metrics: NewMetricsRegistry(1024), Trace: NewTraceRecorder(512), evidence: make([]EvidenceSummary, 0, 256), probeOutcomes: make([]ProbeOutcomeSummary, 0, 64), maxEvidence: 256, maxProbeOutcomes: 64}
}

// RecordEvidence retains only the bounded, redacted summary needed to explain
// a decision in an issue bundle. It never stores packet bytes or cleartext
// host identifiers.
func (r *Recorder) RecordEvidence(summary EvidenceSummary) {
	if r == nil || strings.TrimSpace(summary.Source) == "" {
		return
	}
	summary.SetID = RedactIdentifier(summary.SetID)
	summary.DomainID = RedactDomain(summary.DomainID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxEvidence <= 0 {
		r.maxEvidence = 256
	}
	if len(r.evidence) == r.maxEvidence {
		copy(r.evidence, r.evidence[1:])
		r.evidence = r.evidence[:r.maxEvidence-1]
	}
	r.evidence = append(r.evidence, summary)
}

// RecordProbeOutcome keeps the latest bounded outcome summaries for issue
// bundles. Body payloads and raw request/response data are never retained.
func (r *Recorder) RecordProbeOutcome(summary ProbeOutcomeSummary) {
	if r == nil || strings.TrimSpace(summary.Verdict) == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxProbeOutcomes <= 0 {
		r.maxProbeOutcomes = 64
	}
	if len(r.probeOutcomes) == r.maxProbeOutcomes {
		copy(r.probeOutcomes, r.probeOutcomes[1:])
		r.probeOutcomes = r.probeOutcomes[:r.maxProbeOutcomes-1]
	}
	r.probeOutcomes = append(r.probeOutcomes, summary)
}

func (r *Recorder) Bundle(meta BundleMeta) IssueBundle {
	if r == nil {
		return IssueBundle{SchemaVersion: SchemaVersion, GeneratedAt: meta.GeneratedAt, Versions: map[string]string{"version": meta.Version, "commit": meta.Commit, "config_hash": meta.ConfigHash}, Queue: meta.Queue}
	}
	if meta.GeneratedAt.IsZero() {
		meta.GeneratedAt = time.Now()
	}
	r.mu.Lock()
	evidence := append([]EvidenceSummary(nil), r.evidence...)
	probeOutcomes := append([]ProbeOutcomeSummary(nil), r.probeOutcomes...)
	r.mu.Unlock()
	for _, summary := range meta.Evidence {
		summary.SetID = RedactIdentifier(summary.SetID)
		summary.DomainID = RedactDomain(summary.DomainID)
		evidence = append(evidence, summary)
	}
	probeOutcomes = append(probeOutcomes, meta.ProbeOutcomes...)
	return IssueBundle{SchemaVersion: SchemaVersion, GeneratedAt: meta.GeneratedAt, Versions: map[string]string{"version": meta.Version, "commit": meta.Commit, "config_hash": meta.ConfigHash}, Metrics: r.Metrics.Snapshot(meta.GeneratedAt), Evidence: evidence, Trace: r.Trace.Snapshot(), Queue: meta.Queue, ProbeOutcomes: probeOutcomes, RawCapture: false}
}

var defaultRecorder = NewRecorder()

func Default() *Recorder { return defaultRecorder }

func RedactIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	hash := sha256.Sum256([]byte("b4-observability:" + value))
	return hex.EncodeToString(hash[:6])
}

func RedactDomain(domain string) string {
	return RedactIdentifier(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")))
}

func (b IssueBundle) JSON() ([]byte, error) { return json.Marshal(b) }

func (b IssueBundle) Text() string {
	return fmt.Sprintf("schema=%s generated_at=%s version=%s commit=%s counters=%d histograms=%d trace_events=%d queue_status=%s raw_capture=%t", b.SchemaVersion, b.GeneratedAt.UTC().Format(time.RFC3339), b.Versions["version"], b.Versions["commit"], len(b.Metrics.Counters), len(b.Metrics.Histograms), len(b.Trace), b.Queue.Status, b.RawCapture)
}

func makeMetricKey(name string, labels map[string]string) metricKey {
	return metricKey{name: name, labels: metricSampleKey(name, labels)}
}

func metricSampleKey(name string, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	builder.WriteString(name)
	for _, key := range keys {
		builder.WriteByte(0)
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(labels[key])
	}
	return builder.String()
}

func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func sanitizeFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		if sensitiveFieldKey(key) {
			out[key] = RedactIdentifier(value)
			continue
		}
		out[key] = value
	}
	return out
}

func sensitiveFieldKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	switch lower {
	case "domain", "host", "ip", "mac", "sni", "set_id", "client_id", "flow_id":
		return true
	case "client_identity", "host_markers", "domain_only", "domain_result", "clienthello_size", "sni_hash":
		return false
	}
	for _, suffix := range []string{"_domain", "_host", "_ip", "_mac", "_client_id", "_flow_id"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
