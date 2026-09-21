package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

type handlerTestProvider struct {
	id dnspath.DNSPathID
}

func (p *handlerTestProvider) ID() dnspath.DNSPathID { return p.id }
func (p *handlerTestProvider) Capabilities() dnspath.DNSPathCapabilities {
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: true}
}
func (p *handlerTestProvider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	return dnspath.PreparedDNSPath{PathID: p.id, Generation: req.Generation, PreparedAt: time.Now()}, nil
}
func (p *handlerTestProvider) Probe(_ context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	return dnspath.DNSPathProbeOutcome{PathID: prepared.PathID, QuerySuiteID: q.SuiteCase, Class: dnspath.OutcomePassCorrect}, nil
}
func (p *handlerTestProvider) Resolve(_ context.Context, _ dnspath.PreparedDNSPath, _ dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	return dnspath.DNSResponse{}, nil
}
func (p *handlerTestProvider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapReady}
}
func (p *handlerTestProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }

func handlerPromotionEvidence(paths ...dnspath.DNSPathID) []dnspath.DNSPathProbeOutcome {
	cases := []string{"A", "AAAA", "CNAME", "HTTPS", "NXDOMAIN", "CONTROL_SAME", "CONTROL_UNRELATED"}
	out := make([]dnspath.DNSPathProbeOutcome, 0, len(paths)*len(cases)*2)
	for _, path := range paths {
		for _, caseID := range cases {
			for attempt := uint16(1); attempt <= 2; attempt++ {
				receipt := dnspath.DNSPathProbeOutcome{
					PathID: path, QuerySuiteID: caseID, Attempt: attempt,
					Stage: dnspath.StageControl, Class: dnspath.OutcomePassCorrect,
					ResponseCount: 1, ObservedAt: time.Now(),
				}
				switch caseID {
				case "CNAME":
					receipt.CNAMEFingerprint = "cname-fixture"
				case "HTTPS":
					receipt.HTTPSFingerprint = "https-fixture"
				case "NXDOMAIN":
					receipt.RCode = 3
					receipt.EvidenceRefs = []string{"authority-soa", "independent-quorum"}
				default:
					receipt.AnswerFingerprint = "answer-fixture"
				}
				out = append(out, receipt)
			}
		}
	}
	return out
}

func testManager(t *testing.T) *dnspath.Manager {
	t.Helper()
	pol := dnspath.DefaultAdaptivePolicy()
	pol.Enabled = true
	m := dnspath.NewManager(dnspath.DNSModeAdaptive, pol, 11, "epoch-1", "wan-1")
	now := time.Now()
	primary := dnspath.DNSPathID{Family: dnspath.DNSPathDoH, ResolverID: "r-a", EndpointID: "e-1", IPFamily: "ipv4"}
	fallback := dnspath.DNSPathID{Family: dnspath.DNSPathTCP, ResolverID: "r-b", EndpointID: "e-2", IPFamily: "ipv4"}
	p := &dnspath.DNSPathProfile{
		ProfileID: "dnsprof-api", Status: dnspath.ProfileStatusReady,
		NetworkContextID: "wan-1", ConfigGeneration: 11, RuntimeEpoch: "epoch-1",
		QuerySuiteVersion: "adns-suite-v1",
		Primary:           primary, Fallbacks: []dnspath.DNSPathID{fallback},
		CandidateOutcomes: handlerPromotionEvidence(primary, fallback),
		CreatedAt:         now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := m.PreparePath(context.Background(), &handlerTestProvider{id: primary}, false); err != nil {
		t.Fatal(err)
	}
	if err := m.PreparePath(context.Background(), &handlerTestProvider{id: fallback}, false); err != nil {
		t.Fatal(err)
	}
	m.MarkPathHealth(primary, dnspath.DNSPathHealth{State: dnspath.CapReady})
	m.MarkPathHealth(fallback, dnspath.DNSPathHealth{State: dnspath.CapAvailable})
	if err := m.AdoptProfile(p); err != nil {
		t.Fatal(err)
	}
	binding, err := m.NewBinding("lan", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tx := &dnspath.Transaction{
		Profile: p, Candidate: binding,
		Canary: func(context.Context, *dnspath.DNSPathBinding) error { return nil },
	}
	if err := tx.Run(context.Background(), m); err != nil {
		t.Fatalf("promotion-grade test transaction failed: %v (%s)", err, tx.Reason)
	}
	return m
}

func TestDNSStatusMetricsParity(t *testing.T) {
	m := testManager(t)
	SetDNSPathManager(m)
	defer SetDNSPathManager(nil)

	status := dnsStatusPayload(m)
	metrics := RenderDNSMetrics(m)

	primary, ok := status["primary"].(map[string]any)
	if !ok {
		t.Fatal("status must include primary")
	}
	family := primary["family"].(dnspath.DNSPathFamily)
	if !strings.Contains(metrics, `primary_family="`+string(family)+`"`) {
		t.Fatal("API and /metrics must report the same primary (parity gate)")
	}
	if !strings.Contains(metrics, `state="ready"`) {
		t.Fatal("metrics must expose profile state")
	}
	// privacy: no raw qname/IP labels
	for _, banned := range []string{"example.com", "resolver_id", "profile_id"} {
		if strings.Contains(metrics, banned) {
			t.Fatalf("metrics must not export raw identity %q", banned)
		}
	}
}

func TestDNSConfigWritePreconditions(t *testing.T) {
	m := testManager(t)
	SetDNSPathManager(m)
	defer SetDNSPathManager(nil)
	api := &API{mux: http.NewServeMux()}
	api.RegisterAdaptiveDNSApi()

	// missing headers → precondition failure
	req := httptest.NewRequest(http.MethodPut, "/api/dns/v1/config", strings.NewReader(`{"mode":"manual"}`))
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing generation header must fail precondition, got %d", rec.Code)
	}

	// wrong generation
	req = httptest.NewRequest(http.MethodPut, "/api/dns/v1/config", strings.NewReader(`{"mode":"manual"}`))
	req.Header.Set("X-Config-Generation", "999")
	req.Header.Set("X-Idempotency-Key", "k1")
	rec = httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale generation must fail, got %d", rec.Code)
	}

	// correct headers
	req = httptest.NewRequest(http.MethodPut, "/api/dns/v1/config", strings.NewReader(`{"mode":"manual"}`))
	req.Header.Set("X-Config-Generation", "11")
	req.Header.Set("X-Idempotency-Key", "k2")
	rec = httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid write must succeed, got %d body %s", rec.Code, rec.Body.String())
	}
	if m.Mode() != dnspath.DNSModeManual {
		t.Fatal("mode must be applied")
	}

	// duplicate idempotency key → conflict
	req = httptest.NewRequest(http.MethodPut, "/api/dns/v1/config", strings.NewReader(`{"mode":"adaptive"}`))
	req.Header.Set("X-Config-Generation", "11")
	req.Header.Set("X-Idempotency-Key", "k2")
	rec = httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate idempotency key must conflict, got %d", rec.Code)
	}
}

func TestDNSStatusEndpoint(t *testing.T) {
	m := testManager(t)
	SetDNSPathManager(m)
	defer SetDNSPathManager(nil)
	api := &API{mux: http.NewServeMux()}
	api.RegisterAdaptiveDNSApi()
	req := httptest.NewRequest(http.MethodGet, "/api/dns/v1/status", nil)
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status must render, got %d", rec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["profile_id"] != "dnsprof-api" {
		t.Fatal("status must expose profile id")
	}
	if payload["config_generation"].(float64) != 11 {
		t.Fatal("status must expose generation")
	}
}

func TestDNSRollbackEndpoint(t *testing.T) {
	m := testManager(t)
	SetDNSPathManager(m)
	defer SetDNSPathManager(nil)
	api := &API{mux: http.NewServeMux()}
	api.RegisterAdaptiveDNSApi()
	// no last-good → honest negative
	req := httptest.NewRequest(http.MethodPost, "/api/dns/v1/rollback", nil)
	req.Header.Set("X-Config-Generation", "11")
	req.Header.Set("X-Idempotency-Key", "rb1")
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback endpoint must respond, got %d", rec.Code)
	}
	var payload map[string]any
	json.Unmarshal(rec.Body.Bytes(), &payload)
	if payload["rolled_back"] != false {
		t.Fatal("rollback without last-good must report false, not fake success")
	}
}

func TestDNSDiagnoseStoresArtifact(t *testing.T) {
	m := testManager(t)
	SetDNSPathManager(m)
	defer SetDNSPathManager(nil)
	SetDNSDiagnoser(func(ctx context.Context) (*DNSDiagnoseResult, error) {
		return &DNSDiagnoseResult{
			ProfileID:     "dnsprof-api",
			PrimaryFamily: "doh",
			Confidence:    0.9,
			Explanation:   []string{"controls passed"},
		}, nil
	})
	defer SetDNSDiagnoser(nil)

	api := &API{mux: http.NewServeMux()}
	api.RegisterAdaptiveDNSApi()
	req := httptest.NewRequest(http.MethodPost, "/api/dns/v1/diagnose", nil)
	req.Header.Set("X-Config-Generation", "11")
	req.Header.Set("X-Idempotency-Key", "diag1")
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("diagnose must succeed, got %d", rec.Code)
	}
	var diag map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &diag); err != nil {
		t.Fatal(err)
	}
	runID, _ := diag["run_id"].(string)
	if runID == "" {
		t.Fatal("diagnose must return run_id")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/dns/v1/artifacts/"+runID, nil)
	rec = httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("artifact must be retrievable, got %d", rec.Code)
	}
	var art DNSRunArtifact
	if err := json.Unmarshal(rec.Body.Bytes(), &art); err != nil {
		t.Fatal(err)
	}
	if art.RunID != runID || art.Result == nil || art.Result.PrimaryFamily != "doh" {
		t.Fatal("artifact must contain the diagnosis result")
	}
	if art.Status["profile_id"] != "dnsprof-api" {
		t.Fatal("artifact status must come from the same manager snapshot")
	}
	if len(art.Trace) == 0 {
		t.Fatal("artifact must include causal trace")
	}

	// unknown run id → honest 404
	req = httptest.NewRequest(http.MethodGet, "/api/dns/v1/artifacts/nope", nil)
	rec = httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown run id must 404, got %d", rec.Code)
	}
}

func TestDNSStatusExposesQuarantineAndRevalidateReleases(t *testing.T) {
	m := testManager(t)
	SetDNSPathManager(m)
	defer SetDNSPathManager(nil)
	if !m.RecordPathFailure(dnspath.DNSPathDoT, dnspath.KindMidHandshakeReset) {
		t.Fatal("expected dot to be quarantined after mid-handshake reset")
	}
	status := dnsStatusPayload(m)
	quarantined, ok := status["quarantined_families"].([]dnspath.DNSPathFamily)
	if !ok || len(quarantined) != 1 || quarantined[0] != dnspath.DNSPathDoT {
		t.Fatalf("status quarantined_families = %#v", status["quarantined_families"])
	}

	api := &API{mux: http.NewServeMux()}
	api.RegisterAdaptiveDNSApi()
	req := httptest.NewRequest(http.MethodPost, "/api/dns/v1/revalidate", nil)
	req.Header.Set("X-Config-Generation", "11")
	req.Header.Set("X-Idempotency-Key", "rev-quarantine")
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revalidate must respond, got %d", rec.Code)
	}
	if m.IsFamilyQuarantined(dnspath.DNSPathDoT) {
		t.Fatal("successful revalidate must release family quarantine")
	}
}

func TestDNSStatusAndMetricsExposeDegradedMode(t *testing.T) {
	m := testManager(t)
	SetDNSPathManager(m)
	defer SetDNSPathManager(nil)
	m.SetDegradedReason("classic UDP/TCP only")

	status := dnsStatusPayload(m)
	if status["degraded_mode"] != true {
		t.Fatalf("status must expose degraded_mode, got %#v", status["degraded_mode"])
	}
	if status["degraded_reason"] != "classic UDP/TCP only" {
		t.Fatalf("status must expose degraded_reason, got %#v", status["degraded_reason"])
	}
	metrics := RenderDNSMetrics(m)
	if !strings.Contains(metrics, `b4_dns_path_degraded{reason="classic UDP/TCP only"} 1`) {
		t.Fatalf("metrics must expose degraded mode, got:\n%s", metrics)
	}

	m.SetDegradedReason("")
	if _, ok := dnsStatusPayload(m)["degraded_mode"]; ok {
		t.Fatal("cleared degraded mode must disappear from status")
	}
}
