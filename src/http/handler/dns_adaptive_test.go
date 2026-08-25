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
		Primary: primary, Fallbacks: []dnspath.DNSPathID{fallback},
		CandidateOutcomes: []dnspath.DNSPathProbeOutcome{
			{PathID: primary, Class: dnspath.OutcomePassCorrect},
			{PathID: fallback, Class: dnspath.OutcomePassCorrect},
		},
		CreatedAt: now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := m.AdoptProfile(p); err != nil {
		t.Fatal(err)
	}
	binding, err := m.NewBinding("lan", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tx := &dnspath.Transaction{
		Profile: p, Candidate: binding,
		Gate: dnspath.PromotionGate{
			FreshProfile: true, ProviderReady: true, CorrectnessSuite: true,
			SameServiceControls: true, UnrelatedControls: true,
			NoBlockingHardGate: true, MetricsParity: true,
		},
		Canary: func(context.Context, *dnspath.DNSPathBinding) error { return nil },
	}
	if err := tx.Run(context.Background(), m); err != nil {
		t.Fatal(err)
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
