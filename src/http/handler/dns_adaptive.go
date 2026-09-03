package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// Adaptive DNS control plane API (addendum §83). Status, metrics and report
// are rendered from the same manager snapshot — parity is enforced by tests
// (zero-tolerance: report different primary in API and /metrics).
var (
	dnsPathManager   *dnspath.Manager
	dnsManagerMu     sync.RWMutex
	dnsIdempotency   = map[string]time.Time{}
	dnsIdempotencyMu sync.Mutex
)

// SetDNSPathManager wires the runtime manager into the API.
func SetDNSPathManager(m *dnspath.Manager) {
	dnsManagerMu.Lock()
	dnsPathManager = m
	dnsManagerMu.Unlock()
}

func getDNSPathManager() *dnspath.Manager {
	dnsManagerMu.RLock()
	defer dnsManagerMu.RUnlock()
	return dnsPathManager
}

// DNSDiagnoser runs one bounded differential diagnosis (ADNS-9). Injected
// by the service layer; the handler never constructs providers itself.
type DNSDiagnoser func(ctx context.Context) (*DNSDiagnoseResult, error)

// DNSDiagnoseResult is the API-facing diagnosis summary.
type DNSDiagnoseResult struct {
	ProfileID         string   `json:"profile_id"`
	PrimaryFamily     string   `json:"primary_family"`
	FallbackFamilies  []string `json:"fallback_families"`
	PoisoningDetected bool     `json:"poisoning_detected"`
	InjectionDetected bool     `json:"injection_detected"`
	UDPDropDetected   bool     `json:"udp_drop_detected"`
	Confidence        float64  `json:"confidence"`
	Explanation       []string `json:"explanation"`
}

var dnsDiagnoser DNSDiagnoser

// SetDNSDiagnoser wires the diagnosis entry point.
func SetDNSDiagnoser(d DNSDiagnoser) {
	dnsManagerMu.Lock()
	dnsDiagnoser = d
	dnsManagerMu.Unlock()
}

func (api *API) RegisterAdaptiveDNSApi() {
	api.mux.HandleFunc("/api/dns/v1/config", api.handleDNSConfig)
	api.mux.HandleFunc("/api/dns/v1/status", api.handleDNSStatus)
	api.mux.HandleFunc("/api/dns/v1/profile", api.handleDNSProfile)
	api.mux.HandleFunc("/api/dns/v1/diagnose", api.handleDNSDiagnose)
	api.mux.HandleFunc("/api/dns/v1/revalidate", api.handleDNSRevalidate)
	api.mux.HandleFunc("/api/dns/v1/canary", api.handleDNSCanary)
	api.mux.HandleFunc("/api/dns/v1/rollback", api.handleDNSRollback)
	api.mux.HandleFunc("/api/dns/v1/providers", api.handleDNSProviders)
	api.mux.HandleFunc("/api/dns/v1/metrics", api.handleDNSMetrics)
	api.mux.HandleFunc("/api/dns/v1/artifacts/{run_id}", api.handleDNSArtifact)
}

// dnsConfigPayload is the registered write schema for PUT /api/dns/v1/config.
type dnsConfigPayload struct {
	Mode   string                  `json:"mode"`
	Policy *dnspath.AdaptivePolicy `json:"policy,omitempty"`
}

// checkWritePreconditions enforces generation precondition and idempotency
// key for write endpoints (§83).
func (api *API) checkWritePreconditions(w http.ResponseWriter, r *http.Request, m *dnspath.Manager) bool {
	gen := r.Header.Get("X-Config-Generation")
	if gen == "" {
		http.Error(w, `{"error":"X-Config-Generation header required"}`, http.StatusPreconditionRequired)
		return false
	}
	var genVal uint64
	if _, err := fmt.Sscanf(gen, "%d", &genVal); err != nil || genVal != m.Generation() {
		http.Error(w, `{"error":"config generation precondition failed"}`, http.StatusPreconditionFailed)
		return false
	}
	key := r.Header.Get("X-Idempotency-Key")
	if key == "" {
		http.Error(w, `{"error":"X-Idempotency-Key header required"}`, http.StatusBadRequest)
		return false
	}
	dnsIdempotencyMu.Lock()
	if _, seen := dnsIdempotency[key]; seen {
		dnsIdempotencyMu.Unlock()
		http.Error(w, `{"error":"duplicate idempotency key"}`, http.StatusConflict)
		return false
	}
	dnsIdempotency[key] = time.Now()
	dnsIdempotencyMu.Unlock()
	return true
}

func (api *API) handleDNSConfig(w http.ResponseWriter, r *http.Request) {
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, `{"error":"adaptive dns not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeDNSJSON(w, map[string]any{
			"mode":   m.Mode(),
			"policy": m.Policy(),
		})
	case http.MethodPut:
		if !api.checkWritePreconditions(w, r, m) {
			return
		}
		var payload dnsConfigPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"invalid schema"}`, http.StatusBadRequest)
			return
		}
		mode := dnspath.DNSOperatingMode(payload.Mode)
		if !mode.Valid() {
			http.Error(w, `{"error":"invalid mode"}`, http.StatusBadRequest)
			return
		}
		if err := m.SetMode(mode); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		if payload.Policy != nil {
			m.SetPolicy(*payload.Policy)
		}
		writeDNSJSON(w, map[string]any{"mode": m.Mode(), "applied": true})
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// dnsStatusPayload renders the §84 status payload from the manager snapshot.
func dnsStatusPayload(m *dnspath.Manager) map[string]any {
	health := m.HealthReport()
	payload := map[string]any{
		"mode":               m.Mode(),
		"verdict":            string(health.Overall),
		"network_context_id": m.NetworkContext(),
		"config_generation":  m.Generation(),
		"rollback_ready":     m.LastGood() != nil,
		"axes":               health.Axes,
	}
	if p := m.Profile(); p != nil {
		payload["profile_id"] = p.ProfileID
		payload["diagnosis"] = map[string]any{
			"udp_injection_suspected": p.InjectionDetected,
			"poisoning_detected":      p.PoisoningDetected,
			"port53_blocked":          p.Port53Blocked,
			"confidence":              p.Confidence.Score,
		}
	}
	if b := m.ActiveBinding(); b != nil {
		payload["primary"] = map[string]any{
			"family":           b.Primary.Family,
			"resolver_id_hash": b.Primary.ResolverID,
			"health":           "healthy",
		}
		var fbs []map[string]any
		for _, fb := range b.Fallbacks {
			fbs = append(fbs, map[string]any{"family": fb.Family, "health": "ready"})
		}
		payload["fallbacks"] = fbs
	}
	return payload
}

func (api *API) handleDNSStatus(w http.ResponseWriter, r *http.Request) {
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, `{"error":"adaptive dns not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	writeDNSJSON(w, dnsStatusPayload(m))
}

func (api *API) handleDNSProfile(w http.ResponseWriter, r *http.Request) {
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, `{"error":"adaptive dns not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	p := m.Profile()
	if p == nil {
		http.Error(w, `{"error":"no profile"}`, http.StatusNotFound)
		return
	}
	writeDNSJSON(w, p)
}

func (api *API) handleDNSDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, `{"error":"adaptive dns not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	if !api.checkWritePreconditions(w, r, m) {
		return
	}
	dnsManagerMu.RLock()
	d := dnsDiagnoser
	dnsManagerMu.RUnlock()
	if d == nil {
		http.Error(w, `{"error":"diagnoser not wired"}`, http.StatusServiceUnavailable)
		return
	}
	result, err := d(r.Context())
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	runID := newDNSRunID()
	storeDNSArtifact(DNSRunArtifact{
		RunID:     runID,
		StartedAt: time.Now(),
		Result:    result,
		Status:    dnsStatusPayload(m),
		Trace:     m.Events(),
	})
	writeDNSJSON(w, map[string]any{"run_id": runID, "result": result})
}

func (api *API) handleDNSRevalidate(w http.ResponseWriter, r *http.Request) {
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, `{"error":"adaptive dns not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost || !api.checkWritePreconditions(w, r, m) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
		return
	}
	p := m.Profile()
	if p == nil {
		writeDNSJSON(w, map[string]any{"revalidated": false, "reason": "no profile"})
		return
	}
	if err := p.Valid(time.Now()); err != nil {
		writeDNSJSON(w, map[string]any{"revalidated": false, "reason": err.Error()})
		return
	}
	writeDNSJSON(w, map[string]any{"revalidated": true, "profile_id": p.ProfileID})
}

func (api *API) handleDNSCanary(w http.ResponseWriter, r *http.Request) {
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, `{"error":"adaptive dns not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost || !api.checkWritePreconditions(w, r, m) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
		return
	}
	// Canary execution is owned by the transaction layer; the API reports
	// readiness only.
	if m.Profile() == nil {
		writeDNSJSON(w, map[string]any{"canary_ready": false, "reason": "no adopted profile"})
		return
	}
	writeDNSJSON(w, map[string]any{"canary_ready": true, "profile_id": m.Profile().ProfileID})
}

func (api *API) handleDNSRollback(w http.ResponseWriter, r *http.Request) {
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, `{"error":"adaptive dns not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost || !api.checkWritePreconditions(w, r, m) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
		return
	}
	lg := m.LastGood()
	if lg == nil {
		writeDNSJSON(w, map[string]any{"rolled_back": false, "reason": "no last-good binding"})
		return
	}
	tx := &dnspath.Transaction{LastGood: lg}
	tx.Phase = dnspath.PhaseRollback
	m.RestoreLastGood(lg)
	writeDNSJSON(w, map[string]any{"rolled_back": true, "primary_family": lg.Primary.Family})
}

func (api *API) handleDNSProviders(w http.ResponseWriter, r *http.Request) {
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, `{"error":"adaptive dns not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	ids := m.ProviderIDs()
	caps := m.ProvidersSnapshot()
	type providerView struct {
		Family dnspath.DNSPathFamily   `json:"family"`
		Hash   string                  `json:"hash"`
		State  dnspath.CapabilityState `json:"state"`
		Reason string                  `json:"reason,omitempty"`
	}
	out := make([]providerView, 0, len(ids))
	for i, id := range ids {
		v := providerView{Family: id.Family, Hash: id.Hash()}
		if i < len(caps) {
			v.State = caps[i].State
			v.Reason = caps[i].Reason
		}
		out = append(out, v)
	}
	writeDNSJSON(w, out)
}

// handleDNSMetrics renders the Prometheus text exposition (§85) from the
// same manager snapshot as the status API. Raw resolver names, IPs, qnames,
// client IPs/MACs and profile IDs are never labels.
func (api *API) handleDNSMetrics(w http.ResponseWriter, r *http.Request) {
	m := getDNSPathManager()
	if m == nil {
		http.Error(w, "adaptive dns not initialized", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprint(w, RenderDNSMetrics(m))
}

// RenderDNSMetrics produces the bounded-label exposition.
func RenderDNSMetrics(m *dnspath.Manager) string {
	c := m.Counters()
	var b strings.Builder
	fmt.Fprintf(&b, "dns_path_query_total %d\n", c.QueriesTotal)
	fmt.Fprintf(&b, "dns_path_fallback_total %d\n", c.FallbackTotal)
	fmt.Fprintf(&b, "dns_path_switch_total %d\n", c.SwitchTotal)
	fmt.Fprintf(&b, "dns_cache_hit_total %d\n", c.CacheHits)
	fmt.Fprintf(&b, "dns_cache_miss_total %d\n", c.CacheMisses)
	fmt.Fprintf(&b, "dns_profile_compile_total %d\n", c.ProfileCompiles)
	fmt.Fprintf(&b, "dns_profile_revalidation_total %d\n", c.Revalidations)
	health := m.HealthReport()
	verdictGauge := 0
	if health.Overall == dnspath.AxisHealthy {
		verdictGauge = 1
	}
	fmt.Fprintf(&b, "b4_dns_path_readiness{verdict=%q} %d\n", string(health.Overall), verdictGauge)
	if binding := m.ActiveBinding(); binding != nil {
		fmt.Fprintf(&b, "b4_dns_path_selection_total{primary_family=%q,reason=%q} %d\n",
			string(binding.Primary.Family), "profile", c.SwitchTotal)
	}
	if p := m.Profile(); p != nil {
		state := p.Status
		fmt.Fprintf(&b, "b4_dns_path_profile_state{state=%q} 1\n", state)
	}
	return b.String()
}

func writeDNSJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
