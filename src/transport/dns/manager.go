package dnspath

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
)

// Manager is the DNSPathManager: the single runtime owner of provider
// bindings, cache and fast failover inside the existing transport/DNS
// control plane (addendum Part X). It never decides blocking truth and never
// mutates production DNS outside transactions.
type Manager struct {
	mu sync.RWMutex

	mode      DNSOperatingMode
	policy    AdaptivePolicy
	providers map[string]DNSPathProvider // keyed by path hash
	prepared  map[string]PreparedDNSPath

	active          *DNSPathBinding
	lastGood        *DNSPathBinding
	profile         *DNSPathProfile
	lastGoodProfile *DNSPathProfile

	cache    *GenerationCache
	health   map[string]*DNSPathHealth
	axes     map[HealthAxis]AxisState
	recovery *RecoveryState

	// recurrence aggregates passive path failures (§80) and drives family-scoped
	// quarantine; quarantined/quarantineReason record the active quarantine.
	recurrence       *RecurrenceTracker
	quarantined      map[DNSPathFamily]bool
	quarantineReason map[DNSPathFamily]string

	// degradedReason is non-empty when adaptive DNS runs in an explicitly
	// degraded posture (classic UDP/TCP only, no encrypted path). It is
	// surfaced in status/metrics so the operator can see the degradation.
	degradedReason string

	generation uint64
	epoch      string
	networkCtx string

	// events records causal trace steps (§86) in memory for observability.
	events []TraceEvent

	// counters feed metrics/API parity (§85).
	counters ManagerCounters
}

// ManagerCounters are the parity-checked telemetry counters (§91).
type ManagerCounters struct {
	QueriesTotal    uint64 `json:"dns_path_query_total"`
	QueryFailures   uint64 `json:"-"`
	FallbackTotal   uint64 `json:"dns_path_fallback_total"`
	SwitchTotal     uint64 `json:"dns_path_switch_total"`
	RollbackTotal   uint64 `json:"-"`
	CacheHits       uint64 `json:"dns_cache_hit_total"`
	CacheMisses     uint64 `json:"dns_cache_miss_total"`
	ProfileCompiles uint64 `json:"dns_profile_compile_total"`
	Revalidations   uint64 `json:"dns_profile_revalidation_total"`
}

// TraceEvent is one causal trace step (§86).
type TraceEvent struct {
	Kind       string    `json:"kind"`
	PathFamily string    `json:"path_family,omitempty"`
	Generation uint64    `json:"generation"`
	Scope      string    `json:"scope,omitempty"`
	Seq        uint64    `json:"seq"`
	At         time.Time `json:"at"`
}

// RecoveryState tracks return-to-simpler-path hysteresis (§77).
type RecoveryState struct {
	SimplerCandidate *DNSPathID
	FirstProvenAt    time.Time
	ProofCount       int
	Hysteresis       time.Duration
	MinProofs        int
}

func NewManager(mode DNSOperatingMode, policy AdaptivePolicy, generation uint64, epoch, networkCtx string) *Manager {
	if mode == "" {
		mode = DNSModeCurrent
	}
	return &Manager{
		mode:             mode,
		policy:           policy,
		providers:        map[string]DNSPathProvider{},
		prepared:         map[string]PreparedDNSPath{},
		cache:            NewGenerationCache(1024, 60*time.Second),
		health:           map[string]*DNSPathHealth{},
		axes:             map[HealthAxis]AxisState{},
		recurrence:       NewRecurrenceTracker(3),
		quarantined:      map[DNSPathFamily]bool{},
		quarantineReason: map[DNSPathFamily]string{},
		generation:       generation,
		epoch:            epoch,
		networkCtx:       networkCtx,
	}
}

func (m *Manager) Mode() DNSOperatingMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mode
}

// Generation returns the runtime config generation.
func (m *Manager) Generation() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.generation
}

// NetworkContext returns the current network context ID.
func (m *Manager) NetworkContext() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.networkCtx
}

// Policy returns the active adaptive policy.
func (m *Manager) Policy() AdaptivePolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy
}

// SetPolicy replaces the adaptive policy (validated by the caller).
func (m *Manager) SetPolicy(p AdaptivePolicy) {
	m.mu.Lock()
	m.policy = p
	m.mu.Unlock()
}

// ProvidersSnapshot lists registered provider identities and capabilities.
func (m *Manager) ProvidersSnapshot() []DNSPathCapabilities {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DNSPathCapabilities, 0, len(m.providers))
	for _, p := range m.providers {
		out = append(out, p.Capabilities())
	}
	return out
}

// ProviderIDs lists registered provider path identities.
func (m *Manager) ProviderIDs() []DNSPathID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DNSPathID, 0, len(m.providers))
	for _, p := range m.providers {
		out = append(out, p.ID())
	}
	return out
}

// SetMode changes the operating mode. Adaptive selection only runs in
// adaptive/diagnostic modes; existing installs default to current (§19).
func (m *Manager) SetMode(mode DNSOperatingMode) error {
	if !mode.Valid() {
		return fmt.Errorf("invalid dns mode %q", mode)
	}
	m.mu.Lock()
	m.mode = mode
	m.mu.Unlock()
	return nil
}

// RegisterProvider adds a provider to the runtime catalog.
func (m *Manager) RegisterProvider(p DNSPathProvider) {
	m.mu.Lock()
	m.providers[p.ID().Hash()] = p
	m.mu.Unlock()
}

// Provider returns a registered provider by path hash.
func (m *Manager) Provider(hash string) (DNSPathProvider, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.providers[hash]
	return p, ok
}

// ActiveBinding returns the current promoted binding.
func (m *Manager) ActiveBinding() *DNSPathBinding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// Profile returns an isolated snapshot of the currently staged/adopted
// evidence profile. The Manager owns its internal copy so a caller cannot
// mutate already-validated receipts through a retained pointer.
func (m *Manager) Profile() *DNSPathProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneDNSPathProfile(m.profile)
}

// Cache exposes the generation cache for transactions.
func (m *Manager) Cache() *GenerationCache { return m.cache }

func (m *Manager) trace(kind string, family DNSPathFamily) {
	m.mu.Lock()
	m.events = append(m.events, TraceEvent{
		Kind: kind, PathFamily: string(family),
		Generation: m.generation, Seq: uint64(len(m.events) + 1), At: time.Now(),
	})
	m.mu.Unlock()
}

// Events returns the causal trace snapshot.
func (m *Manager) Events() []TraceEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]TraceEvent, len(m.events))
	copy(out, m.events)
	return out
}

func profileMatchesBinding(p *DNSPathProfile, b *DNSPathBinding) bool {
	return p != nil && b != nil && p.ProfileID == b.ProfileID && p.Primary.Hash() == b.Primary.Hash()
}

// promote atomically swaps the active binding, retaining last-good (§76).
func (m *Manager) promote(candidate, lastGood *DNSPathBinding) {
	m.mu.Lock()
	candidate.PromotedAt = time.Now()
	if m.active != nil {
		m.lastGood = m.active
	}
	if lastGood != nil {
		m.lastGood = lastGood
	}
	m.active = candidate
	m.counters.SwitchTotal++
	m.mu.Unlock()
	m.trace("BINDING_PROMOTED", candidate.Primary.Family)
}

// restoreLastGood reverts to the retained binding/profile pair (§76
// ROLLBACK). A staged candidate profile must never strand the previously
// promoted binding without its evidence profile.
func (m *Manager) restoreLastGood(lastGood *DNSPathBinding) {
	m.mu.Lock()
	m.active = lastGood
	if profileMatchesBinding(m.lastGoodProfile, lastGood) {
		m.profile = m.lastGoodProfile
	}
	m.counters.RollbackTotal++
	m.mu.Unlock()
	if lastGood != nil {
		m.trace("ROLLBACK_STARTED", lastGood.Primary.Family)
	} else {
		m.trace("ROLLBACK_STARTED", "")
	}
}

// AdoptProfile stages a freshly validated profile as the selection basis.
// When a binding is already active, its matching evidence profile is retained
// as last-good so production traffic remains valid throughout canary and can
// be restored atomically on rollback.
func (m *Manager) AdoptProfile(p *DNSPathProfile) error {
	if p == nil {
		return errors.New("profile required")
	}
	if err := p.Validated(time.Now()); err != nil {
		return fmt.Errorf("refusing stale/invalid/unproven profile: %w", err)
	}
	owned := cloneDNSPathProfile(p)
	m.mu.RLock()
	networkCtx := m.networkCtx
	generation := m.generation
	epoch := m.epoch
	m.mu.RUnlock()
	if owned.NetworkContextID != networkCtx || owned.ConfigGeneration != generation || owned.RuntimeEpoch != epoch {
		return errors.New("profile context/generation/epoch mismatch with runtime")
	}
	m.mu.Lock()
	if profileMatchesBinding(m.profile, m.active) {
		m.lastGoodProfile = cloneDNSPathProfile(m.profile)
	}
	m.profile = owned
	m.counters.ProfileCompiles++
	m.mu.Unlock()
	m.trace("PROFILE_COMPILED", owned.Primary.Family)
	return nil
}

// Resolve serves one production query through the active binding with
// bounded per-request fallback (§73/§74). Fast fallback only uses already
// promoted/ready profile paths — never unvalidated candidates. Freshness and
// the canonical evidence chain are checked on every request so stale or
// weakly-proven bindings cannot remain live.
func (m *Manager) Resolve(ctx context.Context, q DNSQuery) (DNSResponse, error) {
	now := time.Now()
	m.mu.RLock()
	mode := m.mode
	binding := m.active
	profile := m.profile
	lastGoodProfile := m.lastGoodProfile
	generation := m.generation
	epoch := m.epoch
	networkCtx := m.networkCtx
	m.mu.RUnlock()
	if mode != DNSModeAdaptive && mode != DNSModeManual {
		return DNSResponse{}, errors.New("adaptive DNS not enabled")
	}
	if binding == nil {
		return DNSResponse{}, errors.New("no active DNS path binding")
	}
	activeProfile := profile
	if !profileMatchesBinding(activeProfile, binding) {
		if profileMatchesBinding(lastGoodProfile, binding) {
			activeProfile = lastGoodProfile
		} else {
			return DNSResponse{}, errors.New("active DNS binding has no matching evidence profile")
		}
	}
	if err := activeProfile.Validated(now); err != nil {
		return DNSResponse{}, fmt.Errorf("active DNS profile is stale/invalid/unproven: %w", err)
	}
	if activeProfile.NetworkContextID != networkCtx || activeProfile.ConfigGeneration != generation || activeProfile.RuntimeEpoch != epoch {
		return DNSResponse{}, errors.New("active DNS profile no longer matches runtime context")
	}
	if !binding.CompatibleWith(generation, epoch, now) {
		return DNSResponse{}, errors.New("active DNS binding is stale or expired")
	}
	m.trace("DNS_QUERY_OBSERVED", binding.Primary.Family)
	m.mu.Lock()
	m.counters.QueriesTotal++
	m.mu.Unlock()

	resp, err := m.resolveVia(ctx, binding.Primary, q)
	if err == nil && !resp.Truncated {
		return resp, nil
	}
	// bounded per-request fallback: only already-ready validated paths.
	for _, fb := range binding.Fallbacks {
		if !m.pathReady(fb) {
			continue
		}
		m.mu.Lock()
		m.counters.FallbackTotal++
		m.mu.Unlock()
		m.trace("DNS_PATH_SELECTED", fb.Family)
		if resp2, err2 := m.resolveVia(ctx, fb, q); err2 == nil && !resp2.Truncated {
			return resp2, nil
		}
	}
	m.mu.Lock()
	m.counters.QueryFailures++
	m.mu.Unlock()
	if err != nil {
		return DNSResponse{}, err
	}
	return DNSResponse{}, errors.New("no complete DNS response: primary/fallback returned truncated or failed data")
}

func (m *Manager) resolveVia(ctx context.Context, path DNSPathID, q DNSQuery) (DNSResponse, error) {
	m.mu.RLock()
	quarantined := m.quarantined[path.Family]
	networkCtx := m.networkCtx
	generation := m.generation
	provider, ok := m.providers[path.Hash()]
	prepared, pok := m.prepared[path.Hash()]
	m.mu.RUnlock()
	if quarantined {
		return DNSResponse{}, fmt.Errorf("path family %s is quarantined", path.Family)
	}
	key := DNSCachePartitionKey{
		NetworkContextID: networkCtx, ConfigGeneration: generation,
		PathHash: path.Hash(), QueryNameHash: HashQName(q.Name), QType: q.QType,
		DNSSECPolicy: "off", ClientScopeClass: "router-origin",
	}
	if e, ok := m.cache.Get(key, time.Now()); ok {
		m.mu.Lock()
		m.counters.CacheHits++
		m.mu.Unlock()
		payload := append([]byte(nil), e.Payload...)
		if len(payload) >= 2 {
			payload[0] = byte(q.TxID >> 8)
			payload[1] = byte(q.TxID)
		}
		resp := DNSResponse{Payload: payload, Fingerprint: e.Fingerprint, FromCache: true}
		if meta, err := b4dns.InspectResponseMetadata(payload); err == nil {
			if meta.Truncated {
				return DNSResponse{}, errors.New("truncated DNS response found in cache partition")
			}
			resp.RCode = meta.RCode
			resp.Truncated = false
		}
		return resp, nil
	}
	m.mu.Lock()
	m.counters.CacheMisses++
	m.mu.Unlock()
	if !ok || !pok || prepared.Generation != generation {
		return DNSResponse{}, fmt.Errorf("path %s not prepared for generation %d", path.Family, generation)
	}
	resp, err := provider.Resolve(ctx, prepared, q)
	if err != nil {
		return DNSResponse{}, err
	}
	if resp.Truncated {
		return DNSResponse{}, errors.New("provider returned truncated DNS response as complete")
	}
	if meta, metaErr := b4dns.InspectResponseMetadata(resp.Payload); metaErr == nil {
		if meta.Truncated {
			return DNSResponse{}, errors.New("provider payload has TC=1 and cannot be returned as complete")
		}
		negative := meta.RCode == 3 || (meta.RCode == 0 && meta.AnswerCount == 0)
		ttl := time.Duration(resp.Fingerprint.TTLMin) * time.Second
		if negative {
			ttl = meta.NegativeTTL
		}
		m.cache.Put(key, resp.Payload, resp.Fingerprint, ttl, negative, time.Now())
	}
	return resp, nil
}

func (m *Manager) pathReady(path DNSPathID) bool {
	m.mu.RLock()
	if m.quarantined[path.Family] {
		m.mu.RUnlock()
		return false
	}
	h, ok := m.health[path.Hash()]
	m.mu.RUnlock()
	if !ok || h == nil {
		return false
	}
	return h.State == CapReady || h.State == CapAvailable
}

// MarkPathHealth records a health snapshot (provider-reported or
// monitor-derived). Monitoring never mutates bindings through this path.
func (m *Manager) MarkPathHealth(path DNSPathID, h DNSPathHealth) {
	m.mu.Lock()
	cp := h
	m.health[path.Hash()] = &cp
	m.mu.Unlock()
}

// RecordPathFailure records one passive path failure observation and applies
// family-scoped quarantine when the recurrence threshold is reached (§80).
// Fast kinds — the DPI mid-handshake cut (KindMidHandshakeReset) — quarantine
// after the FIRST observation (FastThreshold=1). Quarantine is family-scoped,
// never resolver-wide, so plaintext UDP/TCP paths to the same resolver IPs stay
// eligible (§80: "plaintext fallback to the same resolver IPs remains a valid
// candidate"). The tracker itself never mutates bindings (ADR-ADNS-010).
func (m *Manager) RecordPathFailure(family DNSPathFamily, kind string) bool {
	m.mu.Lock()
	triggered := m.recurrence.Record(family, kind, time.Now())
	if triggered {
		m.quarantined[family] = true
		m.quarantineReason[family] = kind
		m.axes[AxisTransport] = AxisDegraded
	}
	m.mu.Unlock()
	if triggered {
		m.trace("PATH_FAMILY_QUARANTINED", family)
	}
	return triggered
}

// SetDegradedReason records (or clears, with "") the explicit degraded-mode
// marker for adaptive DNS. A non-empty reason is surfaced in status/metrics and
// traced, so a fallback to classic-only DNS is visible to the operator.
func (m *Manager) SetDegradedReason(reason string) {
	m.mu.Lock()
	changed := m.degradedReason != reason
	m.degradedReason = reason
	m.mu.Unlock()
	if changed && reason != "" {
		m.trace("DEGRADED_MODE", "")
	}
}

// DegradedReason returns the current degraded-mode reason ("" when normal).
func (m *Manager) DegradedReason() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.degradedReason
}

// IsFamilyQuarantined reports whether a family is currently quarantined.
func (m *Manager) IsFamilyQuarantined(family DNSPathFamily) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.quarantined[family]
}

// QuarantinedFamilies returns the currently quarantined families, sorted for
// deterministic API/metrics rendering.
func (m *Manager) QuarantinedFamilies() []DNSPathFamily {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DNSPathFamily, 0, len(m.quarantined))
	for f := range m.quarantined {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// QuarantineReason returns the failure kind that quarantined a family ("" when
// the family is not quarantined).
func (m *Manager) QuarantineReason(family DNSPathFamily) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.quarantineReason[family]
}

// ClearPathFailure resets recurrence and releases family quarantine after a
// successful revalidation/recovery (§77/§80). It is the only path back to
// eligibility for a quarantined family.
func (m *Manager) ClearPathFailure(family DNSPathFamily, kind string) {
	m.mu.Lock()
	m.recurrence.Reset(family, kind)
	delete(m.quarantined, family)
	delete(m.quarantineReason, family)
	if len(m.quarantined) == 0 && m.axes[AxisTransport] == AxisDegraded {
		delete(m.axes, AxisTransport)
	}
	m.mu.Unlock()
	m.trace("PATH_FAMILY_RELEASED", family)
}

// ReleaseAllQuarantines clears every family quarantine after a successful
// revalidation/recovery (§77/§80) and reports what was released. Quarantine is
// time/evidence-scoped, not permanent: the family must be able to return
// automatically once the block is lifted.
func (m *Manager) ReleaseAllQuarantines() []DNSPathFamily {
	m.mu.Lock()
	released := make([]DNSPathFamily, 0, len(m.quarantined))
	for f := range m.quarantined {
		m.recurrence.Reset(f, m.quarantineReason[f])
		released = append(released, f)
	}
	m.quarantined = map[DNSPathFamily]bool{}
	m.quarantineReason = map[DNSPathFamily]string{}
	if m.axes[AxisTransport] == AxisDegraded {
		delete(m.axes, AxisTransport)
	}
	m.mu.Unlock()
	sort.Slice(released, func(i, j int) bool { return released[i] < released[j] })
	for _, f := range released {
		m.trace("PATH_FAMILY_RELEASED", f)
	}
	return released
}

// PreparePath prepares a provider for a profile generation.
func (m *Manager) PreparePath(ctx context.Context, p DNSPathProvider, diagnostic bool) error {
	m.mu.RLock()
	generation := m.generation
	networkCtx := m.networkCtx
	epoch := m.epoch
	m.mu.RUnlock()
	prepared, err := p.Prepare(ctx, DNSPrepareRequest{
		Generation: generation, NetworkContextID: networkCtx,
		RuntimeEpoch: epoch, Diagnostic: diagnostic,
	})
	if err != nil {
		return err
	}
	if prepared.Generation != generation {
		return fmt.Errorf("provider %s prepared unexpected generation %d", p.ID().Family, prepared.Generation)
	}
	m.mu.Lock()
	// Refuse to install a handle prepared against a generation/context that
	// changed while Prepare was in flight.
	if m.generation != generation || m.networkCtx != networkCtx || m.epoch != epoch {
		m.mu.Unlock()
		_ = p.Retire(ctx, prepared)
		return errors.New("runtime context changed while preparing DNS provider")
	}
	m.providers[p.ID().Hash()] = p
	m.prepared[p.ID().Hash()] = prepared
	m.mu.Unlock()
	m.trace("PROVIDER_PREPARED", p.ID().Family)
	return nil
}

// NewBinding builds a candidate binding from the adopted profile. A binding
// can never outlive the profile evidence that authorized it.
func (m *Manager) NewBinding(scope string, ttl time.Duration) (*DNSPathBinding, error) {
	now := time.Now()
	m.mu.RLock()
	p := m.profile
	generation := m.generation
	epoch := m.epoch
	m.mu.RUnlock()
	if p == nil {
		return nil, errors.New("no adopted profile")
	}
	if err := p.Validated(now); err != nil {
		return nil, fmt.Errorf("cannot bind stale/invalid/unproven profile: %w", err)
	}
	validUntil := p.ValidUntil
	if ttl > 0 {
		requested := now.Add(ttl)
		if requested.Before(validUntil) {
			validUntil = requested
		}
	}
	return &DNSPathBinding{
		BindingID: fmt.Sprintf("bind-%s", p.Primary.Hash()),
		Scope:     scope, ProfileID: p.ProfileID,
		Primary: p.Primary, Fallbacks: append([]DNSPathID(nil), p.Fallbacks...),
		ConfigGeneration: generation, RuntimeEpoch: epoch,
		PreparedAt: now, ValidUntil: validUntil,
	}, nil
}

// InvalidateOnContextChange marks the profile/binding stale on WAN or
// generation change (§23/§97). Last-good state is also invalidated because it
// belongs to the previous context and must never be restored cross-WAN.
func (m *Manager) InvalidateOnContextChange(newGeneration uint64, newNetworkCtx string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if newGeneration == m.generation && newNetworkCtx == m.networkCtx {
		return
	}
	m.generation = newGeneration
	m.networkCtx = newNetworkCtx
	if m.profile != nil {
		m.profile.Status = ProfileStatusStale
	}
	if m.lastGoodProfile != nil {
		m.lastGoodProfile.Status = ProfileStatusStale
	}
	m.active = nil
	m.lastGood = nil
	m.lastGoodProfile = nil
	m.prepared = map[string]PreparedDNSPath{}
}

// HealthReport composes the current health axes (§79). During a staged
// transaction freshness follows the profile associated with the active
// binding, not the not-yet-promoted candidate profile.
func (m *Manager) HealthReport() HealthReport {
	m.mu.RLock()
	axes := map[HealthAxis]AxisState{}
	for k, v := range m.axes {
		axes[k] = v
	}
	profile := m.profile
	lastGoodProfile := m.lastGoodProfile
	binding := m.active
	quarantinedCount := len(m.quarantined)
	m.mu.RUnlock()
	activeProfile := profile
	if binding != nil && !profileMatchesBinding(activeProfile, binding) && profileMatchesBinding(lastGoodProfile, binding) {
		activeProfile = lastGoodProfile
	}
	if activeProfile == nil {
		axes[AxisFreshness] = AxisUnknown
	} else if err := activeProfile.Validated(time.Now()); err != nil {
		axes[AxisFreshness] = AxisFailed
	} else {
		axes[AxisFreshness] = AxisHealthy
	}
	if binding == nil {
		axes[AxisFallback] = AxisUnknown
	} else if len(binding.Fallbacks) == 0 {
		axes[AxisFallback] = AxisDegraded
	} else {
		axes[AxisFallback] = AxisHealthy
	}
	// A quarantined family degrades transport health without masking a harder
	// failure reported by monitoring.
	if quarantinedCount > 0 && axes[AxisTransport] != AxisFailed {
		axes[AxisTransport] = AxisDegraded
	}
	return ComposeHealth(axes)
}

// SetAxis records one health axis from monitoring input.
func (m *Manager) SetAxis(axis HealthAxis, st AxisState) {
	m.mu.Lock()
	m.axes[axis] = st
	m.mu.Unlock()
}

// Counters returns the telemetry counters snapshot.
func (m *Manager) Counters() ManagerCounters {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.counters
}

// LastGood returns the retained rollback target.
func (m *Manager) LastGood() *DNSPathBinding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastGood
}

// RestoreLastGood performs an explicit operator-initiated rollback to the
// retained binding (§76 ROLLBACK), preserving the previous active binding as
// evidence. Returns false when no last-good exists.
func (m *Manager) RestoreLastGood(lastGood *DNSPathBinding) bool {
	if lastGood == nil {
		return false
	}
	m.restoreLastGood(lastGood)
	return true
}

// ManualPin applies the manual-mode pin semantics (§78): the pin is a policy
// upper bound; adaptive discovery may recommend but never silently replaces
// it. Removing the pin returns control to profile selection.
func (m *Manager) ManualPin() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy.PinnedPrimary
}

// SetManualPin sets or clears the manual primary pin (path hash).
func (m *Manager) SetManualPin(pathHash string) {
	m.mu.Lock()
	m.policy.PinnedPrimary = pathHash
	m.mu.Unlock()
}
