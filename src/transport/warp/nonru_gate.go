// Non-RU route gate — runtime controller (design §7; addendum §42–47,
// §62.5, §63, §69). Owns the strict gate lifecycle around the nested inner
// path:
//
//	route active ONLY under a fresh multi-provider PASS_NON_RU attestation;
//	any RU / disagreement / stale / public-ip change / parent reconnect /
//	DNS-path loss / direct-WAN escape / manual disable / config change
//	→ IMMEDIATE revoke with the §62.5 close reason, latency measured.
//
// The gate does not program routes itself (TUN/PBR belong to the field
// layer): OnRouteOpen/OnRouteRevoke are the wiring hooks, and the
// revocation latency (§63 warp_nonru_revocation_latency_seconds) is measured
// honestly AROUND the synchronous revoke hook — trigger detection to route
// removal completion, not around a state flip only.
//
// H-NONRU-1 ("inner terminates outside RU?") is telemetry only: the gate
// surfaces BaseColo/InnerColo passthrough in Status; the verdict on that
// hypothesis belongs to the FIELD experiment, never to unit tests.
//
// IPv6: v1 scope keeps IPv6 disabled for the selected scope (§46); no IPv6
// probe machinery exists here by design.
package transportwarp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// NonRUConfig wires the gate. Transport/CurrentGen/ConfigGen and the colo
// accessors are composition points supplied at E7 wiring time; tests inject
// fakes.
type NonRUConfig struct {
	// Providers must contain at least RequiredProviders (>=2) entries with
	// distinct IDs (§43).
	Providers []GeoProvider
	// RequiredProviders is the quorum floor, default 2.
	RequiredProviders int
	// Transport returns the current INNER path transport, or an error while
	// the inner session is down (drives inner-path-lost / closed-waiting).
	Transport func() (GeoProbeTransport, error)
	// CurrentGen returns the current parent session generation; an open
	// attestation stamped with an older generation is revoked
	// (parent-reconnected; stale parent route token, §69-20).
	CurrentGen func() uint64
	// ConfigGen returns the active config generation; a bump revokes with
	// config-generation-change.
	ConfigGen func() uint64

	AttestationTTL  time.Duration // DefaultGeoAttestationTTL (120s)
	RefreshInterval time.Duration // DefaultGeoRefreshEvery (60s)
	ProbeTimeout    time.Duration // per provider, DefaultGeoProbeTimeout (3s)

	// RUCountries lists ISO codes classified RU; default {"RU"}.
	RUCountries map[string]bool
	// FallbackToBase enables the optional §47 advanced policy: after a
	// revoke the fallback_to_base event is emitted alongside fail-closed.
	// UI warning duty lives upstream (§47).
	FallbackToBase bool

	// OnRouteOpen applies the non-RU route for this attestation (field
	// layer). A failing hook keeps the gate closed; the next fresh PASS
	// retries. OnRouteRevoke removes it synchronously; its duration counts
	// into the revocation latency.
	OnRouteOpen   func(GeoAttestation) error
	OnRouteRevoke func(reason string) error

	// Sink receives structured events (§62.5 names); nil sinks drop them.
	Sink func(NonRUEvent)
	// Now overrides the clock in tests.
	Now func() time.Time
	// PollInterval drives the controller tick, default 20ms.
	PollInterval time.Duration
	// BaseColo / InnerColo surface per-layer edge telemetry into Status
	// (H-NONRU-1 field experiment feeds on these; engine never verdicts).
	BaseColo  func() string
	InnerColo func() string
}

func (c *NonRUConfig) fillDefaults() {
	if c.RequiredProviders <= 0 {
		c.RequiredProviders = DefaultRequiredProviders
	}
	if c.AttestationTTL <= 0 {
		c.AttestationTTL = DefaultGeoAttestationTTL
	}
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = DefaultGeoRefreshEvery
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = DefaultGeoProbeTimeout
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 20 * time.Millisecond
	}
	if len(c.RUCountries) == 0 {
		c.RUCountries = map[string]bool{"RU": true}
	}
}

// validate enforces the structural §43 invariants.
func (c *NonRUConfig) validate() error {
	if c.Transport == nil {
		return fmt.Errorf("%w: transport factory required", ErrGeoConfig)
	}
	if len(c.Providers) < c.RequiredProviders || c.RequiredProviders < 2 {
		return fmt.Errorf("%w: need >=2 independent providers (got %d, required %d)",
			ErrGeoConfig, len(c.Providers), c.RequiredProviders)
	}
	seen := map[string]bool{}
	for _, p := range c.Providers {
		if p == nil || p.ID() == "" {
			return fmt.Errorf("%w: provider with empty id", ErrGeoConfig)
		}
		if seen[p.ID()] {
			return fmt.Errorf("%w: duplicate provider id %q", ErrGeoConfig, p.ID())
		}
		seen[p.ID()] = true
	}
	return nil
}

// ErrGeoConfig reports invalid NewNonRUGate configurations.
var ErrGeoConfig = errors.New("transportwarp: invalid non-RU gate config")

// NonRUEvent is one structured §62.5 event.
type NonRUEvent struct {
	Name       string
	Provider   string
	Reason     string
	Verdict    string
	Gen        uint64
	DurationMS uint64
	Detail     string
	ObservedAt time.Time
}

// NonRUStatus is the externally visible snapshot.
type NonRUStatus struct {
	Open                  bool
	Verdict               GeoVerdict
	CloseReason           string
	ManualDisabled        bool
	Attestation           GeoAttestation
	Observations          []GeoObservation // last refresh round (fresh evidence)
	Revocations           uint64
	LastRevocationLatency time.Duration
	SessionGen            uint64
	BaseColo              string // H-NONRU-1 telemetry passthrough
	InnerColo             string
}

const nonruEventRing = 64

// NonRUGate is the strict non-RU route gate controller.
type NonRUGate struct {
	cfg NonRUConfig

	mu             sync.Mutex
	open           bool
	manual         bool
	verdict        GeoVerdict
	closeReason    string
	att            GeoAttestation
	lastObs        []GeoObservation
	revocations    uint64
	lastRevLatency time.Duration
	nextRefresh    time.Time
	configGenLast  uint64
	configGenSeen  bool
	events         []NonRUEvent
	cancel         context.CancelFunc
	startOnce      sync.Once
	stopOnce       sync.Once
	done           chan struct{}
	wake           chan struct{}
}

// NewNonRUGate validates the configuration.
func NewNonRUGate(cfg NonRUConfig) (*NonRUGate, error) {
	cfg.fillDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &NonRUGate{
		cfg:  cfg,
		done: make(chan struct{}),
		wake: make(chan struct{}, 1),
	}, nil
}

// Start launches the controller loop once.
func (g *NonRUGate) Start(parent context.Context) error {
	g.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		g.cancel = cancel
		go g.run(ctx)
	})
	select {
	case <-g.done:
		return ErrNestedNotRunning
	default:
		return nil
	}
}

// Stop cancels the loop and waits for completion. Idempotent. An open route
// is NOT revoked here on purpose: Stop is teardown of the whole runtime,
// where the field layer removes routes with everything else (child-first
// ordering lives in NestedRuntime).
func (g *NonRUGate) Stop() {
	g.stopOnce.Do(func() {
		if g.cancel != nil {
			g.cancel()
		}
	})
	<-g.done
}

// Done exposes loop termination.
func (g *NonRUGate) Done() <-chan struct{} { return g.done }

// ManualDisable revokes with reason manual-disable and stops all probing
// until a new gate instance is created (§47 checkbox semantics: disabled is
// a terminal operator decision).
func (g *NonRUGate) ManualDisable() {
	g.mu.Lock()
	g.manual = true
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// Status snapshots the gate state.
func (g *NonRUGate) Status() NonRUStatus {
	g.mu.Lock()
	st := NonRUStatus{
		Open:                  g.open,
		Verdict:               g.verdict,
		CloseReason:           g.closeReason,
		ManualDisabled:        g.manual,
		Attestation:           g.att,
		Revocations:           g.revocations,
		LastRevocationLatency: g.lastRevLatency,
		SessionGen:            g.att.SessionGeneration,
	}
	if g.lastObs != nil {
		st.Observations = append([]GeoObservation(nil), g.lastObs...)
	}
	g.mu.Unlock()
	if g.cfg.BaseColo != nil {
		st.BaseColo = g.cfg.BaseColo()
	}
	if g.cfg.InnerColo != nil {
		st.InnerColo = g.cfg.InnerColo()
	}
	return st
}

// RecentEvents returns a copy of the diagnostic ring (oldest first).
func (g *NonRUGate) RecentEvents() []NonRUEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]NonRUEvent(nil), g.events...)
}

// ---- internals ----

func (g *NonRUGate) now() time.Time {
	if g.cfg.Now != nil {
		return g.cfg.Now()
	}
	return time.Now()
}

func (g *NonRUGate) emit(ev NonRUEvent) {
	now := g.now()
	g.mu.Lock()
	ev.ObservedAt = now
	g.events = append(g.events, ev)
	if len(g.events) > nonruEventRing {
		g.events = g.events[1:]
	}
	sink := g.cfg.Sink
	g.mu.Unlock()
	if sink != nil {
		sink(ev)
	}
}

func (g *NonRUGate) run(ctx context.Context) {
	defer close(g.done)
	ticker := time.NewTicker(g.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-g.wake:
		}

		var gen uint64
		if g.cfg.CurrentGen != nil {
			gen = g.cfg.CurrentGen()
		}
		var cfgGen uint64
		cfgGenSeen := false
		if g.cfg.ConfigGen != nil {
			cfgGen = g.cfg.ConfigGen()
			cfgGenSeen = true
		}

		g.mu.Lock()
		manual := g.manual
		configChanged := cfgGenSeen && g.configGenSeen && g.configGenLast != cfgGen
		wasOpen := g.open
		stale := wasOpen && !g.att.FreshUntil.IsZero() && !g.now().Before(g.att.FreshUntil)
		genMismatch := wasOpen && gen != 0 && g.att.SessionGeneration != gen
		due := g.nextRefresh.IsZero() || !g.now().Before(g.nextRefresh)
		g.mu.Unlock()

		switch {
		case manual:
			g.doRevoke(CloseManualDisable)
			continue
		case configChanged:
			if wasOpen {
				g.doRevoke(CloseConfigGenChange)
			}
			g.mu.Lock()
			g.configGenLast = cfgGen
			g.configGenSeen = true
			g.mu.Unlock()
			continue
		case genMismatch:
			g.doRevoke(CloseParentReconnected)
			continue
		case stale:
			g.emit(NonRUEvent{Name: EvGeoAttestationExpired, Gen: gen})
			g.doRevoke(CloseAttestationStale)
			continue
		}

		tr, terr := g.cfg.Transport()
		if terr != nil || tr == nil {
			if wasOpen {
				g.doRevoke(CloseInnerPathLost)
			}
			continue
		}
		if !due {
			continue
		}
		g.refresh(ctx, tr, gen)
	}
}

// refresh runs one full provider round and applies the verdict.
func (g *NonRUGate) refresh(ctx context.Context, tr GeoProbeTransport, gen uint64) {
	now := g.now()
	g.emit(NonRUEvent{Name: EvGeoProbeStarted, Gen: gen})

	var obs []GeoObservation
	zeroDelta := false
	resolveFails := 0
	pathProven := false

	for _, p := range g.cfg.Providers {
		pctx, cancel := context.WithTimeout(ctx, g.cfg.ProbeTimeout)
		before := tr.Counters()
		res, err := p.Probe(pctx, tr)
		after := tr.Counters()
		cancel()

		if err != nil {
			if errors.Is(err, ErrDNSNoAnswer) {
				resolveFails++
			}
			g.emit(NonRUEvent{Name: EvGeoProviderFailed, Provider: p.ID(), Gen: gen, Detail: truncate(err.Error(), 80)})
			continue
		}
		delta := DeltaPackets(before, after)
		if delta == 0 {
			zeroDelta = true
			g.emit(NonRUEvent{Name: EvGeoProviderFailed, Provider: p.ID(), Gen: gen, Detail: ErrNoCounterDelta.Error()})
			continue
		}
		if !pathProven {
			pathProven = true
			g.emit(NonRUEvent{Name: EvGeoProbePathProven, Gen: gen})
			g.emit(NonRUEvent{Name: EvDNSPathProven, Gen: gen}) // §62.6 DNS-through-inner proof
		}
		providerID := res.ProviderID
		if providerID == "" {
			providerID = p.ID()
		}
		obs = append(obs, GeoObservation{
			Provider:          providerID,
			PublicIPHash:      res.PublicIPHash,
			Country:           res.Country,
			PathID:            tr.PathID(),
			Class:             g.classify(res.Country),
			DNSProof:          true, // resolved through the inner resolver by construction
			ObservedAt:        now,
			ExpiresAt:         now.Add(g.cfg.AttestationTTL),
			CounterDelta:      delta,
			SessionGeneration: gen,
		})
		g.emit(NonRUEvent{Name: EvGeoProviderResult, Provider: providerID, Gen: gen,
			Detail: fmt.Sprintf("country=%q iphash=%s", res.Country, shortHash(res.PublicIPHash))})
	}

	g.mu.Lock()
	g.lastObs = obs
	g.mu.Unlock()

	q := EvaluateGeoQuorum(obs, g.cfg.RequiredProviders, g.now())
	g.emit(NonRUEvent{Name: EvGeoQuorumEvaluated, Verdict: string(q.Verdict), Gen: gen,
		Detail: fmt.Sprintf("valid=%d required=%d countries=%v any_ru=%t zero_delta=%t",
			q.Valid, q.Required, q.Countries, q.AnyRU, q.AnyZeroDelta)})
	g.setVerdict(q.Verdict)

	switch {
	case q.Verdict == VerdictFailRU:
		g.doRevoke(CloseProviderRU)
	case q.Verdict == VerdictPassNonRU:
		g.applyPass(tr, q, gen)
	case q.Disagreement:
		if g.isOpen() {
			g.doRevoke(CloseDisagreement)
		}
	case zeroDelta:
		// Direct-WAN escape attempt observed: fail closed when the route is
		// active; record-only while closed (hard gates concern active routes).
		if g.isOpen() {
			g.doRevoke(CloseDirectWANObserved)
		}
	case resolveFails == len(g.cfg.Providers):
		g.emit(NonRUEvent{Name: EvDNSPathFailed, Gen: gen})
		if g.isOpen() {
			g.doRevoke(CloseDNSPathFailed)
		}
	default:
		// Insufficient fresh evidence: hold; staleness closes the gate at TTL.
	}

	g.mu.Lock()
	g.nextRefresh = g.now().Add(g.cfg.RefreshInterval)
	g.mu.Unlock()
}

// applyPass handles a fresh PASS_NON_RU: public-ip change detection,
// attestation issue/renewal, and the open/promote transition.
func (g *NonRUGate) applyPass(tr GeoProbeTransport, q GeoQuorum, gen uint64) {
	now := g.now()
	newAtt := GeoAttestation{
		Class:             geoClassNonRU,
		Country:           q.Country,
		Providers:         q.Valid,
		Quorum:            q.Required,
		PublicIPHash:      q.PublicIPHash,
		PathID:            tr.PathID(),
		FreshUntil:        now.Add(g.cfg.AttestationTTL),
		IssuedAt:          now,
		SessionGeneration: gen,
	}

	g.mu.Lock()
	prev := g.att
	wasOpen := g.open
	ipChanged := wasOpen && prev.PublicIPHash != "" && prev.Valid(now) &&
		prev.PublicIPHash != newAtt.PublicIPHash
	g.mu.Unlock()

	if ipChanged {
		// refresh_on_public_ip_change (§45): revoke now, force an immediate
		// fresh round; the route reopens only on the next stable PASS.
		g.emit(NonRUEvent{Name: EvGeoPublicIPChanged, Gen: gen})
		g.doRevoke(ClosePublicIPChanged)
		g.mu.Lock()
		g.nextRefresh = g.now()
		g.mu.Unlock()
		return
	}

	g.emit(NonRUEvent{Name: EvGeoAttestationIssued, Gen: gen,
		Detail: fmt.Sprintf("country=%s providers=%d/%d", newAtt.Country, newAtt.Providers, newAtt.Quorum)})

	if !wasOpen {
		if g.cfg.OnRouteOpen != nil {
			if err := g.cfg.OnRouteOpen(newAtt); err != nil {
				g.emit(NonRUEvent{Name: EvGeoProviderFailed, Reason: CloseInnerPathLost,
					Detail: "route-open hook failed: " + truncate(err.Error(), 80)})
				return
			}
		}
		g.mu.Lock()
		g.att = newAtt
		g.open = true
		g.mu.Unlock()
		g.emit(NonRUEvent{Name: EvNonRUGateOpened, Gen: gen})
		g.emit(NonRUEvent{Name: EvNonRURoutePromoted, Gen: gen})
		return
	}
	g.mu.Lock()
	g.att = newAtt
	g.mu.Unlock()
}

// doRevoke performs the IMMEDIATE revocation: hook first (its wall time is
// part of the §63 latency), then the state flip and events. No-op when the
// route is already inactive (revocation is edge-triggered, not level).
func (g *NonRUGate) doRevoke(reason string) {
	g.mu.Lock()
	if !g.open {
		g.mu.Unlock()
		return
	}
	g.mu.Unlock()

	start := g.now()
	g.emit(NonRUEvent{Name: EvNonRURouteRevocationStarted, Reason: reason})

	hookDetail := ""
	if g.cfg.OnRouteRevoke != nil {
		if err := g.cfg.OnRouteRevoke(reason); err != nil {
			hookDetail = "revoke hook failed: " + truncate(err.Error(), 80)
		}
	}

	latency := g.now().Sub(start)
	g.mu.Lock()
	g.open = false
	g.att.Revoked = true
	g.closeReason = reason
	switch reason {
	case CloseProviderRU:
		g.verdict = VerdictFailRU
	case CloseAttestationStale:
		g.verdict = VerdictStale
	default:
		g.verdict = VerdictInconclusive
	}
	g.revocations++
	g.lastRevLatency = latency
	failClosed := reason == CloseProviderRU || reason == CloseDisagreement ||
		reason == CloseDirectWANObserved || reason == CloseDNSPathFailed ||
		reason == CloseTargetServiceGeo
	fallback := g.cfg.FallbackToBase
	g.mu.Unlock()

	if failClosed {
		g.emit(NonRUEvent{Name: EvNonRUFailClosed, Reason: reason, DurationMS: msDur(latency)})
	}
	g.emit(NonRUEvent{Name: EvNonRURouteRevoked, Reason: reason, DurationMS: msDur(latency), Detail: hookDetail})
	g.emit(NonRUEvent{Name: EvNonRUGateClosed, Reason: reason})
	if fallback {
		g.emit(NonRUEvent{Name: EvNonRUFallbackBase, Reason: reason})
	}
}

func (g *NonRUGate) classify(country string) string {
	if country == "" {
		return geoClassUnknown
	}
	if g.cfg.RUCountries[country] {
		return geoClassRU
	}
	return geoClassNonRU
}

func (g *NonRUGate) setVerdict(v GeoVerdict) {
	g.mu.Lock()
	g.verdict = v
	g.mu.Unlock()
}

func (g *NonRUGate) isOpen() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}
