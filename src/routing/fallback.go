// Package routing contains the confidence-based escape path. It owns route
// policy and bounded state, not sockets or iptables mutation; transport
// adapters may consume the returned SO_MARK/rule metadata.
package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/observability"
)

type UnknownFlowPolicy string

const (
	UnknownAcceptDirect UnknownFlowPolicy = "direct"
	UnknownUseGeneric   UnknownFlowPolicy = "generic"
	UnknownRouteProxy   UnknownFlowPolicy = "proxy"
)

type RouteKind string

const (
	RouteNative  RouteKind = "native"
	RouteDirect  RouteKind = "direct"
	RouteGeneric RouteKind = "generic"
	RouteProxy   RouteKind = "proxy"
)

type CapabilityMatrix struct {
	NativeTCP  bool
	NativeUDP  bool
	DirectTCP  bool
	DirectUDP  bool
	GenericTCP bool
	GenericUDP bool
	ProxyTCP   bool
	ProxyUDP   bool
	IPv4       bool
	IPv6       bool
}

func DefaultCapabilityMatrix() CapabilityMatrix {
	return CapabilityMatrix{NativeTCP: true, NativeUDP: true, DirectTCP: true, DirectUDP: true, GenericTCP: true, ProxyTCP: true, IPv4: true, IPv6: true}
}

func (m CapabilityMatrix) Supports(route RouteKind, protocol uint8, family capture.AddressFamily) bool {
	if family == capture.AddressFamilyIPv4 && !m.IPv4 || family == capture.AddressFamilyIPv6 && !m.IPv6 {
		return false
	}
	udp := protocol == capture.ProtocolUDP
	switch route {
	case RouteNative:
		return !udp && m.NativeTCP || udp && m.NativeUDP
	case RouteDirect:
		return !udp && m.DirectTCP || udp && m.DirectUDP
	case RouteGeneric:
		return !udp && m.GenericTCP || udp && m.GenericUDP
	case RouteProxy:
		return !udp && m.ProxyTCP || udp && m.ProxyUDP
	default:
		return false
	}
}

type RouteConfig struct {
	Enabled           bool
	Policy            UnknownFlowPolicy
	NativeConfidence  uint8
	ProcessedMark     uint32
	ProcessedMarkMask uint32
	BypassMark        uint32
	GenericMark       uint32
	RuleTable         int
	ProxyRouteID      string
	Cooldown          time.Duration
	LastGoodTTL       time.Duration
	HealthTTL         time.Duration
	MaxScopes         int
	MaxIdlePerScope   int
	MaxUDPSessions    int
	UDPIdleTimeout    time.Duration
	Capabilities      CapabilityMatrix
	Clock             clock.Clock
}

func DefaultRouteConfig() RouteConfig {
	return RouteConfig{Policy: UnknownAcceptDirect, NativeConfidence: classifier.DefaultConfidenceThresholds.Mutate, ProcessedMarkMask: capture.ProcessedMarkMask, Cooldown: 30 * time.Second, LastGoodTTL: 5 * time.Minute, HealthTTL: 30 * time.Second, MaxScopes: 512, MaxIdlePerScope: 4, MaxUDPSessions: 1024, UDPIdleTimeout: 60 * time.Second, Capabilities: DefaultCapabilityMatrix(), Clock: clock.RealClock{}}
}

var (
	ErrRouteInvalid       = errors.New("invalid fallback route configuration")
	ErrRouteScopeRequired = errors.New("fallback route requires a set/device scope")
	ErrRouteUnavailable   = errors.New("fallback route is unavailable")
	ErrPoolFull           = errors.New("fallback connection pool is full")
)

func (c RouteConfig) normalized() (RouteConfig, error) {
	d := DefaultRouteConfig()
	if c.Policy == "" {
		c.Policy = d.Policy
	}
	if c.Policy != UnknownAcceptDirect && c.Policy != UnknownUseGeneric && c.Policy != UnknownRouteProxy {
		return RouteConfig{}, fmt.Errorf("%w: unsupported policy %q", ErrRouteInvalid, c.Policy)
	}
	if c.NativeConfidence == 0 {
		c.NativeConfidence = d.NativeConfidence
	}
	if c.ProcessedMarkMask == 0 {
		c.ProcessedMarkMask = d.ProcessedMarkMask
	}
	if c.Cooldown <= 0 {
		c.Cooldown = d.Cooldown
	}
	if c.Cooldown > time.Hour {
		c.Cooldown = time.Hour
	}
	if c.LastGoodTTL <= 0 {
		c.LastGoodTTL = d.LastGoodTTL
	}
	if c.LastGoodTTL > 24*time.Hour {
		c.LastGoodTTL = 24 * time.Hour
	}
	if c.HealthTTL <= 0 {
		c.HealthTTL = d.HealthTTL
	}
	if c.HealthTTL > time.Hour {
		c.HealthTTL = time.Hour
	}
	if c.MaxScopes <= 0 {
		c.MaxScopes = d.MaxScopes
	}
	if c.MaxScopes > 4096 {
		c.MaxScopes = 4096
	}
	if c.MaxIdlePerScope <= 0 {
		c.MaxIdlePerScope = d.MaxIdlePerScope
	}
	if c.MaxIdlePerScope > 32 {
		c.MaxIdlePerScope = 32
	}
	if c.MaxUDPSessions <= 0 {
		c.MaxUDPSessions = d.MaxUDPSessions
	}
	if c.MaxUDPSessions > 8192 {
		c.MaxUDPSessions = 8192
	}
	if c.UDPIdleTimeout <= 0 {
		c.UDPIdleTimeout = d.UDPIdleTimeout
	}
	if c.UDPIdleTimeout > 5*time.Minute {
		c.UDPIdleTimeout = 5 * time.Minute
	}
	if c.Clock == nil {
		c.Clock = d.Clock
	}
	if c.Capabilities == (CapabilityMatrix{}) {
		c.Capabilities = d.Capabilities
	}
	if c.Policy == UnknownRouteProxy && strings.TrimSpace(c.ProxyRouteID) == "" {
		return RouteConfig{}, fmt.Errorf("%w: proxy route ID is required", ErrRouteInvalid)
	}
	if c.RuleTable < 0 {
		return RouteConfig{}, fmt.Errorf("%w: rule table must not be negative", ErrRouteInvalid)
	}
	return c, nil
}

type FlowRouteRequest struct {
	SetID               string
	DeviceID            string
	Client              classifier.ClientKey
	Protocol            uint8
	Family              capture.AddressFamily
	Phase               classifier.ClassificationPhase
	Confidence          uint8
	PacketMark          uint32
	NativeActionApplied bool
}

type RouteDecision struct {
	ScopeID         string
	Route           RouteKind
	RouteID         string
	SOMark          uint32 `json:"so_mark"`
	RuleTable       int    `json:"rule_table"`
	BypassMark      uint32 `json:"bypass_mark"`
	NoDoubleProcess bool   `json:"no_double_process"`
	LastGood        bool   `json:"last_good"`
	Cooldown        bool   `json:"cooldown"`
	HealthKnown     bool   `json:"health_known"`
	HealthOK        bool   `json:"health_ok"`
	Reason          string `json:"reason"`
	Confidence      uint8  `json:"confidence"`
}

type healthState struct {
	OK        bool
	CheckedAt time.Time
}

type routeState struct {
	RouteID   string
	ExpiresAt time.Time
}

type cooldownState struct {
	Until   time.Time
	RouteID string
}

type FallbackManager struct {
	mu        sync.Mutex
	config    RouteConfig
	clock     clock.Clock
	health    map[string]healthState
	lastGood  map[string]routeState
	cooldowns map[string]cooldownState
	pool      *ConnectionPool
	udp       *UDPSessionStore
}

func NewFallbackManager(config RouteConfig) (*FallbackManager, error) {
	normalized, err := config.normalized()
	if err != nil {
		return nil, err
	}
	return &FallbackManager{config: normalized, clock: normalized.Clock, health: make(map[string]healthState), lastGood: make(map[string]routeState), cooldowns: make(map[string]cooldownState), pool: NewConnectionPool(normalized.MaxScopes, normalized.MaxIdlePerScope, normalized.Clock), udp: NewUDPSessionStore(normalized.MaxUDPSessions, normalized.UDPIdleTimeout, normalized.Clock)}, nil
}

func (m *FallbackManager) Decide(request FlowRouteRequest) (RouteDecision, error) {
	if m == nil {
		return RouteDecision{}, ErrRouteInvalid
	}
	if strings.TrimSpace(request.SetID) == "" && strings.TrimSpace(request.DeviceID) == "" && request.Client.IsZero() {
		return RouteDecision{}, ErrRouteScopeRequired
	}
	if request.Protocol != capture.ProtocolTCP && request.Protocol != capture.ProtocolUDP {
		return RouteDecision{}, fmt.Errorf("%w: unsupported protocol", ErrRouteInvalid)
	}
	if request.Family != capture.AddressFamilyIPv4 && request.Family != capture.AddressFamilyIPv6 {
		return RouteDecision{}, fmt.Errorf("%w: IP family is required", ErrRouteInvalid)
	}
	scope := ScopeID(request.SetID, request.DeviceID, request.Client)
	decision := RouteDecision{ScopeID: scope, BypassMark: m.config.BypassMark, NoDoubleProcess: true, Confidence: request.Confidence}
	now := m.clock.Now()
	if capture.MatchesMark(request.PacketMark, m.config.ProcessedMark, m.config.ProcessedMarkMask) || request.NativeActionApplied {
		decision.Route = RouteNative
		decision.RouteID = "native"
		decision.Reason = "processed or native action flow bypasses fallback"
		m.recordDecision(decision)
		return decision, nil
	}
	resolved := (request.Phase == classifier.PhaseResolved || request.Phase == classifier.PhaseFinal) && request.Confidence >= m.config.NativeConfidence
	if resolved && m.config.Capabilities.Supports(RouteNative, request.Protocol, request.Family) {
		decision.Route = RouteNative
		decision.RouteID = "native"
		decision.Reason = "resolved high-confidence flow uses native B4 action"
		m.recordDecision(decision)
		return decision, nil
	}
	if !m.config.Enabled {
		decision.Route = RouteDirect
		decision.RouteID = "direct"
		decision.Reason = "fallback feature is disabled; fail-open direct route"
		m.recordDecision(decision)
		return decision, nil
	}
	decision = m.chooseFallbackLocked(decision, scope, request, now)
	m.recordDecision(decision)
	return decision, nil
}

func (m *FallbackManager) chooseFallbackLocked(decision RouteDecision, scope string, request FlowRouteRequest, now time.Time) RouteDecision {
	m.mu.Lock()
	defer m.mu.Unlock()
	route := RouteDirect
	routeID := "direct"
	reason := "ambiguous/unknown flow uses scoped direct fallback"
	switch m.config.Policy {
	case UnknownUseGeneric:
		route, routeID, reason = RouteGeneric, "generic", "ambiguous/unknown flow uses scoped generic fallback"
	case UnknownRouteProxy:
		route, routeID, reason = RouteProxy, m.config.ProxyRouteID, "ambiguous/unknown flow uses scoped proxy fallback"
	}
	decision.Route, decision.RouteID, decision.Reason = route, routeID, reason
	if !m.config.Capabilities.Supports(route, request.Protocol, request.Family) {
		decision.Route = RouteDirect
		decision.RouteID = "direct"
		decision.Reason = "configured fallback lacks protocol/family capability; fail-open direct"
		return decision
	}
	if route == RouteProxy {
		if state, ok := m.health[routeID]; ok {
			decision.HealthKnown = true
			decision.HealthOK = state.OK && now.Sub(state.CheckedAt) <= m.config.HealthTTL
		}
		if cooldown, ok := m.cooldowns[scope]; ok && now.Before(cooldown.Until) {
			decision.Cooldown = true
			decision.Reason = "proxy route is in scoped cooldown"
			if last, ok := m.lastGood[scope]; ok && now.Before(last.ExpiresAt) && m.config.Capabilities.Supports(RouteKind(last.RouteID), request.Protocol, request.Family) {
				decision.Route, decision.RouteID, decision.LastGood = routeKindForID(last.RouteID), last.RouteID, true
				decision.Reason = "scoped cooldown uses last-good route"
				return decision
			}
			decision.Route, decision.RouteID = RouteDirect, "direct"
			return decision
		}
		if decision.HealthKnown && !decision.HealthOK {
			decision.Reason = "proxy health is stale or failed; fail-open direct"
			decision.Route, decision.RouteID = RouteDirect, "direct"
		}
	}
	if decision.Route != RouteDirect {
		decision.SOMark = routeMark(decision.Route, m.config)
		decision.RuleTable = m.config.RuleTable
		if decision.SOMark == 0 || decision.RuleTable == 0 {
			decision.Route, decision.RouteID, decision.Reason = RouteDirect, "direct", "route isolation metadata is incomplete; fail-open direct"
			decision.SOMark, decision.RuleTable = 0, 0
		}
	}
	return decision
}

func routeMark(route RouteKind, config RouteConfig) uint32 {
	if route == RouteGeneric {
		return config.GenericMark
	}
	return config.BypassMark
}

func routeKindForID(id string) RouteKind {
	if id == "generic" {
		return RouteGeneric
	}
	if id == "direct" {
		return RouteDirect
	}
	return RouteProxy
}

func (m *FallbackManager) recordDecision(decision RouteDecision) {
	observability.Default().Trace.Record(observability.TraceEvent{Kind: "fallback_route_decision", Fields: map[string]string{
		"scope": observability.RedactIdentifier(decision.ScopeID), "route": string(decision.Route), "route_id": observability.RedactIdentifier(decision.RouteID), "reason": decision.Reason, "confidence": strconv.Itoa(int(decision.Confidence)), "no_double_process": strconv.FormatBool(decision.NoDoubleProcess),
	}})
	observability.Default().Metrics.Inc(observability.MetricFallbackDecision, map[string]string{"route": string(decision.Route)}, 1)
}

func (m *FallbackManager) SetHealth(routeID string, healthy bool, checkedAt time.Time) error {
	if m == nil || strings.TrimSpace(routeID) == "" {
		return ErrRouteInvalid
	}
	if checkedAt.IsZero() {
		checkedAt = m.clock.Now()
	}
	if checkedAt.After(m.clock.Now()) {
		checkedAt = m.clock.Now()
	}
	m.mu.Lock()
	m.health[routeID] = healthState{OK: healthy, CheckedAt: checkedAt}
	m.mu.Unlock()
	m.invalidateExpired()
	return nil
}

func (m *FallbackManager) HealthCheck(ctx context.Context, routeID string, probe func(context.Context, string) error) error {
	if m == nil || probe == nil || strings.TrimSpace(routeID) == "" {
		return ErrRouteInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	err := probe(ctx, routeID)
	_ = m.SetHealth(routeID, err == nil, m.clock.Now())
	observability.Default().Metrics.Inc(observability.MetricFallbackHealth, map[string]string{"route": observability.RedactIdentifier(routeID), "healthy": strconv.FormatBool(err == nil)}, 1)
	return err
}

func (m *FallbackManager) RecordSuccess(scopeID, routeID string) error {
	if m == nil || strings.TrimSpace(scopeID) == "" || strings.TrimSpace(routeID) == "" {
		return ErrRouteInvalid
	}
	now := m.clock.Now()
	m.mu.Lock()
	if len(m.lastGood) >= m.config.MaxScopes {
		m.evictOldestLastGoodLocked()
	}
	m.lastGood[scopeID] = routeState{RouteID: routeID, ExpiresAt: now.Add(m.config.LastGoodTTL)}
	delete(m.cooldowns, scopeID)
	m.mu.Unlock()
	return nil
}

func (m *FallbackManager) RecordFailure(scopeID, routeID string) error {
	if m == nil || strings.TrimSpace(scopeID) == "" || strings.TrimSpace(routeID) == "" {
		return ErrRouteInvalid
	}
	if routeID != m.config.ProxyRouteID {
		return nil
	}
	now := m.clock.Now()
	m.mu.Lock()
	if len(m.cooldowns) >= m.config.MaxScopes {
		m.evictOldestCooldownLocked()
	}
	m.cooldowns[scopeID] = cooldownState{Until: now.Add(m.config.Cooldown), RouteID: routeID}
	m.mu.Unlock()
	observability.Default().Metrics.Inc(observability.MetricFallbackCooldown, map[string]string{"route": observability.RedactIdentifier(routeID)}, 1)
	return nil
}

func (m *FallbackManager) invalidateExpired() {
	if m == nil {
		return
	}
	now := m.clock.Now()
	m.mu.Lock()
	for scope, last := range m.lastGood {
		if !now.Before(last.ExpiresAt) {
			delete(m.lastGood, scope)
		}
	}
	for scope, cooldown := range m.cooldowns {
		if !now.Before(cooldown.Until) {
			delete(m.cooldowns, scope)
		}
	}
	m.mu.Unlock()
	if m.pool != nil {
		m.pool.GC(now)
	}
	if m.udp != nil {
		m.udp.GC(now)
	}
}

func (m *FallbackManager) evictOldestLastGoodLocked() {
	for scope := range m.lastGood {
		delete(m.lastGood, scope)
		return
	}
}

func (m *FallbackManager) evictOldestCooldownLocked() {
	for scope := range m.cooldowns {
		delete(m.cooldowns, scope)
		return
	}
}

func (m *FallbackManager) Pool() *ConnectionPool {
	if m == nil {
		return nil
	}
	return m.pool
}

func (m *FallbackManager) UDPSessions() *UDPSessionStore {
	if m == nil {
		return nil
	}
	return m.udp
}

func (m *FallbackManager) Close() error {
	if m == nil {
		return nil
	}
	if m.pool != nil {
		return m.pool.Close()
	}
	return nil
}

// ScopeID is stable and privacy-safe: it is a digest of set/device/client
// identity, never a raw export. The client key prevents cross-device route
// reuse when destinations are shared.
func ScopeID(setID, deviceID string, client classifier.ClientKey) string {
	input := strings.Join([]string{setID, deviceID, strconv.Itoa(int(client.L3Family)), client.SourceIP.Unmap().String(), strconv.Itoa(client.IfIndex), strconv.Itoa(int(client.VLAN))}, "|")
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:12])
}

type PoolKey struct {
	ScopeID string
	RouteID string
	Network string
	Target  string
}

type pooledConnection struct {
	conn     io.ReadWriteCloser
	lastUsed time.Time
}

type ConnectionPool struct {
	mu        sync.Mutex
	maxScopes int
	maxIdle   int
	idleTTL   time.Duration
	clock     clock.Clock
	entries   map[PoolKey][]pooledConnection
}

func NewConnectionPool(maxScopes, maxIdle int, clk clock.Clock) *ConnectionPool {
	if maxScopes <= 0 {
		maxScopes = 512
	}
	if maxIdle <= 0 {
		maxIdle = 4
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &ConnectionPool{maxScopes: maxScopes, maxIdle: maxIdle, idleTTL: 5 * time.Minute, clock: clk, entries: make(map[PoolKey][]pooledConnection)}
}

func (p *ConnectionPool) Put(key PoolKey, conn io.ReadWriteCloser) error {
	if p == nil || strings.TrimSpace(key.ScopeID) == "" || strings.TrimSpace(key.RouteID) == "" || conn == nil {
		return ErrRouteInvalid
	}
	now := p.clock.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked(now)
	items := p.entries[key]
	if len(items) >= p.maxIdle {
		_ = conn.Close()
		return ErrPoolFull
	}
	if len(p.entries) >= p.maxScopes {
		p.evictOneLocked()
	}
	p.entries[key] = append(items, pooledConnection{conn: conn, lastUsed: now})
	return nil
}

func (p *ConnectionPool) Get(key PoolKey) (io.ReadWriteCloser, bool) {
	if p == nil {
		return nil, false
	}
	now := p.clock.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked(now)
	items := p.entries[key]
	if len(items) == 0 {
		return nil, false
	}
	item := items[len(items)-1]
	items = items[:len(items)-1]
	if len(items) == 0 {
		delete(p.entries, key)
	} else {
		p.entries[key] = items
	}
	return item.conn, true
}

func (p *ConnectionPool) GC(now time.Time) int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gcLocked(now)
}

func (p *ConnectionPool) gcLocked(now time.Time) int {
	removed := 0
	for key, items := range p.entries {
		kept := items[:0]
		for _, item := range items {
			if now.Sub(item.lastUsed) >= p.idleTTL {
				_ = item.conn.Close()
				removed++
				continue
			}
			kept = append(kept, item)
		}
		if len(kept) == 0 {
			delete(p.entries, key)
		} else {
			p.entries[key] = kept
		}
	}
	return removed
}

func (p *ConnectionPool) evictOneLocked() {
	for key, items := range p.entries {
		if len(items) > 0 {
			_ = items[0].conn.Close()
			if len(items) == 1 {
				delete(p.entries, key)
			} else {
				p.entries[key] = items[1:]
			}
			return
		}
	}
}

func (p *ConnectionPool) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, items := range p.entries {
		for _, item := range items {
			_ = item.conn.Close()
		}
		delete(p.entries, key)
	}
	return nil
}

type UDPSessionStore struct {
	mu       sync.Mutex
	max      int
	idleTTL  time.Duration
	clock    clock.Clock
	sessions map[string]time.Time
}

func NewUDPSessionStore(max int, idleTTL time.Duration, clk clock.Clock) *UDPSessionStore {
	if max <= 0 {
		max = 1024
	}
	if idleTTL <= 0 || idleTTL > 5*time.Minute {
		idleTTL = time.Minute
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &UDPSessionStore{max: max, idleTTL: idleTTL, clock: clk, sessions: make(map[string]time.Time)}
}

func (s *UDPSessionStore) Touch(key string, now time.Time) bool {
	if s == nil || strings.TrimSpace(key) == "" {
		return false
	}
	if now.IsZero() {
		now = s.clock.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	if _, exists := s.sessions[key]; !exists && len(s.sessions) >= s.max {
		return false
	}
	s.sessions[key] = now
	return true
}

func (s *UDPSessionStore) GC(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gcLocked(now)
}

func (s *UDPSessionStore) gcLocked(now time.Time) int {
	removed := 0
	for key, last := range s.sessions {
		if now.Sub(last) >= s.idleTTL {
			delete(s.sessions, key)
			removed++
		}
	}
	return removed
}

func (s *UDPSessionStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(s.clock.Now())
	return len(s.sessions)
}
