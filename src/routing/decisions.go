package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

// DecisionEntry is a route decision retained for the transport adapters
// (SOCKS5 dial and TUN forwarding). It is written only by the authorized
// transactional route path (Bind + Decide) and read by adapters that never
// consult the fallback manager themselves (FB-23: the manager stays inside
// the authorized path).
type decisionEntry struct {
	decision  RouteDecision
	createdAt time.Time
}

// DecisionStore is a bounded, TTL-guarded cache of route decisions keyed by
// privacy-safe digests of the client destination. It is the explicit bridge
// between the authorized route path (which produces RouteDecision in
// bindAuthorizedRoute) and the transport adapters (SOCKS5 dial, TUN sender
// selection) that apply the SO_MARK/rule metadata on the device.
//
// The store is deliberately not a fallback re-decision point: it never calls
// FallbackManager.Decide. A miss means the adapter keeps its existing
// fail-open behavior (plain dial / default sender).
type DecisionStore struct {
	mu         sync.Mutex
	flows      map[string]decisionEntry // key: digest(clientIP|dstIP|dport|proto)
	domains    map[string]decisionEntry // key: digest(clientIP|domain|dport|proto)
	maxEntries int
	ttl        time.Duration
	clock      clock.Clock
}

// NewDecisionStore creates a bounded decision store. Zero-ish inputs fall back
// to defaults: 4096 entries (same bound as the binding store) and a 2 minute
// TTL aligned with the exact-flow binding timeout used by the route path.
func NewDecisionStore(maxEntries int, ttl time.Duration, clk clock.Clock) *DecisionStore {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &DecisionStore{
		flows:      make(map[string]decisionEntry, maxEntries),
		domains:    make(map[string]decisionEntry, maxEntries),
		maxEntries: maxEntries,
		ttl:        ttl,
		clock:      clk,
	}
}

// Store records the route decision for the given destination. domain may be
// empty: SOCKS5 attaches by domain when the request carries a hostname, TUN by
// IP flow; the flow key is always written so both adapters can resolve.
func (s *DecisionStore) Store(clientIP netip.Addr, dstIP netip.Addr, dport uint16, proto uint8, domain string, d RouteDecision, now time.Time) {
	if s == nil || !clientIP.IsValid() || d.SOMark == 0 {
		// A zero SO_MARK means "no route isolation metadata" and is already
		// the adapter's default behavior; storing it adds no value.
		return
	}
	if now.IsZero() {
		now = s.clock.Now()
	}
	flowKey := decisionFlowKey(clientIP, dstIP, dport, proto)
	if flowKey == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	entry := decisionEntry{decision: d, createdAt: now}
	if _, exists := s.flows[flowKey]; !exists && len(s.flows) >= s.maxEntries {
		s.evictOldestLocked(s.flows)
	}
	s.flows[flowKey] = entry
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain != "" && dstIP.IsValid() && dport > 0 {
		domKey := decisionDomainKey(clientIP, domain, dport)
		if _, exists := s.domains[domKey]; !exists && len(s.domains) >= s.maxEntries {
			s.evictOldestLocked(s.domains)
		}
		s.domains[domKey] = entry
	}
}

// LookupFlow resolves a route decision for an IP destination flow. The
// reverse direction is folded in by the same digest ordering so reply
// packets resolve identically.
func (s *DecisionStore) LookupFlow(clientIP netip.Addr, dstIP netip.Addr, dport uint16, proto uint8) (RouteDecision, bool) {
	if s == nil || !clientIP.IsValid() {
		return RouteDecision{}, false
	}
	key := decisionFlowKey(clientIP, dstIP, dport, proto)
	if key == "" {
		return RouteDecision{}, false
	}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.flows[key]
	if !ok {
		return RouteDecision{}, false
	}
	if now.Sub(entry.createdAt) >= s.ttl {
		delete(s.flows, key)
		return RouteDecision{}, false
	}
	return entry.decision, true
}

// LookupDomain looks up a route decision by client + SNI domain (the SOCKS5
// hostname path). The domain is matched case-insensitively.
func (s *DecisionStore) LookupDomain(clientIP netip.Addr, domain string, dport uint16) (RouteDecision, bool) {
	if s == nil || !clientIP.IsValid() || domain == "" {
		return RouteDecision{}, false
	}
	key := s.domainKey(clientIP, domain, dport)
	if key == "" {
		return RouteDecision{}, false
	}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.domains[key]
	if !ok {
		return RouteDecision{}, false
	}
	if now.Sub(entry.createdAt) >= s.ttl {
		delete(s.domains, key)
		return RouteDecision{}, false
	}
	return entry.decision, true
}

func (s *DecisionStore) gcLocked(now time.Time) int {
	removed := 0
	for key, entry := range s.flows {
		if now.Sub(entry.createdAt) >= s.ttl {
			delete(s.flows, key)
			removed++
		}
	}
	for key, entry := range s.domains {
		if now.Sub(entry.createdAt) >= s.ttl {
			delete(s.domains, key)
			removed++
		}
	}
	return removed
}

// GC drops expired decisions. It is wired into the pool's bounded-state
// cleanup loop so a decision can never leak marks/routes across generations
// (FB-23).
func (s *DecisionStore) GC(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gcLocked(now)
}

// Len returns the number of entries in the store.
func (s *DecisionStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(s.clock.Now())
	return len(s.flows) + len(s.domains)
}

func (s *DecisionStore) evictOldestLocked(m map[string]decisionEntry) {
	for k := range m {
		delete(m, k)
		return
	}
}

func (s *DecisionStore) domainKey(clientIP netip.Addr, domain string, dport uint16) string {
	return decisionDomainKey(clientIP, strings.ToLower(strings.TrimSpace(domain)), dport)
}

// decisionFlowKey builds a canonically ordered per-flow digest. The two
// endpoint addresses are ordered relative to each other so that the
// direction is irrelevant: both the request and reply directions of the same
// flow produce the same key, mirrored to exactly the same destination port.
func decisionFlowKey(clientIP netip.Addr, dstIP netip.Addr, dport uint16, proto uint8) string {
	if !clientIP.IsValid() || !dstIP.IsValid() {
		return ""
	}
	a := clientIP.Unmap().String()
	b := dstIP.Unmap().String()
	if b < a {
		a, b = b, a
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{strconv.Itoa(int(proto)), a, b, strconv.Itoa(int(dport))}, "|")))
	return hex.EncodeToString(sum[:12])
}

func decisionDomainKey(clientIP netip.Addr, domain string, dport uint16) string {
	if !clientIP.IsValid() || strings.TrimSpace(domain) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{clientIP.Unmap().String(), strings.ToLower(strings.TrimSpace(domain)), strconv.Itoa(int(dport))}, "|")))
	return hex.EncodeToString(sum[:12])
}
