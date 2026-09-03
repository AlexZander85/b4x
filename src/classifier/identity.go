package classifier

import (
	"container/list"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

type IdentityQuality uint8

const (
	IdentityUnresolved IdentityQuality = iota
	IdentityIPOnly
	IdentityFull
)

func (q IdentityQuality) String() string {
	switch q {
	case IdentityIPOnly:
		return "ip-only"
	case IdentityFull:
		return "full"
	default:
		return "unresolved"
	}
}

type MACLookupState uint8

const (
	MACLookupMiss MACLookupState = iota
	MACLookupHit
	MACLookupLate
)

func (s MACLookupState) String() string {
	switch s {
	case MACLookupHit:
		return "hit"
	case MACLookupLate:
		return "late"
	default:
		return "miss"
	}
}

type IdentityObservation struct {
	L3Family     uint8
	SourceIP     netip.Addr
	SourceMAC    [6]byte
	IfIndex      int
	VLAN         uint16
	SourceDevice string
}

type ClientIdentity struct {
	Key             ClientKey
	SourceDevice    string
	Quality         IdentityQuality
	SourceMACLookup MACLookupState
	FirstSeen       time.Time
	LastSeen        time.Time
	Generation      uint64
	Reason          string
}

func (i ClientIdentity) TraceReason() string {
	return fmt.Sprintf("client_identity=%s source_mac_lookup=%s reason=%s", i.Quality, i.SourceMACLookup, i.Reason)
}

func (i ClientIdentity) MatchesSourceDevice(device string) bool {
	device = strings.TrimSpace(device)
	return i.SourceDevice == "" || device == "" || i.SourceDevice == device
}

// MACResolver is intentionally narrow so production can use ARP/neighbour
// lookup while tests use a deterministic in-memory resolver.
type MACResolver interface {
	LookupMAC(ip netip.Addr, ifIndex int, vlan uint16) ([6]byte, bool)
}

type MACResolverFunc func(ip netip.Addr, ifIndex int, vlan uint16) ([6]byte, bool)

func (f MACResolverFunc) LookupMAC(ip netip.Addr, ifIndex int, vlan uint16) ([6]byte, bool) {
	return f(ip, ifIndex, vlan)
}

type identityCacheKey struct {
	L3Family     uint8
	SourceIP     netip.Addr
	IfIndex      int
	VLAN         uint16
	SourceDevice string
}

type identityEntry struct {
	identity ClientIdentity
	element  *list.Element
}

type IdentityStore struct {
	mu        sync.Mutex
	entries   map[identityCacheKey]*identityEntry
	lru       *list.List
	limit     int
	clock     clock.Clock
	resolver  MACResolver
	nextEpoch uint64
}

func NewIdentityStore(limit int, clk clock.Clock, resolver MACResolver) *IdentityStore {
	if limit <= 0 {
		limit = 1024
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &IdentityStore{
		entries:  make(map[identityCacheKey]*identityEntry, limit),
		lru:      list.New(),
		limit:    limit,
		clock:    clk,
		resolver: resolver,
	}
}

// Resolve returns a bounded identity. It never waits for ARP: a missing MAC
// produces a usable IP-only identity and a traceable miss reason.
func (s *IdentityStore) Resolve(obs IdentityObservation) ClientIdentity {
	now := s.clock.Now()
	device := strings.TrimSpace(obs.SourceDevice)
	if !obs.SourceIP.IsValid() {
		return ClientIdentity{
			Quality:         IdentityUnresolved,
			SourceMACLookup: MACLookupMiss,
			FirstSeen:       now,
			LastSeen:        now,
			Reason:          "invalid source IP",
		}
	}

	mac := obs.SourceMAC
	lookup := MACLookupMiss
	if !isZeroMAC(mac) {
		lookup = MACLookupHit
	} else if s.resolver != nil {
		if resolved, ok := s.resolver.LookupMAC(obs.SourceIP, obs.IfIndex, obs.VLAN); ok && !isZeroMAC(resolved) {
			mac = resolved
			lookup = MACLookupHit
		}
	}

	key := identityCacheKey{
		L3Family:     obs.L3Family,
		SourceIP:     obs.SourceIP,
		IfIndex:      obs.IfIndex,
		VLAN:         obs.VLAN,
		SourceDevice: device,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.entries[key]; ok {
		old := entry.identity
		if isZeroMAC(mac) && !isZeroMAC(old.Key.SourceMAC) {
			mac = old.Key.SourceMAC
			lookup = MACLookupHit
		}

		if !isZeroMAC(old.Key.SourceMAC) && !isZeroMAC(mac) && old.Key.SourceMAC != mac {
			identity := s.newIdentity(obs, device, mac, lookup, now, "dhcp/ip reuse: source MAC changed")
			s.replaceLocked(entry, identity)
			return identity
		}

		if isZeroMAC(old.Key.SourceMAC) && !isZeroMAC(mac) {
			lookup = MACLookupLate
		}
		identity := old
		identity.Key.SourceMAC = mac
		identity.Quality = qualityForMAC(mac)
		identity.SourceMACLookup = lookup
		identity.LastSeen = now
		identity.SourceDevice = device
		if identity.Quality == IdentityFull && old.Quality == IdentityIPOnly {
			identity.Reason = "late ARP enrichment"
		} else if identity.Reason == "" {
			identity.Reason = reasonFor(qualityForMAC(mac), lookup)
		}
		entry.identity = identity
		s.lru.MoveToFront(entry.element)
		return identity
	}

	identity := s.newIdentity(obs, device, mac, lookup, now, reasonFor(qualityForMAC(mac), lookup))
	entry := &identityEntry{identity: identity}
	entry.element = s.lru.PushFront(key)
	s.entries[key] = entry
	if len(s.entries) > s.limit {
		s.evictOldestLocked()
	}
	return identity
}

func (s *IdentityStore) newIdentity(obs IdentityObservation, device string, mac [6]byte, lookup MACLookupState, now time.Time, reason string) ClientIdentity {
	s.nextEpoch++
	return ClientIdentity{
		Key: ClientKey{
			L3Family:  obs.L3Family,
			SourceIP:  obs.SourceIP,
			SourceMAC: mac,
			IfIndex:   obs.IfIndex,
			VLAN:      obs.VLAN,
		},
		SourceDevice:    device,
		Quality:         qualityForMAC(mac),
		SourceMACLookup: lookup,
		FirstSeen:       now,
		LastSeen:        now,
		Generation:      s.nextEpoch,
		Reason:          reason,
	}
}

func (s *IdentityStore) replaceLocked(entry *identityEntry, identity ClientIdentity) {
	entry.identity = identity
	s.lru.MoveToFront(entry.element)
}

func (s *IdentityStore) evictOldestLocked() {
	oldest := s.lru.Back()
	if oldest == nil {
		return
	}
	key := oldest.Value.(identityCacheKey)
	delete(s.entries, key)
	s.lru.Remove(oldest)
}

func (s *IdentityStore) Lookup(key ClientKey, sourceDevice string) (ClientIdentity, bool) {
	cacheKey := identityCacheKey{
		L3Family:     key.L3Family,
		SourceIP:     key.SourceIP,
		IfIndex:      key.IfIndex,
		VLAN:         key.VLAN,
		SourceDevice: strings.TrimSpace(sourceDevice),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[cacheKey]
	if !ok {
		return ClientIdentity{}, false
	}
	s.lru.MoveToFront(entry.element)
	return entry.identity, true
}

func (s *IdentityStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *IdentityStore) DeleteClient(key ClientKey, sourceDevice string) bool {
	cacheKey := identityCacheKey{
		L3Family:     key.L3Family,
		SourceIP:     key.SourceIP,
		IfIndex:      key.IfIndex,
		VLAN:         key.VLAN,
		SourceDevice: strings.TrimSpace(sourceDevice),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[cacheKey]
	if !ok {
		return false
	}
	delete(s.entries, cacheKey)
	s.lru.Remove(entry.element)
	return true
}

func (s *IdentityStore) GC(now time.Time, maxAge time.Duration) int {
	if maxAge <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for element := s.lru.Back(); element != nil; {
		previous := element.Prev()
		entry := s.entries[element.Value.(identityCacheKey)]
		if entry != nil && now.Sub(entry.identity.LastSeen) >= maxAge {
			delete(s.entries, element.Value.(identityCacheKey))
			s.lru.Remove(element)
			removed++
		}
		element = previous
	}
	return removed
}

func qualityForMAC(mac [6]byte) IdentityQuality {
	if isZeroMAC(mac) {
		return IdentityIPOnly
	}
	return IdentityFull
}

func isZeroMAC(mac [6]byte) bool { return mac == [6]byte{} }

func reasonFor(quality IdentityQuality, _ MACLookupState) string {
	if quality == IdentityFull {
		return "source MAC resolved"
	}
	return "source MAC unresolved"
}
