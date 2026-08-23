package classifier

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

var (
	ErrInvalidHostHint       = errors.New("invalid host hint evidence")
	ErrUnscopedHostHint      = errors.New("host hint requires a source-scoped client")
	ErrUnsupportedHintSource = errors.New("evidence source cannot create a host hint")
)

// HintKey deliberately includes the complete capture identity. A shared CDN
// address can therefore carry independent candidates for independent clients
// and transport protocols.
type HintKey struct {
	Client        ClientKey
	DestinationIP netip.Addr
	L4Proto       uint8
}

type HintCandidate struct {
	Domain     string
	SetID      string
	Source     EvidenceSource
	Confidence uint8
	ExpiresAt  time.Time
	ConfigGen  uint64
}

type HostHint struct {
	Candidates []HintCandidate
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

type HostHintStoreConfig struct {
	MaxEntries          int
	MaxEntriesPerClient int
	MaxCandidatesPerKey int
	MaxBytesPerClient   int
}

var DefaultHostHintStoreConfig = HostHintStoreConfig{
	MaxEntries:          4096,
	MaxEntriesPerClient: 64,
	MaxCandidatesPerKey: 8,
	MaxBytesPerClient:   64 * 1024,
}

type HintStoreStats struct {
	Observed    uint64
	Lookups     uint64
	Hits        uint64
	Misses      uint64
	Rejected    uint64
	Expired     uint64
	Evicted     uint64
	Invalidated uint64
	Entries     uint64
	Candidates  uint64
}

type hostHintCandidate struct {
	evidence  Evidence
	createdAt time.Time
	lastUsed  time.Time
	order     uint64
}

type hostHintEntry struct {
	key        HintKey
	candidates []*hostHintCandidate
	createdAt  time.Time
	lastUsedAt time.Time
	order      uint64
}

// HostHintStore is a bounded source-scoped evidence store. It owns values,
// never config pointers, and uses absolute candidate expiry. Lookup may touch
// LRU metadata but never extends a candidate's ExpiresAt.
type HostHintStore struct {
	mu      sync.Mutex
	entries map[HintKey]*hostHintEntry
	config  HostHintStoreConfig
	clock   clock.Clock
	order   uint64
	stats   HintStoreStats
}

func NewHostHintStore(config HostHintStoreConfig, clk clock.Clock) *HostHintStore {
	defaults := DefaultHostHintStoreConfig
	if config.MaxEntries <= 0 {
		config.MaxEntries = defaults.MaxEntries
	}
	if config.MaxEntriesPerClient <= 0 {
		config.MaxEntriesPerClient = defaults.MaxEntriesPerClient
	}
	if config.MaxCandidatesPerKey <= 0 {
		config.MaxCandidatesPerKey = defaults.MaxCandidatesPerKey
	}
	if config.MaxBytesPerClient <= 0 {
		config.MaxBytesPerClient = defaults.MaxBytesPerClient
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &HostHintStore{
		entries: make(map[HintKey]*hostHintEntry, config.MaxEntries),
		config:  config,
		clock:   clk,
	}
}

// Observe inserts or updates one positive, source-scoped evidence candidate.
// A repeated candidate preserves its original expiry so repeated DNS/QUIC
// observations cannot turn a finite TTL into a sliding lifetime.
func (s *HostHintStore) Observe(observation Evidence) error {
	now := s.clock.Now()
	evidence := NormalizeEvidence(observation)
	if err := validateHostHintEvidence(evidence); err != nil {
		s.recordRejected()
		return err
	}

	createdAt := evidence.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	if createdAt.After(now) {
		s.recordRejected()
		return fmt.Errorf("%w: created_at is in the future", ErrInvalidHostHint)
	}
	evidence.CreatedAt = createdAt
	if evidence.ExpiresAt.IsZero() {
		evidence.ExpiresAt = createdAt.Add(hostHintSourceTTL(evidence.Source))
	}
	maxExpiry := createdAt.Add(hostHintSourceTTL(evidence.Source))
	if evidence.ExpiresAt.After(maxExpiry) {
		evidence.ExpiresAt = maxExpiry
	}
	if !evidence.ExpiresAt.After(createdAt) || !now.Before(evidence.ExpiresAt) {
		s.recordRejected()
		return fmt.Errorf("%w: evidence is expired", ErrInvalidHostHint)
	}
	evidence.DomainEvidence = true
	evidence.DestinationIP = normalizeHintAddr(evidence.DestinationIP)
	key := HintKey{Client: normalizeHintClient(evidence.Client), DestinationIP: evidence.DestinationIP, L4Proto: evidence.L4Proto}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	s.order++

	if entry, ok := s.entries[key]; ok {
		if existing := findHintCandidate(entry, evidence); existing != nil {
			// Keep absolute expiry and creation time. Confidence may improve when
			// a later observation has stronger parser context.
			if evidence.Confidence > existing.evidence.Confidence {
				oldCreated, oldExpiry := existing.evidence.CreatedAt, existing.evidence.ExpiresAt
				existing.evidence = evidence
				existing.evidence.CreatedAt = oldCreated
				existing.evidence.ExpiresAt = oldExpiry
			}
			entry.order = s.order
			s.stats.Observed++
			return nil
		}

		candidate := newHintCandidate(evidence, s.order)
		if !s.makeCandidateRoomLocked(entry, candidate) {
			s.stats.Rejected++
			return fmt.Errorf("%w: candidate limit reached", ErrInvalidHostHint)
		}
		entry.candidates = append(entry.candidates, candidate)
		entry.order = s.order
		s.syncEntryTimes(entry)
		s.stats.Observed++
		return nil
	}

	if !s.makeEntryRoomLocked(key.Client) {
		s.stats.Rejected++
		return fmt.Errorf("%w: entry limit reached", ErrInvalidHostHint)
	}
	candidate := newHintCandidate(evidence, s.order)
	if !s.makeClientBytesRoomLocked(key.Client, candidateBytes(candidate)) {
		s.stats.Rejected++
		return fmt.Errorf("%w: per-client byte limit reached", ErrInvalidHostHint)
	}
	entry := &hostHintEntry{
		key:        key,
		candidates: []*hostHintCandidate{candidate},
		createdAt:  evidence.CreatedAt,
		order:      s.order,
	}
	s.entries[key] = entry
	s.stats.Observed++
	return nil
}

func (s *HostHintStore) Lookup(client ClientKey, dst netip.Addr, proto uint8) []Evidence {
	return s.lookup(client, dst, proto, 0)
}

// LookupForGeneration removes candidates that cannot be revalidated against
// the active immutable config snapshot before returning the remaining values.
func (s *HostHintStore) LookupForGeneration(client ClientKey, dst netip.Addr, proto uint8, generation uint64) []Evidence {
	return s.lookup(client, dst, proto, generation)
}

func (s *HostHintStore) lookup(client ClientKey, dst netip.Addr, proto uint8, generation uint64) []Evidence {
	now := s.clock.Now()
	key := HintKey{Client: normalizeHintClient(client), DestinationIP: normalizeHintAddr(dst), L4Proto: proto}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Lookups++
	s.pruneExpiredLocked(now)
	lookupKey := key
	entry, ok := s.entries[lookupKey]
	if !ok {
		// Exact CDN node miss: reuse this client's QUIC googlevideo /24
		// affinity key (network address .0) when one was stored.
		if pfx, okPfx := IPv4Prefix24(dst); okPfx && pfx != key.DestinationIP {
			lookupKey.DestinationIP = pfx
			entry, ok = s.entries[lookupKey]
		}
	}
	if !ok {
		s.stats.Misses++
		return []Evidence{}
	}

	if generation != 0 {
		for i := len(entry.candidates) - 1; i >= 0; i-- {
			candidate := entry.candidates[i]
			if candidate.evidence.ConfigGen != 0 && candidate.evidence.ConfigGen != generation {
				s.removeCandidateLocked(entry, i)
				s.stats.Invalidated++
			}
		}
		entry = s.entries[lookupKey]
		if entry == nil {
			s.stats.Misses++
			return []Evidence{}
		}
	}

	entry.lastUsedAt = now
	entry.order = s.nextOrderLocked()
	for _, candidate := range entry.candidates {
		candidate.lastUsed = now
	}
	result := make([]Evidence, 0, len(entry.candidates))
	for _, candidate := range entry.candidates {
		result = append(result, candidate.evidence)
	}
	sortEvidence(result)
	s.stats.Hits++
	return result
}

// InvalidateGeneration removes candidates from one obsolete config snapshot.
// Callers normally pass the generation being retired during hot apply or
// rollback; no mutable SetConfig pointer is retained by this store.
func (s *HostHintStore) InvalidateGeneration(generation uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for _, entry := range s.entries {
		for i := len(entry.candidates) - 1; i >= 0; i-- {
			if entry.candidates[i].evidence.ConfigGen == generation {
				s.removeCandidateLocked(entry, i)
				removed++
				s.stats.Invalidated++
			}
		}
	}
	return removed
}

func (s *HostHintStore) DeleteClient(client ClientKey) int {
	client = normalizeHintClient(client)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, entry := range s.entries {
		if key.Client != client {
			continue
		}
		removed += len(entry.candidates)
		delete(s.entries, key)
	}
	return removed
}

func (s *HostHintStore) GC(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneExpiredLocked(now)
}

func (s *HostHintStore) Stats() HintStoreStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.stats
	stats.Entries = uint64(len(s.entries))
	for _, entry := range s.entries {
		stats.Candidates += uint64(len(entry.candidates))
	}
	return stats
}

func (s *HostHintStore) Snapshot(key HintKey) (HostHint, bool) {
	key.Client = normalizeHintClient(key.Client)
	key.DestinationIP = normalizeHintAddr(key.DestinationIP)
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	if !ok {
		return HostHint{}, false
	}
	return s.snapshotEntry(entry), true
}

func (s *HostHintStore) makeEntryRoomLocked(client ClientKey) bool {
	for len(s.entries) >= s.config.MaxEntries {
		if !s.evictEntryLocked(nil) {
			return false
		}
	}
	for s.countClientEntriesLocked(client) >= s.config.MaxEntriesPerClient {
		if !s.evictEntryLocked(&client) {
			return false
		}
	}
	return true
}

func (s *HostHintStore) makeCandidateRoomLocked(entry *hostHintEntry, candidate *hostHintCandidate) bool {
	for len(entry.candidates) >= s.config.MaxCandidatesPerKey {
		weakest := weakestCandidate(entry.candidates)
		if weakest == nil || weakerHintCandidate(candidate, weakest) {
			return false
		}
		remove := indexOfCandidate(entry.candidates, weakest)
		s.removeCandidateLocked(entry, remove)
		s.stats.Evicted++
		if s.entries[entry.key] == nil {
			// A one-candidate entry is removed by removeCandidateLocked; keep
			// the key alive so the stronger replacement can be appended.
			s.entries[entry.key] = entry
		}
	}
	if !s.makeClientBytesRoomLocked(entry.key.Client, candidateBytes(candidate)) {
		return false
	}
	return true
}

func (s *HostHintStore) makeClientBytesRoomLocked(client ClientKey, needed int) bool {
	if needed > s.config.MaxBytesPerClient {
		return false
	}
	for s.clientBytesLocked(client)+needed > s.config.MaxBytesPerClient {
		if !s.evictCandidateLocked(&client) {
			return false
		}
	}
	return true
}

func (s *HostHintStore) evictEntryLocked(client *ClientKey) bool {
	var victim *hostHintEntry
	for _, entry := range s.entries {
		if client != nil && entry.key.Client != *client {
			continue
		}
		if victim == nil || weakerEntry(entry, victim) || (sameEntryPriority(entry, victim) && hintKeyLess(entry.key, victim.key)) {
			victim = entry
		}
	}
	if victim == nil {
		return false
	}
	s.stats.Evicted += uint64(len(victim.candidates))
	delete(s.entries, victim.key)
	return true
}

func (s *HostHintStore) evictCandidateLocked(client *ClientKey) bool {
	var victimEntry *hostHintEntry
	var victimCandidate *hostHintCandidate
	var victimIndex int
	for _, entry := range s.entries {
		if client != nil && entry.key.Client != *client {
			continue
		}
		for i, candidate := range entry.candidates {
			if victimCandidate == nil || weakerHintCandidate(candidate, victimCandidate) ||
				(sameCandidatePriority(candidate, victimCandidate) && hintKeyLess(entry.key, victimEntry.key)) {
				victimEntry, victimCandidate, victimIndex = entry, candidate, i
			}
		}
	}
	if victimEntry == nil {
		return false
	}
	s.removeCandidateLocked(victimEntry, victimIndex)
	s.stats.Evicted++
	return true
}

func (s *HostHintStore) pruneExpiredLocked(now time.Time) int {
	removed := 0
	for _, entry := range s.entries {
		for i := len(entry.candidates) - 1; i >= 0; i-- {
			if !now.Before(entry.candidates[i].evidence.ExpiresAt) {
				s.removeCandidateLocked(entry, i)
				removed++
				s.stats.Expired++
			}
		}
	}
	return removed
}

func (s *HostHintStore) removeCandidateLocked(entry *hostHintEntry, index int) {
	if index < 0 || index >= len(entry.candidates) {
		return
	}
	entry.candidates = append(entry.candidates[:index], entry.candidates[index+1:]...)
	if len(entry.candidates) == 0 {
		delete(s.entries, entry.key)
		return
	}
	s.syncEntryTimes(entry)
}

func (s *HostHintStore) syncEntryTimes(entry *hostHintEntry) {
	entry.createdAt = entry.candidates[0].createdAt
	entry.lastUsedAt = entry.candidates[0].lastUsed
	for _, candidate := range entry.candidates[1:] {
		if candidate.createdAt.Before(entry.createdAt) {
			entry.createdAt = candidate.createdAt
		}
		if candidate.lastUsed.After(entry.lastUsedAt) {
			entry.lastUsedAt = candidate.lastUsed
		}
	}
}

func (s *HostHintStore) countClientEntriesLocked(client ClientKey) int {
	count := 0
	for key := range s.entries {
		if key.Client == client {
			count++
		}
	}
	return count
}

func (s *HostHintStore) clientBytesLocked(client ClientKey) int {
	bytesUsed := 0
	for _, entry := range s.entries {
		if entry.key.Client != client {
			continue
		}
		for _, candidate := range entry.candidates {
			bytesUsed += candidateBytes(candidate)
		}
	}
	return bytesUsed
}

func (s *HostHintStore) nextOrderLocked() uint64 {
	s.order++
	return s.order
}

func (s *HostHintStore) snapshotEntry(entry *hostHintEntry) HostHint {
	hint := HostHint{
		CreatedAt:  entry.createdAt,
		LastUsedAt: entry.lastUsedAt,
		Candidates: make([]HintCandidate, 0, len(entry.candidates)),
	}
	for _, candidate := range entry.candidates {
		hint.Candidates = append(hint.Candidates, HintCandidate{
			Domain:     candidate.evidence.Domain,
			SetID:      candidate.evidence.SetID,
			Source:     candidate.evidence.Source,
			Confidence: candidate.evidence.Confidence,
			ExpiresAt:  candidate.evidence.ExpiresAt,
			ConfigGen:  candidate.evidence.ConfigGen,
		})
		if candidate.evidence.ExpiresAt.After(hint.ExpiresAt) {
			hint.ExpiresAt = candidate.evidence.ExpiresAt
		}
	}
	return hint
}

func (s *HostHintStore) recordRejected() {
	s.mu.Lock()
	s.stats.Rejected++
	s.mu.Unlock()
}

func validateHostHintEvidence(e Evidence) error {
	if e.Client.IsZero() {
		return ErrUnscopedHostHint
	}
	if !e.DestinationIP.IsValid() || e.L4Proto == 0 || strings.TrimSpace(e.SetID) == "" || e.Domain == "" {
		return fmt.Errorf("%w: client, destination, protocol, domain and set are required", ErrInvalidHostHint)
	}
	if !isHostHintSource(e.Source) {
		return ErrUnsupportedHintSource
	}
	return nil
}

func isHostHintSource(source EvidenceSource) bool {
	switch source {
	case EvidencePacketSNI, EvidenceReassembledSNI, EvidenceQUICSNI,
		EvidenceDNSAnswer, EvidenceDNSHTTPS, EvidenceLegacyLearnedIP, EvidenceScopedLearnedObservation:
		return true
	default:
		return false
	}
}

func hostHintSourceTTL(source EvidenceSource) time.Duration {
	switch source {
	case EvidenceDNSAnswer, EvidenceDNSHTTPS:
		return 5 * time.Minute
	case EvidenceQUICSNI:
		return 90 * time.Second
	case EvidenceReassembledSNI:
		return 5 * time.Minute
	case EvidencePacketSNI:
		return 2 * time.Minute
	case EvidenceLegacyLearnedIP:
		return 30 * time.Second
	case EvidenceScopedLearnedObservation:
		return 90 * time.Second
	default:
		return time.Minute
	}
}

func newHintCandidate(evidence Evidence, order uint64) *hostHintCandidate {
	return &hostHintCandidate{evidence: evidence, createdAt: evidence.CreatedAt, order: order}
}

func findHintCandidate(entry *hostHintEntry, evidence Evidence) *hostHintCandidate {
	for _, candidate := range entry.candidates {
		if candidate.evidence.Domain == evidence.Domain &&
			candidate.evidence.SetID == evidence.SetID &&
			candidate.evidence.Source == evidence.Source &&
			candidate.evidence.ConfigGen == evidence.ConfigGen {
			return candidate
		}
	}
	return nil
}

func weakestCandidate(candidates []*hostHintCandidate) *hostHintCandidate {
	var weakest *hostHintCandidate
	for _, candidate := range candidates {
		if weakest == nil || weakerHintCandidate(candidate, weakest) {
			weakest = candidate
		}
	}
	return weakest
}

func weakerEntry(a, b *hostHintEntry) bool {
	aStrong := strongestCandidate(a.candidates)
	bStrong := strongestCandidate(b.candidates)
	if strength := compareHintStrength(aStrong, bStrong); strength != 0 {
		return strength < 0
	}
	if !a.lastUsedAt.Equal(b.lastUsedAt) {
		if a.lastUsedAt.IsZero() {
			return true
		}
		if b.lastUsedAt.IsZero() {
			return false
		}
		return a.lastUsedAt.Before(b.lastUsedAt)
	}
	if !a.createdAt.Equal(b.createdAt) {
		return a.createdAt.Before(b.createdAt)
	}
	return a.order < b.order
}

func sameEntryPriority(a, b *hostHintEntry) bool {
	aStrong := strongestCandidate(a.candidates)
	bStrong := strongestCandidate(b.candidates)
	return compareHintStrength(aStrong, bStrong) == 0 &&
		a.lastUsedAt.Equal(b.lastUsedAt) &&
		a.createdAt.Equal(b.createdAt) &&
		a.order == b.order
}

func strongestCandidate(candidates []*hostHintCandidate) *hostHintCandidate {
	var strongest *hostHintCandidate
	for _, candidate := range candidates {
		if strongest == nil || weakerHintCandidate(strongest, candidate) {
			strongest = candidate
		}
	}
	return strongest
}

func weakerHintCandidate(a, b *hostHintCandidate) bool {
	if strength := compareHintStrength(a, b); strength != 0 {
		return strength < 0
	}
	if !a.lastUsed.Equal(b.lastUsed) {
		if a.lastUsed.IsZero() {
			return true
		}
		if b.lastUsed.IsZero() {
			return false
		}
		return a.lastUsed.Before(b.lastUsed)
	}
	if !a.createdAt.Equal(b.createdAt) {
		return a.createdAt.Before(b.createdAt)
	}
	if a.evidence.Domain != b.evidence.Domain {
		return a.evidence.Domain < b.evidence.Domain
	}
	if a.evidence.SetID != b.evidence.SetID {
		return a.evidence.SetID < b.evidence.SetID
	}
	return a.order < b.order
}

func compareHintStrength(a, b *hostHintCandidate) int {
	if a.evidence.Confidence != b.evidence.Confidence {
		if a.evidence.Confidence < b.evidence.Confidence {
			return -1
		}
		return 1
	}
	if sourceRank(a.evidence.Source) != sourceRank(b.evidence.Source) {
		if sourceRank(a.evidence.Source) < sourceRank(b.evidence.Source) {
			return -1
		}
		return 1
	}
	return 0
}

func sameCandidatePriority(a, b *hostHintCandidate) bool {
	return !weakerHintCandidate(a, b) && !weakerHintCandidate(b, a)
}

func indexOfCandidate(candidates []*hostHintCandidate, wanted *hostHintCandidate) int {
	for i, candidate := range candidates {
		if candidate == wanted {
			return i
		}
	}
	return -1
}

func candidateBytes(candidate *hostHintCandidate) int {
	return len(candidate.evidence.Domain) + len(candidate.evidence.SetID) + 48
}

func normalizeHintAddr(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		return addr.Unmap()
	}
	return addr
}

// IPv4Prefix24 returns the /24 network address (x.y.z.0) for an IPv4 dest.
func IPv4Prefix24(addr netip.Addr) (netip.Addr, bool) {
	addr = normalizeHintAddr(addr)
	if !addr.Is4() {
		return netip.Addr{}, false
	}
	octets := addr.As4()
	octets[3] = 0
	return netip.AddrFrom4(octets), true
}

func normalizeHintClient(client ClientKey) ClientKey {
	client.SourceIP = normalizeHintAddr(client.SourceIP)
	return client
}

func hintKeyLess(a, b HintKey) bool {
	if cmp := a.DestinationIP.Compare(b.DestinationIP); cmp != 0 {
		return cmp < 0
	}
	if a.L4Proto != b.L4Proto {
		return a.L4Proto < b.L4Proto
	}
	if cmp := a.Client.SourceIP.Compare(b.Client.SourceIP); cmp != 0 {
		return cmp < 0
	}
	if cmp := bytes.Compare(a.Client.SourceMAC[:], b.Client.SourceMAC[:]); cmp != 0 {
		return cmp < 0
	}
	if a.Client.IfIndex != b.Client.IfIndex {
		return a.Client.IfIndex < b.Client.IfIndex
	}
	return a.Client.VLAN < b.Client.VLAN
}
