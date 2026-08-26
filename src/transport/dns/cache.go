package dnspath

import (
	"sync"
	"time"
)

// CacheEntry is one cached DNS answer inside a partition.
type CacheEntry struct {
	Payload     []byte
	Fingerprint ResponseFingerprint
	StoredAt    time.Time
	ExpiresAt   time.Time
	Negative    bool
}

// GenerationCache is the partition-keyed DNS cache (addendum §29/§49).
// Cached positive answers from an old path/generation are never served as
// fresh proof for a new one: every lookup requires the exact partition key.
type GenerationCache struct {
	mu        sync.RWMutex
	entries   map[string]CacheEntry
	maxSize   int
	negMaxTTL time.Duration

	hits   uint64
	misses uint64
	resets uint64
}

func NewGenerationCache(maxSize int, negativeMaxTTL time.Duration) *GenerationCache {
	if maxSize <= 0 {
		maxSize = 1024
	}
	if negativeMaxTTL <= 0 {
		negativeMaxTTL = 60 * time.Second
	}
	return &GenerationCache{
		entries:   map[string]CacheEntry{},
		maxSize:   maxSize,
		negMaxTTL: negativeMaxTTL,
	}
}

// Get returns the entry only from the exact partition.
func (c *GenerationCache) Get(key DNSCachePartitionKey, now time.Time) (CacheEntry, bool) {
	c.mu.RLock()
	e, ok := c.entries[key.String()]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return CacheEntry{}, false
	}
	if now.After(e.ExpiresAt) {
		c.mu.Lock()
		delete(c.entries, key.String())
		c.misses++
		c.mu.Unlock()
		return CacheEntry{}, false
	}
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return e, true
}

// Put stores an entry in its partition. Truncated answers are never cached
// as complete (addendum §61); negative TTL is bounded (§49).
func (c *GenerationCache) Put(key DNSCachePartitionKey, payload []byte, fp ResponseFingerprint, ttl time.Duration, negative bool, now time.Time) {
	if fp.Truncated {
		return
	}
	if negative && ttl > c.negMaxTTL {
		ttl = c.negMaxTTL
	}
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		c.evictLocked(now)
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	c.entries[key.String()] = CacheEntry{
		Payload: cp, Fingerprint: fp,
		StoredAt: now, ExpiresAt: now.Add(ttl), Negative: negative,
	}
}

// ResetPartition drops every entry of one path/generation/context triple.
// Used on promotion, rollback and path switch (§49).
func (c *GenerationCache) ResetPartition(networkContextID string, generation uint64, pathHash string) {
	prefix := networkContextID + "/"
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if matchPartition(k, prefix, generation, pathHash) {
			delete(c.entries, k)
		}
	}
	c.resets++
}

func matchPartition(key, prefix string, generation uint64, pathHash string) bool {
	// key format: ctx/gen/path/qname/qtype/dnssec/scope
	if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
		return false
	}
	rest := key[len(prefix):]
	// gen segment
	i := 0
	for i < len(rest) && rest[i] != '/' {
		i++
	}
	if i == len(rest) {
		return false
	}
	genStr := rest[:i]
	if genStr != uitoa(generation) {
		return false
	}
	rest = rest[i+1:]
	j := 0
	for j < len(rest) && rest[j] != '/' {
		j++
	}
	return rest[:j] == pathHash
}

func uitoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func (c *GenerationCache) evictLocked(now time.Time) {
	// drop expired first
	for k, e := range c.entries {
		if now.After(e.ExpiresAt) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.maxSize {
		return
	}
	// then oldest
	var oldestKey string
	var oldest time.Time
	for k, e := range c.entries {
		if oldestKey == "" || e.StoredAt.Before(oldest) {
			oldestKey, oldest = k, e.StoredAt
		}
	}
	delete(c.entries, oldestKey)
}

// Stats returns cache telemetry counters.
func (c *GenerationCache) Stats() (hits, misses, resets uint64, size int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, c.resets, len(c.entries)
}
