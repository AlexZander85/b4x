// Persistent discover cache (review E-OPERA H3/M4, design §2 item 5): the
// last successful discover is an OFFLINE ASSET, not an in-memory nicety.
// After a reboot with a dead/unavailable API (801 "region unavailable",
// DNS cut, throttle) the data plane still boots from the cached node list
// instead of sitting empty until the control channel heals.
//
// Storage discipline mirrors the identity slot: temp file + fsync + rename,
// corrupt files quarantined *.corrupt, never deleted. Entries carry the
// region they were discovered for and a save timestamp so consumers can
// report honesty about staleness (live vs cache source in status).
package opera

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// nodeCacheFormatVersion bumps on incompatible shape changes.
const nodeCacheFormatVersion = 1

// NodeCacheMaxTTL bounds how far back a cached node list is trusted at
// bootstrap; beyond it the cache is kept on disk but is not auto-adopted
// (the API is expected to heal well within this window).
const NodeCacheMaxTTL = 24 * time.Hour

// NodeCacheRecord is the persisted payload.
type NodeCacheRecord struct {
	Format  int         `json:"format"`
	Region  string      `json:"region"`
	Entries []SEIPEntry `json:"entries"`
	SavedAt time.Time   `json:"saved_at"`
}

// Validate checks the structural minimum (non-empty, parseable entries).
func (r *NodeCacheRecord) Validate() error {
	switch {
	case r.Format != nodeCacheFormatVersion:
		return fmt.Errorf("format %d", r.Format)
	case len(r.Entries) == 0:
		return errors.New("no entries")
	}
	for _, e := range r.Entries {
		if e.IP == "" {
			return errors.New("entry without IP")
		}
	}
	return nil
}

// Stale reports whether the record is older than the trust TTL.
func (r *NodeCacheRecord) Stale(now time.Time) bool {
	return r.SavedAt.Before(now.Add(-NodeCacheMaxTTL))
}

// NodeCache persists one record at Path (nil Path disables persistence —
// tests). It is safe for concurrent use.
type NodeCache struct {
	Path string

	mu   sync.Mutex
	live *NodeCacheRecord // last successful discover this run (authoritative)
}

// DefaultNodeCachePath derives the slot path next to the identity file.
func DefaultNodeCachePath(identityPath string) string {
	dir := filepath.Dir(identityPath)
	return filepath.Join(dir, "nodecache.json")
}

// Save persists the record atomically and remembers it as the live copy.
func (c *NodeCache) Save(region string, entries []SEIPEntry, at time.Time) error {
	rec := &NodeCacheRecord{
		Format:  nodeCacheFormatVersion,
		Region:  region,
		Entries: entries,
		SavedAt: at,
	}
	if err := rec.Validate(); err != nil {
		return fmt.Errorf("opera node cache: %w", err)
	}
	c.mu.Lock()
	c.live = rec
	c.mu.Unlock()
	if c == nil || c.Path == "" {
		return nil
	}
	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".opera-nodes-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(blob); err != nil {
		cleanup()
		return err
	}
	_ = tmp.Chmod(0o600)
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, c.Path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// Load reads the persisted record (quarantine on corruption). Returns the
// record even when stale — the caller decides (FreshEnough gates
// auto-adoption; a manual fallback may take staler data).
func (c *NodeCache) Load() (*NodeCacheRecord, error) {
	if c == nil || c.Path == "" {
		return nil, ErrNodeCacheAbsent
	}
	blob, err := os.ReadFile(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNodeCacheAbsent
		}
		return nil, err
	}
	var rec NodeCacheRecord
	if err := json.Unmarshal(blob, &rec); err != nil {
		if qerr := os.Rename(c.Path, c.Path+".corrupt"); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrNodeCacheCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrNodeCacheCorrupt, err)
	}
	if err := rec.Validate(); err != nil {
		if qerr := os.Rename(c.Path, c.Path+".corrupt"); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrNodeCacheCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrNodeCacheCorrupt, err)
	}
	return &rec, nil
}

// FallbackFor returns the best cached entries for region: an exact-region
// match wins, otherwise the freshest record for any region (the transport
// is TCP to IPs — a foreign-region node still carries traffic).
func (c *NodeCache) FallbackFor(region string, now time.Time) (*NodeCacheRecord, bool) {
	rec, err := c.Load()
	if err != nil {
		return nil, false
	}
	if rec.Region == region {
		return rec, true
	}
	return rec, true // freshest (only) record — still a usable offline asset
}

// FreshEnough reports whether the record may be auto-adopted at bootstrap
// (inside the trust TTL).
func FreshEnough(rec *NodeCacheRecord, now time.Time) bool {
	return rec != nil && !rec.Stale(now)
}

var (
	// ErrNodeCacheAbsent: no cached discover on disk (fresh install).
	ErrNodeCacheAbsent = errors.New("opera node cache absent")
	// ErrNodeCacheCorrupt: cached record unreadable/tampered (quarantined).
	ErrNodeCacheCorrupt = errors.New("opera node cache corrupt")
)
