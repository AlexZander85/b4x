// Serverlist cache (design §1.7, patch-plan §4.1; the fxvpn serverlist
// canon): the free-tier node list rides a TTL'd cache with conditional
// requests and a three-level fallback:
//
//	fresh in memory -> API (v2 with If-Modified-Since; 304 refreshes the
//	mark) -> on transport failure with a cache: STALE-BUT-PRESENT (announced,
//	never silent) -> with no cache at all: the embedded asset.
//
// TTL: the full list lives 3h±22%, the separate /vpn/v1/loads snapshot
// 15m±22%; the EFFECTIVE freshness is their min — 15m±22% (design §1.7).
// The loads endpoint itself is folded into this TTL: mirrors historically
// hang on extra endpoints (Nova field fact, design §11.6), so one request
// per refresh beats two.
//
// Persistence: serverlist.json, sibling of the identity slot, atomic write;
// a corrupt file is quarantined and the asset answers instead.
package proton

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// serverlistFormatVersion bumps on incompatible schema changes.
const serverlistFormatVersion = 1

// TTL bases (design §1.7): full 3h, loads 15min; effective = min.
const (
	ServerlistFullTTL  = 3 * time.Hour
	ServerlistLoadsTTL = 15 * time.Minute
	// ServerlistJitter is the ±22% wobble (vanilla logicals.py:54-56).
	ServerlistJitter = 0.22
)

// Node sources (the source= label of proton_nodes_refreshed).
const (
	SourceLiveV2   = "live-v2"
	SourceLiveV1   = "live-v1"
	SourceAsset    = "asset"
	SourceStale    = "stale"
	SourceMemCache = "cache"
)

type cachedServerlist struct {
	Version      int       `json:"version"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
	Source       string    `json:"source"`
	Nodes        []Node    `json:"nodes"`
}

// ServerlistCache fetches and caches the free-node list.
type ServerlistCache struct {
	Client *Client // nil => offline mode (cache/asset only)
	Path   string  // empty = memory-only (tests)
	// TTL is the effective freshness. 0 => ServerlistLoadsTTL with the ±22%
	// wobble (computed once via Jitter).
	TTL time.Duration
	// Jitter injects randomness for the TTL wobble (tests pin determinism).
	Jitter io.Reader
	Now    func() time.Time
	// OnEvent receives (event, source) notifications: nodes refreshes and
	// stale-but-present announcements.
	OnEvent func(event string, source string)

	mu  sync.Mutex
	cur *cachedServerlist
}

// NewServerlistCache builds the cache, loading the persisted snapshot when
// present. A corrupt file is quarantined (never deleted) and the cache
// starts empty — the asset covers the first fetch failure.
func NewServerlistCache(client *Client, path string) (*ServerlistCache, error) {
	sc := &ServerlistCache{Client: client, Path: path}
	if path == "" {
		return sc, nil
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return sc, nil
		}
		return nil, err
	}
	var f cachedServerlist
	if err := json.Unmarshal(blob, &f); err != nil || f.Version != serverlistFormatVersion {
		if qerr := os.Rename(path, path+".corrupt"); qerr != nil {
			return sc, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrIdentityCorrupt, err, qerr)
		}
		return sc, fmt.Errorf("%w: %v", ErrIdentityCorrupt, err)
	}
	sc.cur = &f
	return sc, nil
}

// effectiveTTL resolves the configured TTL against the default with jitter.
func (sc *ServerlistCache) effectiveTTL() time.Duration {
	if sc.TTL > 0 {
		return sc.TTL
	}
	r := sc.Jitter
	if r == nil {
		r = rand.Reader
	}
	var b [8]byte
	frac := 0.5
	if _, err := io.ReadFull(r, b[:]); err == nil {
		frac = float64(binary.LittleEndian.Uint64(b[:])%1_000_000) / 1_000_000
	}
	// ±22%: [0.78, 1.00) of 2x base — uniform over [1-0.22, 1+0.22].
	wobble := (1 - ServerlistJitter) + 2*ServerlistJitter*frac
	return time.Duration(float64(ServerlistLoadsTTL) * wobble)
}

// Get returns the free-node list: memory-fresh -> conditional fetch ->
// stale-but-present -> asset. The bool reports whether the answer came from
// the cache/asset rather than a fresh fetch.
func (sc *ServerlistCache) Get(ctx context.Context, sess *Session) ([]Node, bool, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	now := sc.now()

	if sc.cur != nil && now.Sub(sc.cur.FetchedAt) < sc.effectiveTTL() {
		return sc.cur.Nodes, true, nil
	}

	// Offline mode (no client wired): stale/asset only.
	if sc.Client == nil {
		return sc.offlineLocked(now)
	}

	resp, err := sc.Client.FetchLogicals(ctx, sess, sc.lastModifiedLocked())
	switch {
	case err == nil && resp == nil:
		// 304: the stored snapshot is still fresh — refresh the mark.
		sc.cur.FetchedAt = now
		sc.persistLocked()
		sc.announce(EventNodesRefreshed, SourceMemCache)
		return sc.cur.Nodes, true, nil
	case err != nil:
		// Transport OR HTTP failure: stale-but-present beats a dead network
		// for reserve-transport duty; the asset covers the rest.
		if sc.cur != nil && len(sc.cur.Nodes) > 0 {
			sc.announce(EventNodesRefreshed, SourceStale)
			return sc.cur.Nodes, true, nil
		}
		return sc.assetLocked(now)
	}

	nodes := FreeNodes(resp)
	if len(nodes) == 0 {
		// Free tier vanished (paid-only answer): honest proton-no-nodes
		// class + the asset keeps the transport usable.
		sc.announce(ClassNoNodes, SourceAsset)
		return sc.assetLocked(now)
	}
	source := SourceLiveV2
	if sc.v1Detected() {
		source = SourceLiveV1
	}
	sc.cur = &cachedServerlist{
		Version:      serverlistFormatVersion,
		LastModified: sc.Client.LastModified,
		FetchedAt:    now,
		Source:       source,
		Nodes:        nodes,
	}
	sc.persistLocked()
	sc.announce(EventNodesRefreshed, source)
	return sc.cur.Nodes, false, nil
}

// v1Detected reports whether the response came from the v1 fallback (the
// client records the endpoint that answered).
func (sc *ServerlistCache) v1Detected() bool {
	return sc.Client != nil && sc.Client.LastLogicalsv1
}

// lastModifiedLocked reads the stored conditional-request hint.
func (sc *ServerlistCache) lastModifiedLocked() string {
	if sc.cur == nil {
		return ""
	}
	return sc.cur.LastModified
}

// offlineLocked serves cache-then-asset with no network at all.
func (sc *ServerlistCache) offlineLocked(now time.Time) ([]Node, bool, error) {
	if sc.cur != nil && len(sc.cur.Nodes) > 0 {
		return sc.cur.Nodes, true, nil
	}
	return sc.assetLocked(now)
}

// assetLocked loads the embedded asset as the current snapshot.
func (sc *ServerlistCache) assetLocked(now time.Time) ([]Node, bool, error) {
	nodes, err := AssetNodes()
	if err != nil || len(nodes) == 0 {
		if err == nil {
			err = ErrNoNodes
		}
		return nil, false, fmt.Errorf("%w: asset unusable: %v", ErrNoNodes, err)
	}
	sc.cur = &cachedServerlist{
		Version:   serverlistFormatVersion,
		FetchedAt: now,
		Source:    SourceAsset,
		Nodes:     nodes,
	}
	sc.persistLocked()
	sc.announce(EventNodesRefreshed, SourceAsset)
	return nodes, false, nil
}

func (sc *ServerlistCache) announce(event, source string) {
	if sc.OnEvent != nil {
		sc.OnEvent(event, source)
	}
}

func (sc *ServerlistCache) now() time.Time {
	if sc.Now != nil {
		return sc.Now()
	}
	return time.Now()
}

// persistLocked writes the snapshot atomically (memory-only when Path=="").
func (sc *ServerlistCache) persistLocked() {
	if sc.Path == "" || sc.cur == nil {
		return
	}
	blob, err := json.MarshalIndent(sc.cur, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(sc.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".proton-sl-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(blob); err != nil {
		cleanup()
		return
	}
	_ = tmp.Chmod(0o600)
	if err := tmp.Sync(); err != nil {
		cleanup()
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, sc.Path); err != nil {
		_ = os.Remove(tmpName)
	}
}

// Snapshot returns the current source label (status view).
func (sc *ServerlistCache) Snapshot() string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.cur == nil {
		return ""
	}
	return sc.cur.Source
}

// FetchedAt reports the current snapshot time (zero when empty).
func (sc *ServerlistCache) FetchedAt() time.Time {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.cur == nil {
		return time.Time{}
	}
	return sc.cur.FetchedAt
}
