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
	// RTTDial optionally overrides the direct TCP/443 sampler. Production
	// leaves it nil and uses a plain direct net.Dialer. Tests/custom HTTP
	// transports do not probe unless they explicitly provide this seam.
	RTTDial RTTProbeDial
	// RankPorts overrides the handshake-tier candidate port window
	// (tests point it at loopback listeners); nil => ProtonPortCatalog.
	RankPorts []uint16
	// HandshakeKey arms the WG-handshake tier of the parallel ranking
	// (handshake_rank.go). It returns the identity's WG private key and
	// the engine prelude I1 ("<b 0x…>") the probe must repeat; ok=false
	// (or a nil hook) degrades to the TCP-only ranking of PR #4. The hook
	// runs OFF the cache mutex and must stay cheap (key derivation only).
	HandshakeKey func() (privateKeyB64, i1 string, ok bool)

	mu          sync.Mutex
	cur         *cachedServerlist
	rttRankedAt time.Time
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
	// ±22%: [0.78, 1.22] of the base.
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
		sc.rankCurrentLocked(ctx)
		return sc.cur.Nodes, true, nil
	}

	// Offline mode (no client wired): stale/asset only. Deliberately no RTT
	// probing here: offline means no extra network activity.
	if sc.Client == nil {
		return sc.offlineLocked(now)
	}

	resp, err := sc.Client.FetchLogicals(ctx, sess, sc.lastModifiedLocked())
	switch {
	case err == nil && resp == nil:
		// 304: the stored snapshot is still fresh — refresh the mark and
		// re-sample latency for the new freshness window.
		sc.cur.FetchedAt = now
		sc.rttRankedAt = time.Time{}
		sc.rankCurrentLocked(ctx)
		sc.persistLocked()
		sc.announce(EventNodesRefreshed, SourceMemCache)
		return sc.cur.Nodes, true, nil
	case err != nil:
		// Transport OR HTTP failure: stale-but-present beats a dead network
		// for reserve-transport duty; the asset covers the rest.
		if sc.cur != nil && len(sc.cur.Nodes) > 0 {
			sc.rankCurrentLocked(ctx)
			sc.announce(EventNodesRefreshed, SourceStale)
			return sc.cur.Nodes, true, nil
		}
		nodes, cached, aerr := sc.assetLocked(now)
		if aerr == nil {
			sc.rankCurrentLocked(ctx)
			nodes = sc.cur.Nodes
		}
		return nodes, cached, aerr
	}

	nodes := FreeNodes(resp)
	if len(nodes) == 0 {
		// Free tier vanished (paid-only answer): honest proton-no-nodes
		// class + the asset keeps the transport usable.
		sc.announce(ClassNoNodes, SourceAsset)
		nodes, cached, aerr := sc.assetLocked(now)
		if aerr == nil {
			sc.rankCurrentLocked(ctx)
			nodes = sc.cur.Nodes
		}
		return nodes, cached, aerr
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
	sc.rttRankedAt = time.Time{}
	sc.rankCurrentLocked(ctx)
	sc.persistLocked()
	sc.announce(EventNodesRefreshed, source)
	return sc.cur.Nodes, false, nil
}

// rankCurrentLocked samples literal node IPs on TCP/443 in parallel once per
// serverlist freshness generation. Get calls it while holding sc.mu, but the
// network work itself runs with the mutex released. The snapshot generation
// is checked again before results are committed, so a late RTT batch cannot
// reorder a newer server list (same generation discipline as runtime rollout).
//
// The sample is a sort hint only. When a custom HTTP client is injected we do
// not create an unexpected direct side channel unless RTTDial was explicitly
// supplied (unit tests and embedded callers keep deterministic ownership).
func (sc *ServerlistCache) rankCurrentLocked(ctx context.Context) {
	if sc.cur == nil || len(sc.cur.Nodes) < 2 || !sc.rttRankedAt.IsZero() {
		return
	}
	if sc.Client == nil {
		return
	}
	if sc.RTTDial == nil && sc.Client.HTTP != nil {
		return
	}

	generation := sc.cur.FetchedAt
	source := sc.cur.Source
	nodes := append([]Node(nil), sc.cur.Nodes...)
	dial := sc.RTTDial
	hook := sc.HandshakeKey

	// Candidate ports for the handshake tier: the catalog rotation as the
	// queue itself would issue them (the probe must measure the ports a
	// real seek would dial — a fallback port is exactly where TCP/443
	// tells nothing about the WireGuard path). RankPorts is the test/embedded
	// override seam.
	ports := append([]uint16(nil), ProtonPortCatalog...)
	if len(sc.RankPorts) > 0 {
		ports = append([]uint16(nil), sc.RankPorts...)
	}
	handshakeCands := make([]Candidate, 0, len(nodes))
	for i, n := range nodes {
		handshakeCands = append(handshakeCands, Candidate{Node: n, Port: ports[i%len(ports)]})
	}
	tcpCands := make([]Candidate, 0, len(nodes))
	for _, n := range nodes {
		tcpCands = append(tcpCands, Candidate{Node: n, Port: 443})
	}

	// Reserve this generation before dropping the mutex so another caller
	// does not start the same probe batch. Even an all-failed batch counts as
	// sampled; repeated TCP noise every status/location call is undesirable.
	sc.rttRankedAt = sc.now()
	sc.mu.Unlock()

	// Параллельный опрос (Nova canon): handshake-пробы и TCP-замер идут
	// ОДНОВРЕМЕННО, каждый со своей параллельностью; слияние — после.
	privB64, i1, armed := "", "", false
	if hook != nil {
		privB64, i1, armed = hook()
	}
	var hs map[string]HandshakeSample
	var tcpRTTs map[string]time.Duration
	var wg sync.WaitGroup
	if armed {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hs = ProbeHandshakeBatch(ctx, privB64, handshakeCands,
				ProbeHandshakeConfig{Timeout: DefaultHandshakeProbeTimeout, I1: i1})
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		tcpRTTs = ProbeTCP443RTT(ctx, tcpCands, dial)
	}()
	wg.Wait()

	nodes = MergeProbeRanking(nodes, hs, tcpRTTs, ports)

	sc.mu.Lock()
	if sc.cur == nil || !sc.cur.FetchedAt.Equal(generation) || sc.cur.Source != source {
		return
	}
	// Publish a replacement slice instead of mutating cur.Nodes in place.
	// A concurrent caller that returned the previous snapshot while this
	// probe batch was running keeps an immutable slice and cannot race with
	// RTT application.
	sc.cur.Nodes = nodes
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
	sc.rttRankedAt = time.Time{}
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
