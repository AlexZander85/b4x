package tor

// Bridge collection conveyor (design §4.1, patch-plan §5 — the Nova
// BridgeCollector adapted): sources in order —
//
//	1. builtin snowflake sets (CDN77 / AMP, chosen by measurement, G202:
//	   a silent probe still yields a usable verdict — forced "alive");
//	2. OnionHop mirror race (the first NON-EMPTY response wins, 25 s cap;
//	   an empty 200 never wins);
//	3. Moat circumvention settings (country + transports), through the
//	   egress dialer — never through tor itself;
//	4. owner lines from config (validated by the same parser).
//
// Freshness 24 h, re-collection pause 300 s (both injected-clock aware);
// a failed run KEEPS the previous list (Save happens only on a conveyor
// outcome the caller persists); dedup transport|fingerprint|endpoint;
// trim-keeping-every-kind to 40; success requires ≥1 live NETWORK bridge
// (builtins never count — TOR-1). Everything travels through injected
// HTTP/dial seams — unit tests ride httptest, live requests stay outside.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Conveyor constants (design §4.1/§4.2).
const (
	BridgesFreshness   = 24 * time.Hour
	RecollectPause     = 5 * time.Minute
	MirrorRaceCap      = 25 * time.Second
	MoatRequestTimeout = 15 * time.Second
)

// DefaultMoatURL is the Moat circumvention endpoint (design §4.1 source 3).
const DefaultMoatURL = "https://bridges.torproject.org/moat/circumvention/settings"

// OnionHopCollectorFiles are the per-transport tested-line files.
var OnionHopCollectorFiles = []string{"obfs4_tested.txt", "webtunnel_tested.txt", "vanilla_tested.txt"}

// DefaultMirrorBases are the collector mirrors ({file} expands to the file
// name; a template without {file} gets "<base>/<file>" appended). The
// OnionHop project moved to center2055/OnionHop-Bridges-Collector (path
// bridge/, not bridges/); Delta-Kronecker is the independent fallback pool
// (obfs4 only). Verified live from the router 2026-09-21: all four OnionHop
// mirrors and the Delta jsDelivr mirror answer 200 with real lines.
var DefaultMirrorBases = []string{
	"https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/{file}",
	"https://center2055.github.io/OnionHop-Bridges-Collector/bridge/{file}",
	"https://cdn.jsdelivr.net/gh/center2055/OnionHop-Bridges-Collector@main/bridge/{file}",
	"https://cdn.statically.io/gh/center2055/OnionHop-Bridges-Collector@main/bridge/{file}",
	"https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/{file}",
	"https://cdn.jsdelivr.net/gh/Delta-Kronecker/Tor-Bridges-Collector@main/bridge/{file}",
}

// moatSettings mirrors one entry of the Moat circumvention response.
type moatSettings struct {
	Bridges struct {
		Type          string   `json:"type"`
		Source        string   `json:"source"`
		BridgeStrings []string `json:"bridge_strings"`
	} `json:"bridges"`
}

type moatResponse struct {
	Settings []moatSettings `json:"settings"`
}

// moatRequest is the POST body.
type moatRequest struct {
	Country    string   `json:"country"`
	Transports []string `json:"transports"`
}

// CollectorSource names a contributing source for the report field.
const (
	SourceBuiltin = "builtin"
	SourceMirror  = "onionhop"
	SourceMoat    = "moat"
	SourceOwner   = "owner"
)

// Collector is the bridge collection conveyor.
type Collector struct {
	store      *BridgesStore
	client     *http.Client
	dial       ProbeDial
	now        func() time.Time
	moatURL    string
	mirrorURLs []string

	mu        sync.Mutex
	lastRun   time.Time
	lastOK    time.Time
	snowflake string // cached per-run set verdict: "cdn77" | "amp"
}

// CollectorOptions wires the seams; nils get safe defaults (an unstarted
// conveyor that answers should-collect=false and fails closed).
type CollectorOptions struct {
	Store      *BridgesStore
	Client     *http.Client // mirrors + Moat + rendezvous probes
	Dial       ProbeDial    // TCP/WS probes through the egress dialer
	Now        func() time.Time
	MoatURL    string   // tests override; "" => DefaultMoatURL
	MirrorURLs []string // full templates; prepended after cfg.CollectURLs
	// NoDefaultMirrors drops the built-in OnionHop mirror list — tests
	// only (consent rule: injected httptest mirrors must be the WHOLE
	// race; production always races the defaults too).
	NoDefaultMirrors bool
}

// NewCollector builds the conveyor.
func NewCollector(opts CollectorOptions) *Collector {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	moat := opts.MoatURL
	if moat == "" {
		moat = DefaultMoatURL
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: MirrorRaceCap}
	}
	var mirrors []string
	mirrors = append(mirrors, opts.MirrorURLs...)
	if !opts.NoDefaultMirrors {
		mirrors = append(mirrors, DefaultMirrorBases...)
	}
	return &Collector{
		store:      opts.Store,
		client:     client,
		dial:       opts.Dial,
		now:        now,
		moatURL:    moat,
		mirrorURLs: mirrors,
	}
}

// ShouldCollect reports the freshness/pause decision for the current
// stored state (freshness 24 h from the last SUCCESSFUL run; the
// re-collection pause bounds every attempt).
func (c *Collector) ShouldCollect(extraURLs []string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Sub(c.lastRun) < RecollectPause {
		return false
	}
	if !c.lastOK.IsZero() && now.Sub(c.lastOK) < BridgesFreshness {
		return false
	}
	if c.store != nil {
		f, err := c.store.Load()
		if err == nil && len(f.Bridges) > 0 && !time.UnixMilli(f.UpdatedAt).Add(BridgesFreshness).Before(now) {
			return false // still fresh on disk
		}
	}
	_ = extraURLs
	return true
}

// markRun records the attempt (and optionally the success).
func (c *Collector) markRun(ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRun = c.now()
	if ok {
		c.lastOK = c.now()
	}
}

// Collect runs one conveyor pass and PERSISTS the result on success.
// A failed pass never touches the store (the old list survives) and
// returns the error with full source attribution.
func (c *Collector) Collect(ctx context.Context, builtinSnowflake bool, ownerLines []string, country string, collectURLs []string) (BridgesFile, error) {
	c.mu.Lock()
	c.lastRun = c.now()
	c.mu.Unlock()

	now := c.now()
	var sources []string
	var candidates []Bridge

	// --- source 1: builtin snowflake (the set choice, G202) ---
	if builtinSnowflake {
		set := c.chooseSnowflakeSet(ctx)
		lines := BuiltinSnowflakeCDN77
		if set == "amp" {
			lines = BuiltinSnowflakeAMP
		}
		for _, raw := range lines {
			if b, err := ParseBridgeLine(raw); err == nil {
				candidates = append(candidates, b)
			}
		}
		if len(candidates) > 0 {
			sources = append(sources, SourceBuiltin)
		}
	}

	// --- source 2: mirror race (first non-empty wins) ---
	mirrorBridges, mirrorSrc := c.raceMirrors(ctx, collectURLs)
	if len(mirrorBridges) > 0 {
		candidates = append(candidates, mirrorBridges...)
		sources = append(sources, mirrorSrc)
	}

	// --- source 3: Moat (country-tuned fronts) ---
	moatBridges := c.fetchMoat(ctx, country)
	if len(moatBridges) > 0 {
		candidates = append(candidates, moatBridges...)
		sources = append(sources, SourceMoat)
	}

	// --- source 4: owner lines ---
	owner := 0
	for _, raw := range ownerLines {
		if b, err := ParseBridgeLine(raw); err == nil {
			candidates = append(candidates, b)
			owner++
		}
	}
	if owner > 0 {
		sources = append(sources, SourceOwner)
	}

	// --- dedup + trim-keeping-every-kind ---
	candidates = Dedup(candidates)
	candidates = TrimKeepingEveryKind(candidates, MaxBridgesPerKindCap)

	// --- probes (pool 8, budgets per transport, overall 60 s) ---
	alive, networkAlive := c.probeAll(ctx, candidates)

	// success = >=1 live NETWORK bridge (builtins never count, TOR-1)
	if networkAlive == 0 {
		err := fmt.Errorf("no live network bridge (builtin=%d candidates=%d alive=%d)",
			countBuiltin(candidates), len(candidates), len(alive))
		if c.store != nil {
			// failed run: report the error WITHOUT erasing the old list —
			// only annotate last_error via a non-destructive save of the
			// PREVIOUS bridges when the store has none at all.
			if prev, lerr := c.store.Load(); lerr == nil && len(prev.Bridges) > 0 {
				prev.LastError = err.Error()
				_ = c.store.Save(prev) // keep bridges, record the failure
			}
		}
		c.markRun(false)
		return BridgesFile{}, err
	}

	out := BridgesFile{
		Schema:    BridgesFileSchema,
		UpdatedAt: now.UnixMilli(),
		Source:    strings.Join(sources, "+"),
		Bridges:   storedFrom(alive),
	}
	if c.store != nil {
		if err := c.store.Save(out); err != nil {
			c.markRun(false)
			return out, err
		}
	}
	c.markRun(true)
	return out, nil
}

// chooseSnowflakeSet implements G202: probe CDN77's rendezvous; on silence
// probe AMP; on silence of both, return CDN77 with the forced verdict
// (the probe rides plain HTTP — the real rendezvous inside the transport
// carries the uTLS/fronting and may still succeed). The verdict caches per
// conveyor run.
func (c *Collector) chooseSnowflakeSet(ctx context.Context) string {
	c.mu.Lock()
	if c.snowflake != "" {
		defer c.mu.Unlock()
		return c.snowflake
	}
	c.mu.Unlock()

	set := "cdn77"
	for _, candidate := range []struct {
		name string
		url  string
	}{
		{"cdn77", snowflakeRendezvousURL(BuiltinSnowflakeCDN77)},
		{"amp", snowflakeRendezvousURL(BuiltinSnowflakeAMP)},
	} {
		if candidate.url != "" && ProbeRendezvous(ctx, c.client, candidate.url) {
			set = candidate.name
			break
		}
		if candidate.name == "amp" {
			set = "cdn77" // both silent: forced verdict (G202)
		}
	}
	c.mu.Lock()
	c.snowflake = set
	c.mu.Unlock()
	return set
}

// snowflakeRendezvousURL extracts the rendezvous place (url= or ampcache=)
// from the first line of a builtin set.
func snowflakeRendezvousURL(lines []string) string {
	for _, raw := range lines {
		b, err := ParseBridgeLine(raw)
		if err != nil {
			continue
		}
		if u := b.Args["url"]; u != "" {
			return u
		}
		if u := b.Args["ampcache"]; u != "" {
			return u
		}
	}
	return ""
}

// raceMirrors races the configured mirror templates; the first NON-EMPTY
// parsed line set wins (an empty 200 never wins). Returns the parsed
// bridges and the winning source tag.
func (c *Collector) raceMirrors(ctx context.Context, collectURLs []string) ([]Bridge, string) {
	rctx, cancel := context.WithTimeout(ctx, MirrorRaceCap)
	defer cancel()

	var urls []string
	urls = append(urls, collectURLs...)
	urls = append(urls, c.mirrorURLs...)

	type result struct {
		bridges []Bridge
		tag     string
	}
	ch := make(chan result, len(urls))
	var wg sync.WaitGroup
	for _, base := range urls {
		wg.Add(1)
		go func(base string) {
			defer wg.Done()
			var got []Bridge
			for _, file := range OnionHopCollectorFiles {
				u := expandMirrorURL(base, file)
				lines, err := c.fetchLines(rctx, u)
				if err != nil {
					continue
				}
				for _, raw := range lines {
					if b, perr := ParseBridgeLine(raw); perr == nil {
						got = append(got, b)
					}
				}
			}
			if len(got) > 0 { // empty 200 never wins
				ch <- result{bridges: got, tag: SourceMirror}
			}
		}(base)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	for res := range ch {
		if len(res.bridges) > 0 {
			return res.bridges, res.tag // first non-empty wins
		}
	}
	return nil, ""
}

// expandMirrorURL expands {file} or appends the file name.
func expandMirrorURL(base, file string) string {
	if strings.Contains(base, "{file}") {
		return strings.ReplaceAll(base, "{file}", file)
	}
	return strings.TrimSuffix(base, "/") + "/" + file
}

// fetchLines downloads one plain-text line list.
func (c *Collector) fetchLines(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("mirror status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(body), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		lines = append(lines, l)
	}
	return lines, nil
}

// fetchMoat asks the circumvention API for country-tuned bridges.
func (c *Collector) fetchMoat(ctx context.Context, country string) []Bridge {
	mctx, cancel := context.WithTimeout(ctx, MoatRequestTimeout)
	defer cancel()
	body, err := json.Marshal(moatRequest{
		Country:    country,
		Transports: []string{"webtunnel", "obfs4", "snowflake"},
	})
	if err != nil {
		return nil
	}
	req, err := http.NewRequestWithContext(mctx, http.MethodPost, c.moatURL, strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil
	}
	var moat moatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&moat); err != nil {
		return nil
	}
	var out []Bridge
	for _, s := range moat.Settings {
		for _, raw := range s.Bridges.BridgeStrings {
			if b, err := ParseBridgeLine(raw); err == nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// probeAll runs the per-transport probes under the budgets (pool 8,
// overall 60 s). Bridges past their transport's budget are KEPT unprobed
// (honest: kept, not verified — the fat lists stay useful, the probe bill
// stays bounded). Returns the alive subset and how many NETWORK bridges
// (non-builtin — TOR-1) proved alive.
func (c *Collector) probeAll(ctx context.Context, candidates []Bridge) (alive []Bridge, networkAlive int) {
	pctx, cancel := context.WithTimeout(ctx, ProbeOverallTimeout)
	defer cancel()

	probed := map[string]int{}
	sem := make(chan struct{}, ProbePoolSize)
	var mu sync.Mutex
	var wg sync.WaitGroup
	builtinSet := builtinLineSet()
	keep := func(b Bridge) {
		mu.Lock()
		defer mu.Unlock()
		alive = append(alive, b)
		if !builtinSet[DedupKey(b)] {
			networkAlive++
		}
	}
	for _, b := range candidates {
		wg.Add(1)
		go func(b Bridge) {
			defer wg.Done()
			mu.Lock()
			cap := probeClassBudget(b.Transport)
			done := probed[b.Transport]
			if cap > 0 && done >= cap {
				// over budget: keep unprobed
				mu.Unlock()
				keep(b)
				return
			}
			probed[b.Transport] = done + 1
			mu.Unlock()

			sem <- struct{}{}
			defer func() { <-sem }()
			if ProbeBridge(pctx, c.dial, c.client, b) {
				keep(b)
			}
		}(b)
	}
	wg.Wait()
	return alive, networkAlive
}

func builtinLineSet() map[string]bool {
	set := map[string]bool{}
	for _, lines := range [][]string{BuiltinSnowflakeCDN77, BuiltinSnowflakeAMP} {
		for _, raw := range lines {
			if b, err := ParseBridgeLine(raw); err == nil {
				set[DedupKey(b)] = true
			}
		}
	}
	return set
}

func countBuiltin(candidates []Bridge) int {
	set := builtinLineSet()
	n := 0
	for _, b := range candidates {
		if set[DedupKey(b)] {
			n++
		}
	}
	return n
}

func storedFrom(bridges []Bridge) []StoredBridge {
	out := make([]StoredBridge, 0, len(bridges))
	for _, b := range bridges {
		out = append(out, StoredBridge{
			Transport:   b.Transport,
			Line:        b.Line,
			Endpoint:    b.AddrPort,
			Fingerprint: b.Fingerprint,
		})
	}
	return out
}

// ErrNoStore is the honest failure when the conveyor has nowhere to persist.
var ErrNoStore = errors.New("tor collector: no store wired")
