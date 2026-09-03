package nfq

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/log"
)

// GGC-shard discovery (Часть 3 П.4): close the L3 hole "TCP to a FRESH CDN IP
// before any QUIC/DNS hint of that exact address" (seek race, PROJECT_DIRECTIVES
// §3). redirector.googlevideo.com/report_mapping returns the googlevideo edge
// hostnames that serve THIS WAN exit right now (zapret-gui
// core/testers/youtube_cdn.py:38-48); resolving them yields the shard IPs the
// phone will hit minutes later. Feeding those into the always-present scoped
// host-hint store lets googlevideoSetForHold start the CH hold on the first
// doomed packet — no config keys, no prefixes, no Google /16.
//
// Evidence is client-scoped (managed devices only), confidence 65: above
// Classify (55) so it classifies and starts holds, below Destructive (85) so
// it alone never authorizes destructive decisions.

const (
	ggcdiscInterval      = 4 * time.Minute
	ggcdiscInitialDelay  = 30 * time.Second
	ggcdiscFetchTimeout  = 5 * time.Second
	ggcdiscResolveTimeo  = 5 * time.Second
	ggcdiscMaxHosts      = 16
	ggcdiscMaxIPs        = 64
	ggcdiscMaxClients    = 32
	// ggcdiscTTL matches the host-hint store cap for EvidenceDNSAnswer
	// (classifier/hints.go hostHintSourceTTL): requesting more would be
	// silently clamped. The 4-minute interval keeps coverage seamless.
	ggcdiscTTL           = 5 * time.Minute
	ggcdiscConfidence    = 89
	ggcdiscDeadSkipTTL   = 20 * time.Minute // trust a fresh dead-verdict this long
	ggcdiscBodyLimit     = 1 << 16
	ggcdiscReportMapping = "https://redirector.googlevideo.com/report_mapping?di=no"
	ggcdiscReportHTTP    = "http://redirector.googlevideo.com/report_mapping?di=no"
)

// Shard hostname shape: rr5---sn-c0q7lnz7.googlevideo.com,
// r2---sn-jvhnu5g-c35k.googlevideo.com (zapret-gui youtube_cdn.py:45-48).
var ggcdiscShardRe = regexp.MustCompile(`(?i)\b([a-z0-9]+---sn-[a-z0-9-]+\.googlevideo\.com)\b`)

// Region-dependent short-code format (YT-DPI.sh resolve_cdn_from_redirector):
//   188.18.149.69 => arn09s18 : router: "pr04.arn16" ...
// The token after "=>" is either a bare POP code (-> host r1.<code>.
// googlevideo.com, anything but literal "r1") or an already-full
// *.googlevideo.com hostname.
var ggcdiscRedirecteeRe = regexp.MustCompile(`=>[ \t]*([A-Za-z0-9.-]+)`)

type ggcShard struct {
	host string
	addr netip.Addr
}

type ggcClient struct {
	key classifier.ClientKey
	mac string
}

type ggcDiscFetcher func(ctx context.Context) ([]byte, error)
type ggcDiscResolver func(ctx context.Context, host string) ([]netip.Addr, error)

type ggcShardDiscovery struct {
	w       *Worker
	fetch   ggcDiscFetcher
	resolve ggcDiscResolver
	now     func() time.Time
}

func StartGGCShardDiscovery(ctx context.Context, cfgPtr *atomic.Pointer[config.Config], pool *Pool) {
	if !ggcDiscEnabled || ctx == nil || cfgPtr == nil || pool == nil || len(pool.Workers) == 0 {
		return
	}
	d := &ggcShardDiscovery{
		w:       pool.Workers[0],
		fetch:   ggcdiscHTTPFetch,
		resolve: ggcdiscDNSResolve,
		now:     time.Now,
	}
	go d.loop(ctx, cfgPtr)
	log.Infof("[ggcdisc] GGC shard discovery started (interval=%v ttl=%v confidence=%d)",
		ggcdiscInterval, ggcdiscTTL, ggcdiscConfidence)
}

func (d *ggcShardDiscovery) loop(ctx context.Context, cfgPtr *atomic.Pointer[config.Config]) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(ggcdiscInitialDelay):
	}
	ticker := time.NewTicker(ggcdiscInterval)
	defer ticker.Stop()
	for {
		d.cycle(ctx, cfgPtr.Load())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *ggcShardDiscovery) cycle(ctx context.Context, cfg *config.Config) {
	body, err := d.fetch(ctx)
	if err != nil {
		log.Warnf("[ggcdisc] fetch failed: %v", err)
		return
	}
	hosts := ggcdiscExtractShardHosts(body, ggcdiscMaxHosts)
	if len(hosts) == 0 {
		log.Tracef("[ggcdisc] mapping contained no shard hostnames")
		return
	}
	shards := d.resolveShards(ctx, hosts)
	if len(shards) == 0 {
		log.Warnf("[ggcdisc] hosts=%d resolved to no usable public IPv4", len(hosts))
		return
	}
	clients := d.managedClients(cfg)
	if len(clients) == 0 {
		log.Tracef("[ggcdisc] no known clients to feed")
		return
	}
	fed := d.feed(cfg, shards, clients)
	log.Warnf("[ggcdisc] hosts=%d ips=%d clients=%d hints=%d ttl=%v",
		len(hosts), len(shards), len(clients), fed, ggcdiscTTL)
}

// ggcdiscExtractShardHosts pulls candidate googlevideo shard hostnames from a
// report_mapping body: full ---sn- shard names anywhere in the body, plus the
// region-dependent "=> CODE" redirectee form (bare POP code -> r1.<code>.
// googlevideo.com, or an already-full hostname). Unique, lowercase,
// first-seen order up to max.
func ggcdiscExtractShardHosts(body []byte, max int) []string {
	seen := make(map[string]struct{})
	hosts := make([]string, 0, 8)
	add := func(host string) bool {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" {
			return false
		}
		if _, dup := seen[host]; dup {
			return false
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
		return len(hosts) >= max
	}
	for _, m := range ggcdiscShardRe.FindAllStringSubmatch(string(body), -1) {
		if add(m[1]) {
			return hosts
		}
	}
	for _, m := range ggcdiscRedirecteeRe.FindAllStringSubmatch(string(body), -1) {
		token := m[1]
		switch {
		case strings.HasSuffix(token, ".googlevideo.com"):
			if add(token) {
				return hosts
			}
		case token != "r1" && !strings.ContainsAny(token, "."):
			if add("r1." + token + ".googlevideo.com") {
				return hosts
			}
		}
	}
	return hosts
}

// ggcdiscPublicIPv4 accepts only routable global IPv4 addresses. Google never
// answers with private/CGNAT space for these hostnames; the filter is defense
// against a poisoned/misbehaving resolver, not against Google.
func ggcdiscPublicIPv4(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() {
		return false
	}
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() &&
		!a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsUnspecified()
}

func (d *ggcShardDiscovery) resolveShards(ctx context.Context, hosts []string) []ggcShard {
	seen := make(map[netip.Addr]struct{})
	out := make([]ggcShard, 0, len(hosts))
	for _, host := range hosts {
		addrs, err := d.resolve(ctx, host)
		if err != nil {
			log.Tracef("[ggcdisc] resolve %s failed: %v", host, err)
			continue
		}
		for _, addr := range addrs {
			if !ggcdiscPublicIPv4(addr) {
				continue
			}
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, ggcShard{host: host, addr: addr})
			if len(out) >= ggcdiscMaxIPs {
				return out
			}
		}
	}
	return out
}

// managedClients scopes the feed to known LAN clients. When the config
// selects device MACs, only those are fed; otherwise every DHCP-known client
// (bounded) benefits — the mapping is POP-level truth shared by the whole WAN.
func (d *ggcShardDiscovery) managedClients(cfg *config.Config) []ggcClient {
	if d.w == nil {
		return nil
	}
	raw := d.w.ipToMac.Load()
	m, _ := raw.(map[string]string)
	if len(m) == 0 {
		return nil
	}
	var allowed map[string]struct{}
	useFilter := false
	if cfg != nil && cfg.Queue.Devices.Enabled {
		allowed = make(map[string]struct{})
		for _, mac := range cfg.Queue.Devices.SelectedMACs() {
			n := strings.ToLower(strings.TrimSpace(mac))
			if n != "" {
				allowed[n] = struct{}{}
				useFilter = true
			}
		}
	}
	clients := make([]ggcClient, 0, len(m))
	for ip, mac := range m {
		nm := strings.ToLower(strings.TrimSpace(mac))
		if useFilter {
			if _, ok := allowed[nm]; !ok {
				continue
			}
		}
		key, ok := dnsClientKey(net.ParseIP(ip), mac)
		if !ok {
			continue
		}
		clients = append(clients, ggcClient{key: key, mac: nm})
		if len(clients) >= ggcdiscMaxClients {
			break
		}
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].mac < clients[j].mac })
	return clients
}

// feed writes one scoped observation per (client, shard IP, proto). The set
// comes from the live suffix matcher so the youtube-video set id stays
// authoritative; unmatched hosts are skipped silently (they may belong to a
// disabled set).
func (d *ggcShardDiscovery) feed(cfg *config.Config, shards []ggcShard, clients []ggcClient) int {
	if d.w == nil || d.w.dnsHints == nil {
		return 0
	}
	matcher := d.w.getMatcher()
	if matcher == nil {
		log.Tracef("[ggcdisc] matcher unavailable; skipping feed")
		return 0
	}
	now := d.now()
	gen := dnsHintConfigGeneration(cfg)
	fed := 0
	for _, c := range clients {
		for _, s := range shards {
			// A shard whose latest VN probe says dead is not fed: hints must
			// not point clients at corpses during rotation storms. Fresh
			// dead-verdicts only; unknown IPs still feed.
			if v, ok := vnbLastVerdict(s.addr); ok && !v.alive && d.now().Sub(v.at) < ggcdiscDeadSkipTTL {
				log.Tracef("[ggcdisc] skip dead shard %s (%s)", s.host, s.addr)
				continue
			}
			matched, set := matcher.MatchSNIWithSource(s.host, c.mac)
			if !matched || set == nil || !set.Enabled {
				continue
			}
			setID := strings.TrimSpace(set.Id)
			if setID == "" {
				setID = strings.TrimSpace(set.Name)
			}
			if setID == "" {
				continue
			}
			for _, proto := range []uint8{6, 17} {
				if proto == 6 && !set.MatchesTCPDPort(443) {
					continue
				}
				if proto == 17 && !set.MatchesUDPDPort(443) {
					continue
				}
				// DNS-answer semantics: the mapping is a Google-authoritative
				// hostname→IP answer for this POP, consumed by the store under
				// the same policy as real client DNS (confidence 89, 5-minute
				// cap). The store clamps ExpiresAt itself; we request ggcdiscTTL.
				ev := classifier.Evidence{
					Source:          classifier.EvidenceDNSAnswer,
					Client:          c.key,
					DestinationIP:   s.addr,
					DestinationPort: 443,
					L4Proto:         proto,
					SourceDevice:    c.mac,
					Domain:          s.host,
					SetID:           setID,
					Confidence:      ggcdiscConfidence,
					DomainEvidence:  true,
					CreatedAt:       now,
					ExpiresAt:       now.Add(ggcdiscTTL),
					ConfigGen:       gen,
					Reason:          "source-scoped GGC report_mapping discovery",
				}
				if err := d.w.dnsHints.Observe(ev); err != nil {
					continue
				}
				fed++
				diagnostics.Default().UpdateEvidence(c.key, s.addr, 443, proto, []classifier.Evidence{ev})
			}
		}
	}
	return fed
}

func ggcdiscHTTPFetch(ctx context.Context) ([]byte, error) {
	// HTTP first: field-proven working from the router WAN on 23.08 (the
	// HTTPS variant answers with an empty body there). An empty body counts
	// as a failed attempt so both endpoints get their chance.
	urls := []string{ggcdiscReportHTTP, ggcdiscReportMapping}
	client := &http.Client{Timeout: ggcdiscFetchTimeout}
	var lastErr error
	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "b4-ggcdisc/1")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, ggcdiscBodyLimit))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: status %d", url, resp.StatusCode)
			continue
		}
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			lastErr = fmt.Errorf("%s: empty body", url)
			continue
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoint attempted")
	}
	return nil, lastErr
}

func ggcdiscDNSResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	rctx, cancel := context.WithTimeout(ctx, ggcdiscResolveTimeo)
	defer cancel()
	var resolver net.Resolver
	addrs, err := resolver.LookupHost(rctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if addr, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
			out = append(out, addr)
		}
	}
	return out, nil
}
