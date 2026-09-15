// Package torscan is the vanilla relay scanner (design §4.3, patch-plan
// §10 — the ValdikSS tor-relay-scanner canon on a Go skeleton): onionoo
// relay discovery with a fallback chain, deep probes proving a LIVE Tor
// node (not just an open port) that the DPI lets through, and
// observed-bandwidth ranking so the vanilla guards carry real speed.
// Zero dependencies on the tor runtime — a standalone package.
package torscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Relay is one onionoo relay record (the requested field set).
type Relay struct {
	Fingerprint       string   `json:"fingerprint"`
	OrAddresses       []string `json:"or_addresses"`
	Country           string   `json:"country,omitempty"`
	ObservedBandwidth int64    `json:"observed_bandwidth,omitempty"`
}

type onionooResponse struct {
	Relays []Relay `json:"relays"`
}

// DefaultOnionooURL is the primary relay-list source.
const DefaultOnionooURL = "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses,country,observed_bandwidth"

// Fallback source templates ({url} expands to the escaped onionoo query).
var DefaultFallbacks = []string{
	"https://icors.vercel.app/?url={url}",
	"https://raw.githubusercontent.com/ValdikSS/tor-onionoo-mirror/main/details.json",
	"https://bitbucket.org/ValdikSS/tor-onionoo-mirror/raw/master/details.json",
}

// Fetcher downloads one source URL (production: an HTTP client riding the
// egress dialer; tests: httptest).
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Onionoo fetches the relay list through the fallback chain (direct →
// CORS proxy → GitHub mirror → Bitbucket → cache file). The FIRST source
// returning a non-empty parsed list wins.
func Onionoo(ctx context.Context, fetch Fetcher, customURLs []string, cachePath string) ([]Relay, string, error) {
	var urls []string
	for _, u := range customURLs {
		if u != "" {
			urls = append(urls, u)
		}
	}
	urls = append(urls, DefaultOnionooURL)
	for _, fb := range DefaultFallbacks {
		if strings.Contains(fb, "{url}") {
			urls = append(urls, strings.ReplaceAll(fb, "{url}", escapedQuery()))
		} else {
			urls = append(urls, fb)
		}
	}

	for _, u := range urls {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		body, err := fetch(ctx, u)
		if err != nil {
			continue
		}
		relays, perr := parseOnionoo(body)
		if perr != nil || len(relays) == 0 {
			continue
		}
		// cache the winning payload for offline fallback
		if cachePath != "" {
			_ = writeCache(cachePath, body)
		}
		return relays, u, nil
	}

	// offline fallback: the last good cache
	if cachePath != "" {
		if body, err := readCache(cachePath); err == nil {
			if relays, perr := parseOnionoo(body); perr == nil && len(relays) > 0 {
				return relays, "cache", nil
			}
		}
	}
	return nil, "", fmt.Errorf("torscan: all onionoo sources failed")
}

func escapedQuery() string {
	return strings.ReplaceAll("type=relay&running=true&fields=fingerprint,or_addresses,country,observed_bandwidth", "&", "%26")
}

func parseOnionoo(body []byte) ([]Relay, error) {
	var resp onionooResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp.Relays, nil
}

func writeCache(path string, body []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func readCache(path string) ([]byte, error) { return os.ReadFile(path) }

// AddrCandidates expands one relay into dial candidates: every
// or_address (the juev bug fixed — [0] only misses IPv6-only relays),
// filtered by the wanted OR ports.
func AddrCandidates(r Relay, ports []int) []string {
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	var out []string
	for _, addr := range r.OrAddresses {
		host, portStr, err := splitLastColon(addr)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		if len(want) > 0 && !want[port] {
			continue
		}
		out = append(out, joinHostPort(host, port))
	}
	return out
}

// splitLastColon splits "host:port" tolerating bare IPv6 (last colon).
func splitLastColon(s string) (string, string, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", "", fmt.Errorf("no port in %q", s)
	}
	return strings.Trim(s[:i], "[]"), s[i+1:], nil
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// BandwidthRank sorts candidates by observed bandwidth DESC (the
// top-quantile selection: fast vanilla guards, not random ones).
func BandwidthRank(relays []Relay) []Relay {
	out := append([]Relay(nil), relays...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ObservedBandwidth > out[j-1].ObservedBandwidth; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Shuffle randomizes candidate order (the ValdikSS canon: probe order
// must not leak a preference).
func Shuffle(relays []Relay, seed uint64) []Relay {
	out := append([]Relay(nil), relays...)
	s := seed | 1
	for i := len(out) - 1; i > 0; i-- {
		s = s*6364136223846793005 + 1442695040888963407
		j := int((s >> 33) % uint64(i+1))
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// FetchTimeout bounds one source download.
const FetchTimeout = 20 * time.Second

// HTTPFetcher builds a Fetcher over an http.Client.
func HTTPFetcher(client *http.Client) Fetcher {
	return func(ctx context.Context, url string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, FetchTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			return nil, fmt.Errorf("source status %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	}
}
