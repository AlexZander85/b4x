package vless

import (
	"net/url"
	"strings"
)

// bundledSources is the curated list of public aggregator raw endpoints used
// when system.vless.bundled_sources is on (default). It is OUR short list of
// public upstreams (design §3.2 rail: not a copy of any collector's source
// file) — public URLs only, no code borrowed.
//
// Curated by measured VLESS yield (2026-09-21), which is why the three
// highest-volume sources lead:
//
//	iboxz           317 vless   (vless-only, curated)
//	0xRadikal      6284 vless   (widest pool)
//	barry-far      6068 vless   (freshest)
//	peasoft          40 vless
//	Pawdroid          3 vless
//	ALIILAPRO       500 vless
//
// Dropped as dead or duplicate: mahdibland (0 vless — the aggregator no longer
// ships VLESS), ts-sf/fly (0), freefq/free (0), and Epodonios (its
// Splitted-By-Protocol pool is a byte-identical mirror of barry-far). A dead or
// broken upstream is skipped by the fetcher, never fatal.
var bundledSources = []string{
	"https://iboxz.github.io/free-v2ray-collector/main/vless.txt",
	"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
	"https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
	"https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
	"https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
}

// BundledSources returns a copy of the curated aggregator list.
func BundledSources() []string {
	return append([]string(nil), bundledSources...)
}

// ResolveSources composes the fetch list: the bundled aggregators (when on)
// followed by the operator's own subscriptions, deduplicated and trimmed.
func ResolveSources(bundled bool, own []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(bundledSources)+len(own))
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	if bundled {
		for _, u := range bundledSources {
			add(u)
		}
	}
	for _, u := range own {
		add(u)
	}
	return out
}

// RedactURL hides the path/query of a subscription URL (which may embed an
// access token) for logs and status output.
func RedactURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "<invalid>"
	}
	return u.Scheme + "://" + u.Host + "/<redacted>"
}
