package vless

import (
	"net/url"
	"strings"
)

// bundledSources is the curated list of public aggregator raw endpoints used
// when system.vless.bundled_sources is on (default). It is OUR short list of
// public upstreams (design §3.2 rail: not a copy of any collector's source
// file). Every entry was HTTP-verified reachable at implementation time; a
// dead upstream is skipped by the fetcher, never fatal.
var bundledSources = []string{
	"https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
	"https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
	"https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
	"https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
	"https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
	"https://raw.githubusercontent.com/ts-sf/fly/main/v2",
	"https://raw.githubusercontent.com/freefq/free/master/v2",
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
