package vless

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// MaxNodes caps the merged node set (defensive rail: a hostile/runaway upstream
// must not grow the working set without bound).
const MaxNodes = 5000

// RefreshReport is the outcome of one refresh pass.
type RefreshReport struct {
	Nodes     []Node                 `json:"-"`
	Stats     Stats                  `json:"stats"`
	Sources   []string               `json:"sources"` // redacted, successfully fetched
	Failed    map[string]string      `json:"failed,omitempty"`
	BySource  map[string]SourceState `json:"by_source,omitempty"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// sourceKey is a stable, token-free cache key for a subscription URL (the URL
// may embed an access token, which must not land in the cache).
func sourceKey(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:8])
}

// Refresh fetches every source unconditionally and merges the results.
func Refresh(ctx context.Context, client *http.Client, sources []string, maxNodes int) RefreshReport {
	return RefreshWithState(ctx, client, sources, nil, maxNodes)
}

// RefreshWithState is Refresh with conditional GET: each source carries its
// stored ETag/Last-Modified; a 304 (or a transient failure) reuses that
// source's last-good nodes instead of dropping them. A failed source is
// recorded, not fatal — public aggregators rot all the time.
func RefreshWithState(ctx context.Context, client *http.Client, sources []string, prev map[string]SourceState, maxNodes int) RefreshReport {
	if maxNodes <= 0 {
		maxNodes = MaxNodes
	}
	rep := RefreshReport{UpdatedAt: time.Now().UTC(), BySource: map[string]SourceState{}}
	seen := make(map[string]bool)
	addNodes := func(nodes []Node) {
		for i := range nodes {
			if len(rep.Nodes) >= maxNodes {
				return
			}
			id := nodes[i].Identity()
			if seen[id] {
				rep.Stats.Duplicate++
				continue
			}
			seen[id] = true
			rep.Nodes = append(rep.Nodes, nodes[i])
		}
	}
	for _, src := range sources {
		if ctx.Err() != nil {
			break
		}
		key := sourceKey(src)
		var old SourceState
		if prev != nil {
			old = prev[key]
		}
		body, etag, lastMod, notModified, err := FetchConditional(ctx, client, src, old.ETag, old.LastMod)
		if err != nil {
			if rep.Failed == nil {
				rep.Failed = map[string]string{}
			}
			rep.Failed[RedactURL(src)] = err.Error()
			if len(old.Nodes) > 0 { // keep last-good on failure
				rep.BySource[key] = old
				addNodes(old.Nodes)
				rep.Sources = append(rep.Sources, RedactURL(src))
			}
			continue
		}
		if notModified {
			rep.BySource[key] = old
			addNodes(old.Nodes)
			rep.Sources = append(rep.Sources, RedactURL(src))
			continue
		}
		nodes, st := ParseSubscription(body)
		rep.Stats.Total += st.Total
		rep.Stats.VLESS += st.VLESS
		rep.Stats.Other += st.Other
		rep.Stats.Bad += st.Bad
		rep.Stats.Duplicate += st.Duplicate
		rep.Stats.Truncated += st.Truncated
		rep.BySource[key] = SourceState{ETag: etag, LastMod: lastMod, Nodes: nodes}
		rep.Sources = append(rep.Sources, RedactURL(src))
		addNodes(nodes)
	}
	sort.Strings(rep.Sources)
	return rep
}

// SummarizeFailed renders the failed-source map for a log/status line (already
// redacted keys).
func SummarizeFailed(failed map[string]string) string {
	if len(failed) == 0 {
		return ""
	}
	parts := make([]string, 0, len(failed))
	for k, v := range failed {
		parts = append(parts, k+": "+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}
