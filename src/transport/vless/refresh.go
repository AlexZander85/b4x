package vless

import (
	"context"
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
	Nodes     []Node            `json:"-"`
	Stats     Stats             `json:"stats"`
	Sources   []string          `json:"sources"` // redacted, successfully fetched
	Failed    map[string]string `json:"failed,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Refresh fetches every source, parses it defensively and merges the results
// with dedup by Identity and a hard node cap. A failed source is recorded, not
// fatal — public aggregators rot all the time.
func Refresh(ctx context.Context, client *http.Client, sources []string, maxNodes int) RefreshReport {
	if maxNodes <= 0 {
		maxNodes = MaxNodes
	}
	rep := RefreshReport{UpdatedAt: time.Now().UTC()}
	seen := make(map[string]bool)
	for _, src := range sources {
		if ctx.Err() != nil {
			break
		}
		body, err := Fetch(ctx, client, src)
		if err != nil {
			if rep.Failed == nil {
				rep.Failed = map[string]string{}
			}
			rep.Failed[RedactURL(src)] = err.Error()
			continue
		}
		nodes, st := ParseSubscription(body)
		rep.Stats.Total += st.Total
		rep.Stats.VLESS += st.VLESS
		rep.Stats.Other += st.Other
		rep.Stats.Bad += st.Bad
		rep.Stats.Duplicate += st.Duplicate
		rep.Stats.Truncated += st.Truncated
		rep.Sources = append(rep.Sources, RedactURL(src))
		for i := range nodes {
			if len(rep.Nodes) >= maxNodes {
				break
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
