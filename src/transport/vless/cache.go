package vless

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// NodeCache is the last-good online asset (design §3.2): the last successfully
// fetched node set, persisted next to the identity slot with 0600 so a restart
// or an outage still has nodes to dial. It never contains secrets beyond what
// a public node link already carries, but it is still operator data.
type NodeCache struct {
	Nodes     []Node    `json:"nodes"`
	Sources   []string  `json:"sources,omitempty"` // redacted
	UpdatedAt time.Time `json:"updated_at"`
}

// LoadNodeCache reads the cache. A missing file returns (nil, nil) — the
// honest "no last-good yet" state, never an error.
func LoadNodeCache(path string) (*NodeCache, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vless: read node cache: %w", err)
	}
	var c NodeCache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("vless: parse node cache: %w", err)
	}
	return &c, nil
}

// Save writes the cache atomically (tmp + rename) with 0600 inside a 0700 dir.
func (c *NodeCache) Save(path string) error {
	if path == "" {
		return fmt.Errorf("vless: empty node cache path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("vless: cache dir: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("vless: encode node cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("vless: write node cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vless: replace node cache: %w", err)
	}
	return nil
}

// MergeNodes deduplicates by Identity, validates every node and keeps the
// first occurrence (base before extra). A node that fails validation is
// dropped, never rendered.
func MergeNodes(sets ...[]Node) []Node {
	seen := make(map[string]bool)
	out := make([]Node, 0)
	for _, set := range sets {
		for i := range set {
			n := set[i]
			if err := n.Validate(); err != nil {
				continue
			}
			id := n.Identity()
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, n)
		}
	}
	return out
}
