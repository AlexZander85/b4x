package proton

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// The asset is guarded by tests, not by eyes (the ProtonNodesAssetTest
// pattern): a missing field is a dead candidate, but a leaked seed or
// private key would be one shared Proton identity for every user of the
// binary (MaxConnect: 2). The tests watch completeness AND absence.

// assetNodes decodes the embedded asset for inspection.
func assetNodes(t *testing.T) []map[string]any {
	t.Helper()
	var raw struct {
		Nodes []map[string]any `json:"nodes"`
	}
	if err := json.Unmarshal(nodesAssetJSON, &raw); err != nil {
		t.Fatalf("asset json: %v", err)
	}
	return raw.Nodes
}

// TestAssetOnlyPublicFields: every node carries EXACTLY the five public
// fact fields — nothing else rides in the firmware.
func TestAssetOnlyPublicFields(t *testing.T) {
	allowed := map[string]bool{
		"server_name": true, "country": true, "city": true,
		"entry_ip": true, "peer_public_key": true,
	}
	nodes := assetNodes(t)
	for i, node := range nodes {
		for key := range node {
			if !allowed[key] {
				t.Fatalf("node %d carries extra field %q — only public server facts ride in the firmware", i, key)
			}
		}
	}
}

// TestAssetCompleteness: >= 40 nodes, >= 3 countries, every node has a
// non-blank entry IP and a plausible x25519 peer key, and the (ip, key)
// pairs are unique.
func TestAssetCompleteness(t *testing.T) {
	nodes := assetNodes(t)
	if len(nodes) < 40 {
		t.Fatalf("asset holds %d nodes, want >= 40", len(nodes))
	}
	countries := map[string]bool{}
	seen := map[string]bool{}
	for i, n := range nodes {
		ip, _ := n["entry_ip"].(string)
		key, _ := n["peer_public_key"].(string)
		country, _ := n["country"].(string)
		if ip == "" {
			t.Fatalf("node %d without entry_ip", i)
		}
		if key == "" {
			t.Fatalf("node %d without peer key", i)
		}
		if len(key) < 40 {
			t.Fatalf("node %d: peer key does not look like x25519 (%d chars)", i, len(key))
		}
		if _, err := base64.StdEncoding.DecodeString(key); err != nil {
			t.Fatalf("node %d: peer key not base64: %v", i, err)
		}
		if country == "" {
			t.Fatalf("node %d without country", i)
		}
		countries[country] = true
		if !seen[ip+"\x00"+key] {
			seen[ip+"\x00"+key] = true
		} else {
			t.Fatalf("node %d repeats (ip,key)", i)
		}
	}
	if len(countries) < 3 {
		t.Fatalf("asset spans %d countries, want >= 3", len(countries))
	}
}

// TestAssetHeadInterleaved: the first four nodes MUST come from four
// different countries — otherwise a single-country outage stalls the head of
// the queue.
func TestAssetHeadInterleaved(t *testing.T) {
	nodes := assetNodes(t)
	head := map[string]bool{}
	for i := 0; i < 4 && i < len(nodes); i++ {
		c, _ := nodes[i]["country"].(string)
		head[c] = true
	}
	if len(head) != 4 {
		t.Fatalf("first four nodes span %d countries, want 4 (interleaved head)", len(head))
	}
}

// TestAssetNoSecrets: a grep-like sweep over every field value — no PEM
// bodies, no private-key markers, no base64 blobs longer than a public key.
func TestAssetNoSecrets(t *testing.T) {
	forbidden := []string{"PRIVATE", "BEGIN", "END", "seed", "token", "password", "secret"}
	nodes := assetNodes(t)
	for i, node := range nodes {
		for key, v := range node {
			s, _ := v.(string)
			for _, f := range forbidden {
				if strings.Contains(strings.ToLower(s), strings.ToLower(f)) {
					t.Fatalf("node %d field %q contains forbidden marker %q", i, key, f)
				}
			}
			// A public x25519 key is 44 chars; anything longer base64 in a
			// value field would be a foreign blob.
			if strings.HasSuffix(key, "_key") && len(s) > 64 {
				t.Fatalf("node %d field %q suspiciously long (%d chars)", i, key, len(s))
			}
		}
	}
}

// TestAssetNodesParsesIntoModel: the embedded asset decodes into the Node
// model and keeps its interleaved order.
func TestAssetNodesParsesIntoModel(t *testing.T) {
	nodes, err := AssetNodes()
	if err != nil {
		t.Fatalf("AssetNodes: %v", err)
	}
	if len(nodes) != len(assetNodes(t)) {
		t.Fatalf("model node count %d != asset count", len(nodes))
	}
	if nodes[0].Name == "" || nodes[0].PeerPubKey == "" {
		t.Fatalf("first node incomplete: %+v", nodes[0])
	}
}
