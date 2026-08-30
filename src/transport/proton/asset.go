// Embedded offline asset (design §1.7 step 4, patch-plan §4.1): the built-in
// free-tier node list of the firmware, a copy of the Nova v1.31 asset —
// PUBLIC SERVER FACTS ONLY (server_name, country, city, entry_ip,
// peer_public_key). No account material, no private keys: each device
// registers its own key (red line §10.4; the asset invariant test guards the
// five-fields-only rule).
//
// The live logicals list ALWAYS takes priority; the asset is the fallback
// when neither the API nor the on-disk cache can answer. A source swap is
// logged/announced, never silent (proton_nodes_refreshed{source=asset}).
package proton

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed assets/proton_nodes.json
var nodesAssetJSON []byte

// AssetNode is the on-disk node shape of the asset (exactly five public
// fields; the invariant test refuses anything else).
type AssetNode struct {
	ServerName    string `json:"server_name"`
	Country       string `json:"country"`
	City          string `json:"city"`
	EntryIP       string `json:"entry_ip"`
	PeerPublicKey string `json:"peer_public_key"`
}

type assetFile struct {
	GeneratedAt int64       `json:"generated_at"`
	Source      string      `json:"source"`
	Note        string      `json:"note"`
	Nodes       []AssetNode `json:"nodes"`
}

// AssetNodes parses the embedded asset into the live Node model. Load, the
// ranking input of the live list, is unknown offline — every node carries
// the neutral 0 and keeps the asset's country-interleaved order.
func AssetNodes() ([]Node, error) {
	var f assetFile
	if err := json.Unmarshal(nodesAssetJSON, &f); err != nil {
		return nil, fmt.Errorf("proton: nodes asset: %w", err)
	}
	out := make([]Node, 0, len(f.Nodes))
	for _, n := range f.Nodes {
		out = append(out, Node{
			Name:       n.ServerName,
			Country:    n.Country,
			City:       n.City,
			EntryIP:    n.EntryIP,
			PeerPubKey: n.PeerPublicKey,
		})
	}
	return out, nil
}
