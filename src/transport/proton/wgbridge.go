// Projection of the Proton identity onto the shared transport/wg engine
// (design §7, patch-plan §6.1): the WG private key is DERIVED from the seed
// (never stored), the peer key is the node's X25519 public half, and
// cf_warp=false — the reserved-bytes hook is nil (the red line §11.3: those
// bytes ride ONLY on Cloudflare peers; against Proton they are zero on the
// wire, the vanilla peer would fail the MAC otherwise).
package proton

import (
	"encoding/base64"
	"strings"
	"time"

	twg "github.com/daniellavrushin/b4/transport/wg"
)

// wgSyntheticClientID satisfies twg.Identity.Validate()'s non-empty client_id
// requirement. The reserved hook is nil for cf_warp=false, so the value
// never reaches the wire — it is engine bookkeeping only (base64 of "PTN").
const wgSyntheticClientID = "UFRO"

// Proton tunnel constants fixed by the topology (design §1.8): the client
// sits at 10.2.0.2/32 (+ v6), the peer allows everything.
// Bare addresses: wg.Identity.Validate parses AssignedV4/V6 as plain
// addresses; the /32-/128 prefixing belongs to the config render.
const (
	ProtonTunnelV4    = "10.2.0.2"
	ProtonTunnelV6    = "2a07:b944::2:2"
	ProtonTunnelDNSV4 = "10.2.0.1"
	ProtonTunnelDNSV6 = "2a07:b944::2:1"
)

// WGIdentity projects the stored identity + the chosen node onto the engine
// identity. AssignedV4/V6 come from the certificate response when the API
// provided them, otherwise the fixed Proton constants.
func (id *Identity) WGIdentity(node Node) (*twg.Identity, error) {
	seed, err := id.Seed()
	if err != nil {
		return nil, err
	}
	kp := DeriveKeyPair(seed)
	priv, err := base64.StdEncoding.DecodeString(kp.WGPrivateKeyB64)
	if err != nil {
		return nil, err
	}
	peer, err := base64.StdEncoding.DecodeString(node.PeerPubKey)
	if err != nil || len(peer) != 32 {
		return nil, ErrAPIInvalid
	}
	v4 := id.VPNIv4
	if v4 == "" {
		v4 = ProtonTunnelV4
	}
	v6 := id.VPNIv6
	if v6 == "" {
		v6 = ProtonTunnelV6
	}
	return &twg.Identity{
		PrivateKey:    twg.Key(priv),
		PeerPublicKey: twg.Key(peer),
		ClientID:      wgSyntheticClientID,
		AssignedV4:    v4,
		AssignedV6:    v6,
		// CFWarp=false is the red line: DatagramHookOrNil() returns nil, the
		// reserved bytes stay zero on the wire.
		CFWarp: false,
	}, nil
}

// TunnelAddresses renders the netstack address/DNS lists from the identity
// (API-provided when present, Proton constants otherwise).
func (id *Identity) TunnelAddresses() (v4, v6 string, dns []string) {
	v4 = id.VPNIv4
	v6 = id.VPNIv6
	if v4 == "" {
		v4 = ProtonTunnelV4
	}
	if v6 == "" {
		v6 = ProtonTunnelV6
	}
	if len(id.VPNDNS) > 0 {
		dns = append([]string(nil), id.VPNDNS...)
	} else {
		dns = []string{ProtonTunnelDNSV4}
	}
	return v4, v6, dns
}

// SessionSummary is the redacted registration digest for logs (the
// redaction rule: seed/tokens never leave; pubkey prefix only).
func (id *Identity) SessionSummary() string {
	red := id.Redacted()
	var sb strings.Builder
	sb.WriteString("pub=")
	sb.WriteString(red.PubkeyPrefix)
	sb.WriteString(" cert_expires=")
	sb.WriteString(time.Unix(red.CertExpiresAt, 0).UTC().Format(time.RFC3339))
	return sb.String()
}
