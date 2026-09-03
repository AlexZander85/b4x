// Package transportwg implements the WG/AWG transport layer (design
// .ag/research/wg-layer-design.md, stage WG1): an embedded amneziawg-go v3
// device driven without a UAPI socket (NewDevice -> IpcSet -> Up), a custom
// conn.Bind with scoped-socket options (SO_MARK / SO_BINDTODEVICE) and a
// datagram patch seam reserved for Cloudflare routing bytes (filled by WG2),
// plus the config bridge with the pre-IpcSet validator the upstream daemon
// does not have.
package transportwg

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

//go:embed NOTICE.md
var noticeMD []byte

// LicenseSHA256 returns the sha256 of NOTICE.md. Engine manifests for this
// transport must carry it in their LicenseHash field so the WARP-1
// "license bundled" requirement is checked mechanically, not on trust
// (contract shape: src/warp/manifest.go EngineManifest.LicenseHash).
func LicenseSHA256() string {
	sum := sha256.Sum256(noticeMD)
	return hex.EncodeToString(sum[:])
}
