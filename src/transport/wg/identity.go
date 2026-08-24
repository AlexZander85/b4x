// WG/AWG identity (design §2): ONE Cloudflare enrollment feeds both
// transports. The registration response already carries everything this
// layer needs — the client-generated curve25519 key pinned by peers[0],
// the edge public key, client_id (the source of the reserved routing
// bytes), and the assigned tunnel addresses. Fields follow the wg_* naming
// of the shared identity store v2; decoding is strict (Aether
// decode_fixed discipline): exact 32-byte keys, client_id decodable to
// <=3 bytes, parseable addresses. Security-relevant fields are re-derived
// on Validate so a tampered store cannot reach the engine.
//
// Red line §11.3: reserved bytes apply ONLY to Cloudflare peers
// (cf_warp=true). With other peers the reserved bytes are zero — otherwise
// the MAC check fails on the far end. The gate is DatagramHookOrNil: the
// engine MUST install the returned hook iff it is non-nil.
package transportwg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

// IdentityFormatVersion bumps on incompatible schema changes; Load refuses
// other versions instead of guessing.
const IdentityFormatVersion = 1

var (
	ErrIdentityAbsent  = errors.New("transportwg: no stored wg identity")
	ErrIdentityCorrupt = errors.New("transportwg: stored wg identity unreadable (quarantined)")
	ErrIdentityInvalid = errors.New("transportwg: wg identity failed field validation")
)

// Identity is one enrolled device projected onto the WG/AWG transport.
type Identity struct {
	Format int `json:"format"`

	// PrivateKey is the client-generated curve25519 key sent with the
	// registration request and pinned by the response's peers[0].
	PrivateKey Key `json:"wg_private_key"`
	// PeerPublicKey is peers[0].public_key — the edge trust anchor for
	// this transport (curve25519, unlike the MASQUE secp256r1 pin).
	PeerPublicKey Key `json:"wg_peer_public_key"`

	// ClientID is the registration's client_id (base64, <=3 bytes decoded);
	// Reserved derives from it and is re-checked by Validate.
	ClientID string `json:"wg_client_id"`

	AssignedV4   string `json:"wg_assigned_v4"`
	AssignedV6   string `json:"wg_assigned_v6,omitempty"`
	EndpointHint string `json:"wg_endpoint_hint,omitempty"`

	// CFWarp marks a Cloudflare WARP peer: ONLY then may reserved bytes be
	// stamped on the wire (red line §11.3).
	CFWarp bool `json:"cf_warp"`
}

// NewIdentity builds and validates an identity from enrollment material:
// base64 (raw std) 32-byte curve25519 keys, the base64 client_id, and the
// assigned addresses verbatim from the response.
func NewIdentity(privateKeyB64, peerPublicB64, clientID, assignedV4, assignedV6 string, cfWarp bool) (*Identity, error) {
	id := &Identity{
		ClientID:   clientID,
		AssignedV4: assignedV4,
		AssignedV6: assignedV6,
		CFWarp:     cfWarp,
	}
	var err error
	if id.PrivateKey, err = ParseKeyB64(privateKeyB64); err != nil {
		return nil, fmt.Errorf("%w: private key: %v", ErrIdentityInvalid, err)
	}
	if id.PeerPublicKey, err = ParseKeyB64(peerPublicB64); err != nil {
		return nil, fmt.Errorf("%w: peer public key: %v", ErrIdentityInvalid, err)
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return id, nil
}

// Reserved derives the 3 reserved routing bytes from ClientID
// (warp-socks/usque lineage: base64-decode, first <=3 bytes, zero-filled).
func (id *Identity) Reserved() ([3]byte, error) {
	return ReservedFromClientID(id.ClientID)
}

// DatagramHookOrNil implements the red-line §11.3 gate: the reserved-bytes
// hook exists only for cf_warp identities; everyone else gets nil (pure
// passthrough, zeroed reserved on the wire).
func (id *Identity) DatagramHookOrNil() (DatagramHook, error) {
	if !id.CFWarp {
		return nil, nil
	}
	r, err := id.Reserved()
	if err != nil {
		return nil, err
	}
	return ReservedHook{Reserved: r}, nil
}

// Validate re-derives every security-relevant field.
func (id *Identity) Validate() error {
	if id == nil {
		return fmt.Errorf("%w: nil", ErrIdentityInvalid)
	}
	if id.Format != 0 && id.Format != IdentityFormatVersion {
		return fmt.Errorf("%w: format %d", ErrIdentityInvalid, id.Format)
	}
	if id.PrivateKey == (Key{}) {
		return fmt.Errorf("%w: zero wg_private_key", ErrIdentityInvalid)
	}
	if id.PeerPublicKey == (Key{}) {
		return fmt.Errorf("%w: zero wg_peer_public_key", ErrIdentityInvalid)
	}
	if id.PrivateKey == id.PeerPublicKey {
		return fmt.Errorf("%w: private equals peer public", ErrIdentityInvalid)
	}
	if _, err := id.Reserved(); err != nil {
		return fmt.Errorf("%w: client_id: %v", ErrIdentityInvalid, err)
	}
	v4, err := netip.ParseAddr(id.AssignedV4)
	if err != nil || !v4.IsValid() || !v4.Is4() {
		return fmt.Errorf("%w: assigned_v4 %q", ErrIdentityInvalid, id.AssignedV4)
	}
	if id.AssignedV6 != "" {
		v6, err := netip.ParseAddr(id.AssignedV6)
		if err != nil || !v6.IsValid() || !v6.Is6() {
			return fmt.Errorf("%w: assigned_v6 %q", ErrIdentityInvalid, id.AssignedV6)
		}
	}
	return nil
}

// ReservedFromClientID decodes the registration client_id into the 3
// reserved routing bytes: base64 (padding tolerated), first <=3 bytes,
// zero-filled tail. Longer decodings are truncated to 3 (warp-socks
// behavior); empty or undecodable input is an error.
func ReservedFromClientID(clientID string) ([3]byte, error) {
	var out [3]byte
	if clientID == "" {
		return out, fmt.Errorf("%w: empty client_id", ErrIdentityInvalid)
	}
	dec := base64.StdEncoding
	if m := len(clientID) % 4; m != 0 {
		clientID += "===="[:4-m]
	}
	raw, err := dec.DecodeString(clientID)
	if err != nil {
		return out, fmt.Errorf("%w: client_id base64: %v", ErrIdentityInvalid, err)
	}
	if len(raw) == 0 {
		return out, fmt.Errorf("%w: client_id decodes to zero bytes", ErrIdentityInvalid)
	}
	if len(raw) > 3 {
		raw = raw[:3]
	}
	copy(out[:], raw)
	return out, nil
}

// ReservedHook stamps/scrubs the CF reserved routing bytes on wire
// datagrams. TX: message types 1..4 carry the identity at packet[1:4]
// (Cloudflare anycast routes by these bytes). RX: the edge sends them SET
// while its MAC covers ZEROED bytes, so the receiver must zero [1:4]
// before the device verifies (warp-socks tunnel.rs lineage). Junk and any
// non-WG datagram pass untouched except for harmless RX scrubbing.
type ReservedHook struct {
	Reserved [3]byte
}

// Compile-time proof the hook satisfies the seam contract.
var _ DatagramHook = ReservedHook{}

// PatchOutbound stamps reserved bytes into types 1..4 (after Noise
// encapsulation, before the wire).
func (h ReservedHook) PatchOutbound(buf []byte) {
	if len(buf) < 4 {
		return
	}
	switch buf[0] {
	case 1, 2, 3, 4:
		buf[1] = h.Reserved[0]
		buf[2] = h.Reserved[1]
		buf[3] = h.Reserved[2]
	}
}

// AdjustInbound zeroes reserved bytes before the device verifies the MAC.
func (h ReservedHook) AdjustInbound(buf []byte) {
	if len(buf) < 4 {
		return
	}
	buf[1] = 0
	buf[2] = 0
	buf[3] = 0
}

// IdentityStore persists one wg Identity atomically at Path (same
// transactional pattern as the MASQUE store: temp file, 0600, fsync,
// rename; corrupt files are quarantined *.corrupt, never deleted). The
// path IS the slot selector — nested configurations (design §7) use a
// second, distinct slot path for the secondary identity.
type IdentityStore struct {
	Path string
}

// Save writes the identity atomically after validation.
func (s *IdentityStore) Save(id *Identity) error {
	if id == nil {
		return fmt.Errorf("%w: nil", ErrIdentityInvalid)
	}
	id.Format = IdentityFormatVersion
	if err := id.Validate(); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".wgid-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := writeSecretFile(tmp, blob); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// Load reads and fully validates the stored identity; missing ->
// ErrIdentityAbsent; unreadable/tampered -> quarantined + ErrIdentityCorrupt.
func (s *IdentityStore) Load() (*Identity, error) {
	blob, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrIdentityAbsent
		}
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(blob, &id); err != nil {
		if qerr := s.Quarantine(); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrIdentityCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrIdentityCorrupt, err)
	}
	if err := id.Validate(); err != nil {
		if qerr := s.Quarantine(); qerr != nil {
			return nil, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrIdentityCorrupt, err, qerr)
		}
		return nil, fmt.Errorf("%w: %v", ErrIdentityCorrupt, err)
	}
	return &id, nil
}

// Quarantine renames the current file to *.corrupt (evidence survives).
func (s *IdentityStore) Quarantine() error {
	return os.Rename(s.Path, s.Path+".corrupt")
}

// writeSecretFile performs write+chmod+sync+close on an open temp file
// (same discipline as the MASQUE store's writer).
func writeSecretFile(f *os.File, blob []byte) error {
	if _, err := f.Write(blob); err != nil {
		return err
	}
	// Best-effort on platforms without POSIX modes (Windows); production
	// target is Linux where 0600 is mandatory for secret files.
	_ = f.Chmod(0o600)
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
