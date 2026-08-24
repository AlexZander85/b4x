// Config bridge: our typed config -> amneziawg-go IpcSet string.
//
// The renderer is a WHITELIST, not a mirror: HiddenJunk (j1-j3) and
// JunkIntervalSec (itime) are stored in Profile but deliberately never
// rendered — external awg tooling drops the entire config on such keys and
// keeping them out of the wire format is a design invariant enforced by
// TestIPCStringNeverRendersStoreOnlyKeys. Bools render as "true"/"false"
// because the v3 daemon parses them with strconv.ParseBool (uapi.go:530-544);
// the "on/off" grammar belongs to external awg-tools configs, not here.
package transportwg

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Key is a 32-byte curve25519 key rendered as lowercase hex in IPC strings
// (upstream uapiCfg uses hex.EncodeToString for private/public/psk).
type Key [32]byte

// GenerateKey returns a random key (tests and identity provisioning).
func GenerateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	return k, nil
}

func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

// ParseKey decodes 32 bytes from hex.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("transportwg: key hex: %w", err)
	}
	if len(b) != 32 {
		return k, fmt.Errorf("transportwg: key must be 32 bytes, got %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// PeerConfig is one [Peer] section.
type PeerConfig struct {
	PublicKey              Key
	PresharedKey           *Key           // optional
	Endpoint               netip.AddrPort // zero = unset (learned by roaming)
	AllowedIPs             []netip.Prefix
	PersistentKeepaliveSec uint16 // 0 = off
}

// Config is the full device configuration handed to the engine.
type Config struct {
	PrivateKey Key
	ListenPort uint16 // 0 = kernel-assigned
	FWMark     uint32 // mirrors SocketOptions.FwMark when set via IPC
	Profile    Profile
	Peers      []PeerConfig
}

// Validate runs profile validation plus structural peer checks.
func (c *Config) Validate() error {
	if c.PrivateKey == (Key{}) {
		return errors.New("transportwg: private_key is required")
	}
	if err := c.Profile.Validate(); err != nil {
		return err
	}
	for i := range c.Peers {
		p := &c.Peers[i]
		if p.PublicKey == (Key{}) {
			return fmt.Errorf("transportwg: peer[%d]: public_key is required", i)
		}
	}
	return nil
}

// IPCString validates and renders the canonical IpcSet representation.
func (c *Config) IPCString() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var sb strings.Builder
	line := func(key, val string) {
		sb.WriteString(key)
		sb.WriteByte('=')
		sb.WriteString(val)
		sb.WriteByte('\n')
	}

	line("private_key", c.PrivateKey.Hex())
	if c.ListenPort != 0 {
		line("listen_port", fmt.Sprintf("%d", c.ListenPort))
	}
	if c.FWMark != 0 {
		line("fwmark", fmt.Sprintf("%d", c.FWMark))
	}

	p := &c.Profile
	if p.JunkCount > 0 {
		line("jc", u32(p.JunkCount))
		line("jmin", u32(p.JunkMin))
		line("jmax", u32(p.JunkMax))
	}
	pads := []struct {
		key string
		v   uint32
	}{{"s1", p.PadInit}, {"s2", p.PadResponse}, {"s3", p.PadCookie}, {"s4", p.PadTransport}}
	for _, pd := range pads {
		if pd.v > 0 {
			line(pd.key, u32(pd.v))
		}
	}
	hdrs := []struct {
		key string
		r   *Range
	}{
		{"h1", p.HeaderInit}, {"h2", p.HeaderResponse},
		{"h3", p.HeaderCookie}, {"h4", p.HeaderTransport},
	}
	for _, h := range hdrs {
		if h.r != nil {
			line(h.key, h.r.String())
		}
	}
	for i, spec := range p.InitPacket {
		if spec != "" {
			line(fmt.Sprintf("i%d", i+1), spec)
		}
	}
	// j1..j3 / itime are NEVER rendered here by design; see package comment.

	if len(p.HeaderProtKey) > 0 {
		line("header_protection_key", hex.EncodeToString(p.HeaderProtKey))
	}
	if p.ContentPadding != nil {
		line("content_padding_addition", p.ContentPadding.String())
	}
	timings := []struct {
		key string
		r   *Range
	}{
		{"rekey_after_time", p.RekeyAfterTime}, {"rekey_timeout", p.RekeyTimeout},
		{"reject_after_time", p.RejectAfterTime}, {"keepalive_timeout", p.KeepaliveTimeout},
		{"max_handshake_attempts", p.MaxHandshakeAtt},
	}
	for _, t := range timings {
		if t.r != nil {
			line(t.key, t.r.String())
		}
	}
	if p.RandomTrailers {
		line("random_trailers", "true")
	}
	if p.DisableCookies {
		line("disable_cookies", "true")
	}

	for i := range c.Peers {
		peer := &c.Peers[i]
		line("public_key", peer.PublicKey.Hex())
		if peer.PresharedKey != nil {
			line("preshared_key", peer.PresharedKey.Hex())
		}
		if peer.Endpoint.IsValid() && peer.Endpoint.Port() != 0 {
			line("endpoint", peer.Endpoint.String())
		}
		if len(peer.AllowedIPs) == 0 {
			line("allowed_ip", "0.0.0.0/0")
			line("allowed_ip", "::/0")
		} else {
			for _, pref := range peer.AllowedIPs {
				line("allowed_ip", pref.String())
			}
		}
		if peer.PersistentKeepaliveSec > 0 {
			line("persistent_keepalive_interval", fmt.Sprintf("%d", peer.PersistentKeepaliveSec))
		}
	}
	return sb.String(), nil
}

func u32(v uint32) string { return fmt.Sprintf("%d", v) }
