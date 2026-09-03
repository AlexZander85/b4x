// TOFU SPKI pinning for the three control-plane hosts (design Part I §5,
// red line 6): vpn.mozilla.org, api.accounts.firefox.com,
// firefox.settings.services.mozilla.com. Mismatch = ErrPinMismatch =
// FailureClass fxvpn-api-pin-mismatch, and the caller fail-closes (the
// ControlPlane dialer closes the TLS connection before any request rides
// it). The reference client pins nothing — this is our hole-closer, same as
// E-OPERA §3.
//
// TWO-LAYER TOFU (review F5 — the naive "record at first handshake" is a
// MITM-freeze hazard):
//
//   - BAKED SEEDS (F5b): the production hosts serve long-lived public
//     certificates, so the leaf SPKI SHA-256 of all three is baked in below
//     (the Proton 10-pin seed analogue). A seeded host must present the
//     seed's key: divergence fails closed with an explicit error; a match
//     proves the channel without any recording. Seeds are re-derived at
//     release time (command in the seedPins comment) — a rotation of
//     Mozilla keys ships as a seed update, which is the deliberate trade of
//     seeded pinning.
//   - PENDING → COMMIT (F5a, the opera/pin.go pattern): a host WITHOUT seed
//     coverage records its observed leaf as a PENDING candidate only; the
//     pin is committed (and persisted) after the first parseable 2xx
//     exchange rode the pinned channel (ControlPlane.Do → CommitPending).
//     A MITM on the very first contact can no longer freeze its key into
//     the store before any proof.
package fxvpn

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const pinStoreFormatVersion = 1

// seedPins are the baked-in leaf SPKI SHA-256 pins of the production
// control-plane hosts. Re-derive with:
//
//	openssl s_client -connect HOST:443 -servername HOST </dev/null | \
//	  openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | \
//	  openssl dgst -sha256
var seedPins = map[string]string{
	"api.accounts.firefox.com":              "8135c69230002ac8c819db501afa013274a2cdc4c0800d3c313a30adbaccff95",
	"vpn.mozilla.org":                       "6b20ae39c60a268fa01310bc2ae7fdb335547671456016f2dac31e89e0d87308",
	"firefox.settings.services.mozilla.com": "437017bdda304f5ba09b14acc410580f4fddb98e06c0b31fcff024c62c367d09",
}

// PinStore persists host -> SPKI-SHA256 hex mappings at Path (0600 atomic).
// Pending candidates live in memory only.
type PinStore struct {
	mu   sync.Mutex
	Path string
	Pins map[string]string `json:"pins"`

	pending map[string]string // host -> fingerprint observed pre-proof (F5a)
}

type pinStoreFile struct {
	Version int               `json:"version"`
	SavedAt time.Time         `json:"saved_at"`
	Pins    map[string]string `json:"pins"`
}

// LoadPinStore loads the store from path; a missing file yields an empty
// in-memory store (TOFU starts fresh). A corrupt file is quarantined and
// reported: the caller may decide to start over, but the event surfaces.
func LoadPinStore(path string) (*PinStore, error) {
	ps := &PinStore{Path: path, Pins: map[string]string{}, pending: map[string]string{}}
	blob, err := readStoreFile(path)
	if err != nil {
		if errors.Is(err, ErrStoreAbsent) {
			return ps, nil
		}
		return nil, err
	}
	var f pinStoreFile
	if jerr := json.Unmarshal(blob, &f); jerr != nil || f.Version != pinStoreFormatVersion {
		if qerr := quarantinePath(path); qerr != nil {
			return ps, fmt.Errorf("%w: %v (quarantine failed: %v)", ErrStoreCorrupt, jerr, qerr)
		}
		return ps, fmt.Errorf("%w: %v", ErrStoreCorrupt, jerr)
	}
	if f.Pins != nil {
		ps.Pins = f.Pins
	}
	return ps, nil
}

// Verify checks the leaf certificate against the recorded pin for host.
// Known host with a different SPKI => ErrPinMismatch (fail-closed). Seeded
// host presenting a foreign key => ErrPinMismatch with the seed divergence
// spelled out (the explicit event of F5b). Unseeded unknown host =>
// PENDING record (no persist; the commit follows the first 2xx proof).
// Empty certificate chain => hard error.
func (p *PinStore) Verify(host string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("fxvpn: no peer certificates for %s", host)
	}
	sum := spkiPin(certs[0])

	p.mu.Lock()
	defer p.mu.Unlock()
	existing, ok := p.Pins[host]
	if ok {
		if existing != sum {
			return fmt.Errorf("%w: %s presented %s, pinned %s", ErrPinMismatch, host, sum, existing)
		}
		delete(p.pending, host)
		return nil
	}
	if seed, seeded := seedPins[host]; seeded {
		if seed != sum {
			return fmt.Errorf("%w: %s presented %s, baked seed %s (seed divergence — a MITM on first contact, a CDN key rotation, or a stale seed; rotate seeds at release, do NOT auto-commit)", ErrPinMismatch, host, sum, seed)
		}
		// Proven against the baked seed: the channel needs no recording.
		delete(p.pending, host)
		return nil
	}
	// No seed coverage: auto-TOFU stays pending until the 2xx proof (F5a).
	p.pending[host] = sum
	return nil
}

// CommitPending promotes the pending candidate for host after a successful
// (parseable 2xx) HTTP exchange rode the pinned channel — the opera commit
// pattern. Reports whether a new pin was recorded; a persistence failure
// keeps the in-memory pin (the next proof re-attempts the write) and
// returns the error for logging.
func (p *PinStore) CommitPending(host string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fp, ok := p.pending[host]
	if !ok {
		return false, nil
	}
	delete(p.pending, host)
	if p.Pins[host] == fp {
		return false, nil
	}
	p.Pins[host] = fp
	if err := p.saveLocked(); err != nil {
		return true, fmt.Errorf("fxvpn: persisting pin for %s: %w", host, err)
	}
	return true, nil
}

// PendingSnapshot returns the in-flight pending candidates (status/tests).
func (p *PinStore) PendingSnapshot() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.pending))
	for k, v := range p.pending {
		out[k] = v
	}
	return out
}

// Snapshot returns a copy of the pins for status reporting.
func (p *PinStore) Snapshot() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.Pins))
	for k, v := range p.Pins {
		out[k] = v
	}
	return out
}

func (p *PinStore) saveLocked() error {
	blob, err := json.MarshalIndent(pinStoreFile{
		Version: pinStoreFormatVersion,
		SavedAt: time.Now().UTC(),
		Pins:    p.Pins,
	}, "", "  ")
	if err != nil {
		return err
	}
	return saveAtomic(p.Path, blob)
}
