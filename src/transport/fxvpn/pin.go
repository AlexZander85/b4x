// TOFU SPKI pinning for the three control-plane hosts (design Part I §5,
// red line 6): vpn.mozilla.org, api.accounts.firefox.com,
// firefox.settings.services.mozilla.com. First successful contact records
// the leaf SPKI SHA-256; every later contact must match exactly.
// Mismatch = ErrPinMismatch = FailureClass fxvpn-api-pin-mismatch, and the
// caller fail-closes (the ControlPlane dialer closes the TLS connection
// before any request rides it). The reference client pins nothing — this is
// our hole-closer, same as E-OPERA §3.
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

// PinStore persists host -> SPKI-SHA256 hex mappings at Path (0600 atomic).
type PinStore struct {
	mu   sync.Mutex
	Path string
	Pins map[string]string `json:"pins"`
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
	ps := &PinStore{Path: path, Pins: map[string]string{}}
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
// Unknown host => TOFU record + persist. Known host with different SPKI =>
// ErrPinMismatch (fail-closed). Empty certificate chain => hard error.
func (p *PinStore) Verify(host string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("fxvpn: no peer certificates for %s", host)
	}
	sum := spkiPin(certs[0])

	p.mu.Lock()
	defer p.mu.Unlock()
	existing, ok := p.Pins[host]
	if !ok {
		p.Pins[host] = sum
		if err := p.saveLocked(); err != nil {
			// Roll back the in-memory record so a persistence failure does
			// not silently widen trust to "recorded but never durable".
			delete(p.Pins, host)
			return fmt.Errorf("fxvpn: recording pin for %s: %w", host, err)
		}
		return nil
	}
	if existing != sum {
		return fmt.Errorf("%w: %s presented %s, pinned %s", ErrPinMismatch, host, sum, existing)
	}
	return nil
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
