// SPKI pin-store for the Proton control plane (design §2/§3.3, patch-plan
// §3.3). Every control host is pinned; authenticity rides SPKI pins, never
// the certificate chain — the DoH mirrors present self-signed certificates
// for a foreign CN by design, so chain validation would reject the honest
// mirror while accepting nothing about a hostile one.
//
// Seed = 10 published pins: the 6 main Proton API pins
// (ProtonVPN-Next NetworkConstants.kt:24-35) + the 4 alternative-routing
// mirror pins (Nova ProtonDoh.kt:36-49). Behavior:
//
//   - leaf SPKI in the seed set        -> OK (any host; pin evolution
//     without a release);
//   - host with a committed TOFU pin   -> leaf must match (divergence =
//     proton-api-pin-mismatch, fail closed, next ladder rung);
//   - otherwise                        -> TOFU: the observed leaf is recorded
//     as PENDING; trust arrives only after a successful Proton API exchange
//     through the same channel promotes it (commit), the opera/pin.go
//     pattern.
//
// The committed map persists at pins.json (sibling of the identity slot,
// atomic write, 0644 acceptable — pins are public key fingerprints, not
// secrets).
package proton

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SeedPins are the 10 published Proton SPKI pins (base64 SHA-256 of the
// SubjectPublicKeyInfo). The first six cover the main API channel, the last
// four the alternative-routing mirrors (CN=*.demo-wathever.net self-signed).
var SeedPins = []string{
	// Main Proton API (NetworkConstants.kt DEFAULT_SPKI_PINS).
	"drtmcR2kFkM8qJClsuWgUzxgBkePfRCkRpqUesyDmeE=",
	"YRGlaY0jyJ4Jw2/4M8FIftwbDIQfh8Sdro96CeEel54=",
	"AfMENBVvOS8MnISprtvyPsjKlPooqh8nMB/pvCrpJpw=",
	"CT56BhOTmj5ZIPgb/xD5mH8rY3BLo/MlhP7oPyJUEDo=",
	"35Dx28/uzN3LeltkCBQ8RHK0tlNSa2kCpCRGNp34Gxc=",
	"qYIukVc63DEITct8sFT7ebIq5qsWmuscaIKeJx+5J5A=",
	// Alternative-routing mirrors (ProtonDoh.kt ALTERNATIVE_SPKI_PINS).
	"EU6TS9MO0L/GsDHvVc9D5fChYLNy5JdGYpJw0ccgetM=",
	"iKPIHPnDNqdkvOnTClQ8zQAIKG0XavaPkcEo0LBAABA=",
	"MSlVrBCdL0hKyczvgYVSRNm88RicyY04Q2y5qrBt0xA=",
	"C2UxW0T1Ckl9s+8cXfjXxlEqwAfPM4HiW2y3UdtBeCw=",
}

// PinFileFormat is the on-disk schema version of pins.json.
const PinFileFormat = 1

type pinFile struct {
	Format    int               `json:"format"`
	Committed map[string]string `json:"committed"`
}

// PinStore holds the seed pins plus the TOFU-committed per-host leaf pins.
type PinStore struct {
	Path string // empty = memory-only (tests)

	mu        sync.Mutex
	seed      map[string]bool
	committed map[string]string // host -> committed leaf fingerprint (trusted)
	pending   map[string]string // host -> leaf fingerprint observed on the bootstrap contact
}

// NewPinStore builds the store, loading committed TOFU pins from Path when
// set. A corrupt pins file is quarantined (it is not a secret; losing it
// only forces fresh TOFU on unknown mirrors).
func NewPinStore(path string) (*PinStore, error) {
	p := &PinStore{
		Path:      path,
		seed:      make(map[string]bool, len(SeedPins)),
		committed: make(map[string]string),
		pending:   make(map[string]string),
	}
	for _, pin := range SeedPins {
		if pin != "" {
			p.seed[pin] = true
		}
	}
	if path == "" {
		return p, nil
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return nil, err
	}
	var f pinFile
	if err := json.Unmarshal(blob, &f); err != nil || f.Format != PinFileFormat {
		_ = os.Rename(path, path+".corrupt")
		return p, nil
	}
	for host, pin := range f.Committed {
		if host != "" && pin != "" {
			p.committed[host] = pin
		}
	}
	return p, nil
}

// Fingerprint returns the base64 SHA-256 SPKI pin of the leaf certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// VerifyConnection returns a tls.Config VerifyConnection callback bound to
// host. The transport ignores the chain (mirrors are self-signed by design)
// and pins instead — the exact trade the design §2 fixes.
func (p *PinStore) VerifyConnection(host string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		return p.Verify(host, cs.PeerCertificates)
	}
}

// Verify pins the presented chain. The leaf is the TOFU/comparison material;
// the seed check walks the whole chain leaf-first (published Proton pins may
// cover an intermediate CA, the OkHttp CertificatePinner semantics of the
// references).
func (p *PinStore) Verify(host string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("%w: no peer certificates from %q", ErrPinMismatch, host)
	}
	leaf := Fingerprint(certs[0])
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range certs {
		if p.seed[Fingerprint(c)] {
			delete(p.pending, host)
			return nil
		}
	}
	if committed, ok := p.committed[host]; ok {
		if committed != leaf {
			return fmt.Errorf("%w: api channel key changed for %s", ErrPinMismatch, host)
		}
		return nil
	}
	p.pending[host] = leaf
	return nil
}

// Commit promotes the pending candidate for host after a successful API
// exchange decoded through this channel. Reports whether a new pin was
// recorded so the caller persists the store.
func (p *PinStore) Commit(host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	fp, ok := p.pending[host]
	if !ok {
		return false
	}
	delete(p.pending, host)
	if p.committed[host] == fp {
		return false
	}
	p.committed[host] = fp
	return true
}

// Save persists the committed map atomically (0644: fingerprints are public
// facts; the identity slot next to it holds the secrets).
func (p *PinStore) Save() error {
	if p.Path == "" {
		return nil
	}
	p.mu.Lock()
	f := pinFile{Format: PinFileFormat, Committed: make(map[string]string, len(p.committed))}
	for k, v := range p.committed {
		f.Committed[k] = v
	}
	p.mu.Unlock()
	blob, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proton-pins-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(blob); err != nil {
		cleanup()
		return err
	}
	_ = tmp.Chmod(0o644)
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, p.Path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
