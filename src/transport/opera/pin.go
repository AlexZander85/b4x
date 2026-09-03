// TOFU pinning of the SurfEasy API channel (design §3). Every upstream
// opera-proxy reference rides InsecureSkipVerify because api2.sec-tunnel.com
// serves a self-signed certificate — a MITM can hand out a fake node list.
// We keep the self-signed tolerance (there is nothing else to verify against)
// but bind the channel to the first genuinely-proven key: the leaf SPKI seen
// during the first successful API exchange is committed as a pin, and every
// later contact must match it. Mismatch => ClassAPIPinMismatch, fail closed;
// recovery belongs to bootstrap-through-carrier (OP4).
package opera

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
)

// spkiFingerprint returns the lowercase-hex SHA-256 of the certificate's
// SubjectPublicKeyInfo (the standard HPKP-style pin material).
func spkiFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

type pinStore struct {
	mu      sync.Mutex
	pins    map[string]string // host -> committed fingerprint (trusted)
	pending map[string]string // host -> fingerprint observed on the bootstrap contact
}

func newPinStore(committed map[string]string) *pinStore {
	pins := make(map[string]string, len(committed))
	for host, fp := range committed {
		if host != "" && fp != "" {
			pins[host] = fp
		}
	}
	return &pinStore{pins: pins, pending: make(map[string]string)}
}

// verify runs inside the TLS handshake (VerifyConnection). A host without a
// committed pin records its observed leaf fingerprint as a pending candidate
// — trust arrives only after commit() proves the channel speaks the real
// SurfEasy API. A host with a pin must match exactly.
func (p *pinStore) verify(host string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("tls: no peer certificates from %q", host)
	}
	fp := spkiFingerprint(certs[0])
	p.mu.Lock()
	defer p.mu.Unlock()
	known, ok := p.pins[host]
	switch {
	case !ok:
		p.pending[host] = fp
	case known != fp:
		return newFailure(ClassAPIPinMismatch,
			fmt.Sprintf("api channel key changed for %s (had %.16s…, got %.16s…)", host, known, fp), nil)
	default:
		delete(p.pending, host)
	}
	return nil
}

// commit promotes the pending candidate for host after a successful API
// exchange decoded through this channel. Reports whether a new pin was
// recorded so the caller can persist the identity slot.
func (p *pinStore) commit(host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	fp, ok := p.pending[host]
	if !ok {
		return false
	}
	delete(p.pending, host)
	if p.pins[host] == fp {
		return false
	}
	p.pins[host] = fp
	return true
}

// snapshot returns a copy of the committed pins for identity persistence.
func (p *pinStore) snapshot() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.pins))
	for k, v := range p.pins {
		out[k] = v
	}
	return out
}

// load seeds committed pins from a stored identity (adopt path).
func (p *pinStore) load(pins map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for host, fp := range pins {
		if host != "" && fp != "" {
			p.pins[host] = fp
		}
	}
}
