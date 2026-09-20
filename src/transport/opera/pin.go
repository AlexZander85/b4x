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

// endpointKey renders the TOFU pin key for one dialed API endpoint. The
// SurfEasy API fleet serves PER-BACKEND self-signed certificates: measured
// 2026-09-20, api2.sec-tunnel.com resolves to 77.111.247.139 (CN=
// h07-24-04.best.am4.osa, SPKI b4d61662…) and 77.111.247.143 (CN=
// h05-22-01.best.am4.osa, SPKI f409a453…) — two stable but DIFFERENT keys
// behind one name. A single host-scoped pin can therefore never hold (the
// health layer would flap between the two backends); keying the pin by host
// AND endpoint keeps strict fail-closed semantics while making the fleet
// usable. When ip is empty or equals host (an IP-literal authority, or an
// unresolved fallback) the historical host-only key is kept.
func endpointKey(host, ip string) string {
	if ip == "" || ip == host {
		return host
	}
	return host + "@" + ip
}

type pinStore struct {
	mu      sync.Mutex
	pins    map[string]string // endpoint key -> committed fingerprint (trusted)
	pending map[string]string // endpoint key -> fingerprint observed on the bootstrap contact
	lastKey map[string]string // host -> endpoint key most recently presented
}

func newPinStore(committed map[string]string) *pinStore {
	pins := make(map[string]string, len(committed))
	for k, fp := range committed {
		if k != "" && fp != "" {
			pins[k] = fp
		}
	}
	return &pinStore{pins: pins, pending: make(map[string]string), lastKey: make(map[string]string)}
}

// verify runs inside the TLS handshake (VerifyConnection). The key is the
// endpoint-scoped pin (host@ip); a key without a committed pin records its
// observed leaf fingerprint as a pending candidate — trust arrives only after
// commit() proves the channel speaks the real SurfEasy API. A known key must
// match exactly (server key change => fail closed).
func (p *pinStore) verify(key, host string, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("tls: no peer certificates from %q", key)
	}
	fp := spkiFingerprint(certs[0])
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastKey[host] = key
	known, ok := p.pins[key]
	switch {
	case !ok:
		p.pending[key] = fp
	case known != fp:
		return newFailure(ClassAPIPinMismatch,
			fmt.Sprintf("api channel key changed for %s (had %.16s…, got %.16s…)", key, known, fp), nil)
	default:
		delete(p.pending, key)
	}
	return nil
}

// commit promotes the pending candidate for the endpoint most recently
// presented for host, after a successful API exchange decoded through this
// channel. Reports whether a new pin was recorded so the caller can persist
// the identity slot.
func (p *pinStore) commit(host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.lastKey[host]
	if !ok {
		return false
	}
	fp, ok := p.pending[key]
	if !ok {
		return false
	}
	delete(p.pending, key)
	if p.pins[key] == fp {
		return false
	}
	p.pins[key] = fp
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
