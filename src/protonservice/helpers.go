// Small assembly helpers of the proton runtime: the crypto/rand reader
// adapter, the certificate clock guard, the seed codec and the last-good
// adapter over the wg store.
package protonservice

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/netip"
	"time"

	"github.com/daniellavrushin/b4/transport/proton"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// crandReader adapts crypto/rand to io.Reader for the proton generators.
type crandReader struct{}

func (crandReader) Read(p []byte) (int, error) { return rand.Read(p) }

var _ io.Reader = crandReader{}

// encodeSeed renders the raw seed for the identity slot.
func encodeSeed(seed [32]byte) string { return base64.StdEncoding.EncodeToString(seed[:]) }

// parseCertNotBefore extracts notBefore from a PEM X.509 body (ok=false when
// absent/unparseable — the guard then skips).
func parseCertNotBefore(pemBody string) (time.Time, bool) {
	blk, _ := pem.Decode([]byte(pemBody))
	if blk == nil {
		return time.Time{}, false
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return cert.NotBefore, true
}

// wgLastGoodView adapts the wg LastGoodStore onto the proton issuer's
// LastGood seam (the profile id of the stored winner).
type wgLastGoodView struct{ store twg.LastGoodStore }

func (v *wgLastGoodView) LastGoodProfileID() string {
	if v.store == nil {
		return ""
	}
	if a, ok := v.store.Get(); ok {
		return a.ProfileID
	}
	return ""
}

var (
	_ proton.LastGood = (*wgLastGoodView)(nil)
)

// candidateAddrs projects the candidate list onto the seeker's AddrPort
// list (order preserved).
func candidateAddrs(cands []proton.Candidate) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.AddrPort())
	}
	return out
}
