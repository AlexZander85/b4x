package providers

import (
	"errors"
	"io"
	"strings"
	"syscall"
)

// tlsCutError reports whether a TLS-stage error is the DPI family-filter
// signature: the encrypted path was cut after ClientHello (addendum §58).
//
// It extends isMidHandshakeReset with the error shapes crypto/tls actually
// returns in the field. A clean FIN at the record layer with zero bytes of the
// next record surfaces as io.EOF (not io.ErrUnexpectedEOF), and a hard cut may
// surface as EPIPE — neither is matched by the generic mapper, so without this
// a wired native DoT path is classified INCONCLUSIVE and the family is never
// quarantined (observed in field b4x-gy9a re-validation: the WAN cuts
// dns.google:853 with "unexpected eof" but the detector saw no mid-handshake).
//
// This classifier is intentionally TLS-only: it is used by the DoT/DoH
// providers, never by the plaintext UDP/TCP paths, where a bare EOF is ordinary
// truncation rather than a mid-handshake cut.
func tlsCutError(err error) bool {
	if err == nil {
		return false
	}
	if isMidHandshakeReset(err) {
		return true
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "unexpected EOF") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}
