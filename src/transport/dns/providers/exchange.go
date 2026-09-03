// Package providers implements the native B4X DNS path providers
// (addendum §§32-39). DoT/DoQ are native by owner decision ADR-ADNS-003 and
// are never attributed to the managed dnscrypt backend.
package providers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"golang.org/x/sys/unix"
)

// markedDialer returns a net.Dialer that sets SO_MARK on outbound sockets
// when mark != 0 (dedicated bypass route, addendum §47.5).
func markedDialer(mark int, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if mark != 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if cerr := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
			}); cerr != nil {
				return cerr
			}
			return serr
		}
	}
	return d
}

var (
	errTxIDMismatch     = errors.New("dns transaction id mismatch")
	errQuestionMismatch = errors.New("dns question mismatch")
)

// routerOrigin is the zero client identity used for router-origin probes.
var routerOrigin = classifier.ClientKey{}

// parseQuestion extracts the first question (name, type, class) from a query.
func parseQuestion(query []byte) (name string, qtype, qclass uint16, err error) {
	if len(query) < 12 {
		return "", 0, 0, fmt.Errorf("query truncated: %d bytes", len(query))
	}
	off := 12
	for {
		if off >= len(query) {
			return "", 0, 0, errors.New("question name overruns message")
		}
		l := int(query[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(query) {
			return "", 0, 0, errors.New("invalid label in question")
		}
		if name != "" {
			name += "."
		}
		name += string(query[off : off+l])
		off += l
	}
	if off+4 > len(query) {
		return "", 0, 0, errors.New("question tail truncated")
	}
	qtype = binary.BigEndian.Uint16(query[off : off+2])
	qclass = binary.BigEndian.Uint16(query[off+2 : off+4])
	return name, qtype, qclass, nil
}

// validateResponse enforces transaction-ID and question equality
// (addendum §33: no response is accepted without structural validation).
func validateResponse(query, resp []byte) error {
	if len(resp) < 12 {
		return b4dns.ErrMalformedResponse
	}
	if !bytes.Equal(query[0:2], resp[0:2]) {
		return errTxIDMismatch
	}
	qn, qt, qc, err := parseQuestion(query)
	if err != nil {
		return err
	}
	rn, rt, rc, err := parseQuestion(resp)
	if err != nil {
		return err
	}
	if !equalFoldName(qn, rn) || qt != rt || qc != rc {
		return errQuestionMismatch
	}
	return nil
}

func equalFoldName(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// parseStructured parses and fingerprints a validated response.
func parseStructured(resp []byte, resolverID string, now time.Time) (b4dns.DNSObservation, dnspath.ResponseFingerprint, error) {
	obs, err := b4dns.ParseStructuredResponse(resp, routerOrigin, resolverID, now)
	if err != nil {
		return b4dns.DNSObservation{}, dnspath.ResponseFingerprint{}, err
	}
	return obs, dnspath.FingerprintObservation(obs), nil
}

// outcomeFromError maps transport errors to normalized outcome classes.
func outcomeFromError(err error) dnspath.OutcomeClass {
	switch {
	case err == nil:
		return dnspath.OutcomePassCorrect
	case errors.Is(err, errTxIDMismatch), errors.Is(err, errQuestionMismatch):
		return dnspath.OutcomeQuestionMismatch
	case errors.Is(err, b4dns.ErrMalformedResponse):
		return dnspath.OutcomeMalformedDNS
	case isTimeout(err):
		return dnspath.OutcomeTimeout
	case isRefused(err):
		return dnspath.OutcomeConnectionRefused
	case isMidHandshakeReset(err):
		return dnspath.OutcomeTLSMidHandshakeReset
	default:
		return dnspath.OutcomeInconclusive
	}
}

func isTimeout(err error) bool {
	var nerr interface{ Timeout() bool }
	if errors.As(err, &nerr) {
		return nerr.Timeout()
	}
	return false
}

func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// isMidHandshakeReset matches the DPI family-filter signature: connection
// reset (ECONNRESET) or TLS-layer truncation (unexpected EOF) after
// ClientHello. crypto/tls surfaces the latter as "unexpected EOF" /
// io.ErrUnexpectedEOF; both mean the encrypted path was cut mid-handshake.
func isMidHandshakeReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return strings.Contains(err.Error(), "unexpected EOF")
}
