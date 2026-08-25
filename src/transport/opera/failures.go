// Structural failure taxonomy for the Opera reserve transport (design:
// .ag/research/opera-reserve-design.md §3/§7). Every structured outcome
// carries a machine-readable class so downstream consumers (health layer
// OP3, supervisor, trace pipeline) never parse strings. The opera-api-*
// prefix covers the SurfEasy control channel; data-plane classes land with
// OP2 in the same namespace.
package opera

import (
	"errors"
	"fmt"
)

// FailureClass enumerates the structural outcomes of this transport.
type FailureClass string

const (
	// ClassAPIPinMismatch: TOFU SPKI pin of the SurfEasy API channel does
	// not match the certificate presented now. Design §3: every upstream
	// reference rides InsecureSkipVerify here (self-signed API cert); we
	// fail closed instead and leave recovery to bootstrap-through-carrier.
	ClassAPIPinMismatch FailureClass = "opera-api-pin-mismatch"
	// ClassAPIAlgorithm: server offered a Digest algorithm outside our
	// minimal RFC 7616 profile (MD5 only — design §7 red line 0).
	ClassAPIAlgorithm FailureClass = "opera-api-algorithm"
	// ClassAPIAuthRefused: 401 persisted after presenting a fresh Digest
	// response with stale=false — credentials rejected (design §7.0:
	// stale=false / repeated 401 => refuse classification).
	ClassAPIAuthRefused FailureClass = "opera-api-auth-refused"
	// ClassAPIThrottled: HTTP 429 from the SurfEasy API.
	ClassAPIThrottled FailureClass = "opera-api-throttled"
	// ClassDiscoverRegionUnavailable: discover returned code=801 for the
	// requested region (design §2 item 5: fall back to cached endpoints;
	// health layer OP3 owns the fallback, client only classifies).
	ClassDiscoverRegionUnavailable FailureClass = "opera-discover-region-unavailable"
	// ClassDataPlaneTLS: node TLS handshake or certificate verification
	// failed (wrong name / untrusted chain) — fail closed (OP2).
	ClassDataPlaneTLS FailureClass = "opera-dataplane-tls"
	// ClassDataPlaneConnectRefused: the node answered CONNECT with a
	// non-200 status (incl. 407 auth rejection) (OP2).
	ClassDataPlaneConnectRefused FailureClass = "opera-dataplane-connect-refused"
	// ClassDataPlaneProtocol: CONNECT reply was unparseable / truncated —
	// endpoint does not speak the SurfEasy data plane (OP2).
	ClassDataPlaneProtocol FailureClass = "opera-dataplane-protocol"
)

// Failure is a structured outcome. It implements error so it travels
// through ordinary error paths while staying switchable by class.
type Failure struct {
	Class  FailureClass
	Reason string
	Err    error
}

func (f *Failure) Error() string {
	if f.Err != nil {
		return fmt.Sprintf("opera: %s: %s: %v", f.Class, f.Reason, f.Err)
	}
	return fmt.Sprintf("opera: %s: %s", f.Class, f.Reason)
}

func (f *Failure) Unwrap() error { return f.Err }

// IsClass reports whether err is (or wraps) a *Failure of the given class.
func IsClass(err error, class FailureClass) bool {
	var f *Failure
	if !errors.As(err, &f) {
		return false
	}
	return f.Class == class
}

// newFailure wraps err into a Failure (err may be nil for pure conditions).
func newFailure(class FailureClass, reason string, err error) *Failure {
	return &Failure{Class: class, Reason: reason, Err: err}
}
