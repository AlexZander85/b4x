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
        // ClassDataPlaneNoRoots: the verification pool resolved structurally
        // empty (embedded anchors unreadable AND no system store) — fail closed
        // with an honest, searchable class instead of a silent TLS dead-end the
        // field would read as "Opera is down in my region" (review H1).
        ClassDataPlaneNoRoots FailureClass = "opera-dataplane-no-roots"
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
        // Status carries the HTTP status code when the failure came from an
        // HTTP-level refusal (e.g. 407 on the data-plane CONNECT); zero
        // otherwise. 407 distinguishes credential rejection (refresh /
        // re-register lever) from a plain bad node (rotation lever).
        Status int
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

// newFailureStatus is newFailure plus the HTTP status code (review M2:
// 407 on CONNECT must be distinguishable from other non-200 refusals
// without parsing strings).
func newFailureStatus(class FailureClass, reason string, status int, err error) *Failure {
        return &Failure{Class: class, Reason: reason, Err: err, Status: status}
}

// FailureStatus extracts the HTTP status from a structured failure
// (zero when the failure carries none).
func FailureStatus(err error) int {
        var f *Failure
        if !errors.As(err, &f) {
                return 0
        }
        return f.Status
}
