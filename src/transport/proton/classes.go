// FailureClass taxonomy and sentinel errors (design §8). Class strings are
// stable wire identifiers used by events/metrics; events are snake_case,
// classes kebab-case — the program canon (opera/wg/fxvpn parity). The
// transport part of the taxonomy (wg-handshake-timeout, wg-stall-rx,
// awg-version-mismatch, awg-junk-profile-failed) is REUSED from
// transport/wg as-is and never duplicated here.
package proton

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// FailureClass values emitted by the proton control plane.
const (
	ClassAPIRefused        = "proton-api-refused"            // 401/403/410 on registration — stop, never retry
	ClassAPIThrottled      = "proton-api-throttled"          // 429/5xx — backoff honoring Retry-After, cap 30s
	ClassAPIPinMismatch    = "proton-api-pin-mismatch"       // TOFU/SPKI divergence — fail closed
	ClassAPIInvalid        = "proton-api-invalid"            // response structurally unusable (e.g. no ExpirationTime)
	ClassCaptchaRequired   = "proton-captcha-required"       // 9001/12087 — structural refusal, event to owner
	ClassScopeMissing      = "proton-scope-missing"          // Scopes lacks "vpn"
	ClassSessionRefreshBad = "proton-session-refresh-failed" // refresh 400/401/422 -> re-register (capped!)
	ClassCertExpired       = "proton-cert-expired"           // notAfter passed, re-issue failed
	ClassNoNodes           = "proton-no-nodes"               // both node sources empty
	ClassJailed            = "proton-jailed"                 // handshake ok, data does not flow (trust-gate x2)
	ClassExitMismatch      = "proton-exit-mismatch"          // exit country != requested location
)

// Event names (snake_case, design §8). proton_established fires STRICTLY
// after the DATA GATE — the camouflage cutoff rule.
const (
	EventRegistered       = "proton_registered"
	EventSessionRefreshed = "proton_session_refreshed"
	EventCertRenewed      = "proton_cert_renewed"
	EventNodesRefreshed   = "proton_nodes_refreshed"
	EventProfileIssued    = "proton_profile_issued"
	EventEstablished      = "proton_established"
	EventRotated          = "proton_rotated"
	EventLocationSwitched = "proton_location_switched"
	EventExitMismatch     = "proton_exit_mismatch"
)

// Sentinel errors. Callers branch with errors.Is; typed wrappers below add
// HTTP detail without leaking secrets into logs (bodies are truncated and
// Proton API error strings carry no credentials by construction).
var (
	ErrAPIRefused       = errors.New("proton: api refused")
	ErrAPIThrottled     = errors.New("proton: api throttled")
	ErrPinMismatch      = errors.New("proton: api spki pin mismatch")
	ErrCaptchaRequired  = errors.New("proton: captcha required")
	ErrScopeMissing     = errors.New("proton: session scope missing vpn")
	ErrAlreadyTied      = errors.New("proton: session already tied to a user")
	ErrAPIInvalid       = errors.New("proton: api response invalid")
	ErrNoNodes          = errors.New("proton: no free nodes")
	ErrCertExpired      = errors.New("proton: certificate expired")
	ErrExitMismatch     = errors.New("proton: exit country mismatch")
	ErrIdentityAbsent   = errors.New("proton: no stored identity")
	ErrIdentityCorrupt  = errors.New("proton: stored identity unreadable (quarantined)")
	ErrIdentityInvalid  = errors.New("proton: identity failed field validation")
	ErrSessionRefreshed = errors.New("proton: session refreshed")
)

// ThrottledError reports HTTP 429/5xx with the parsed Retry-After header
// (the caller owes the backoff, capped at 30 s — the enrollment canon).
type ThrottledError struct {
	RetryAfter    time.Duration
	HasRetryAfter bool
	Status        int
	Body          string
}

func (e *ThrottledError) Error() string {
	if e.HasRetryAfter {
		return "proton: throttled (HTTP " + strconv.Itoa(e.Status) + ", retry-after " + e.RetryAfter.String() + "): " + e.Body
	}
	return "proton: throttled (HTTP " + strconv.Itoa(e.Status) + "): " + e.Body
}

func (e *ThrottledError) Unwrap() error { return ErrAPIThrottled }

// APIError is a Proton-Code-carrying failure (the envelope {Code, Error}).
// Code 9001/12087 classify as captcha; everything else keeps its code for
// diagnostics.
type APIError struct {
	Code    int
	Status  int
	Body    string
	Wrapped error
}

func (e *APIError) Error() string {
	return fmt.Sprintf("proton: api error code=%d status=%d: %s", e.Code, e.Status, e.Body)
}

func (e *APIError) Unwrap() error { return e.Wrapped }

// Classify maps a control-plane error onto its FailureClass constant.
// Unknown errors map to "" (caller decides; not every failure is a class).
func Classify(err error) string {
	switch {
	case errors.Is(err, ErrAPIRefused):
		return ClassAPIRefused
	case errors.Is(err, ErrAPIThrottled):
		return ClassAPIThrottled
	case errors.Is(err, ErrPinMismatch):
		return ClassAPIPinMismatch
	case errors.Is(err, ErrCaptchaRequired):
		return ClassCaptchaRequired
	case errors.Is(err, ErrScopeMissing):
		return ClassScopeMissing
	case errors.Is(err, ErrAPIInvalid):
		return ClassAPIInvalid
	case errors.Is(err, ErrNoNodes):
		return ClassNoNodes
	case errors.Is(err, ErrCertExpired):
		return ClassCertExpired
	case errors.Is(err, ErrExitMismatch):
		return ClassExitMismatch
	default:
		return ""
	}
}
