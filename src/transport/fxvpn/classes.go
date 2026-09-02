// FailureClass taxonomy continuation and sentinel errors (design Part I §5).
// Class strings are stable wire identifiers used by events/metrics from FX4
// onward; keep them exactly as written in the design doc.
package fxvpn

import (
        "errors"
        "strconv"
        "time"
)

// FailureClass values emitted by the fxvpn control plane.
const (
        ClassAuthRejected        = "fxvpn-auth-rejected"
        ClassQuotaExhausted      = "fxvpn-quota-exhausted"
        ClassChallengeFailed     = "fxvpn-challenge-failed"
        ClassConnectRejected     = "fxvpn-connect-rejected"
        ClassNoServerForLocation = "fxvpn-no-server-for-location"
        ClassAPIPinMismatch      = "fxvpn-api-pin-mismatch"
        ClassAccountStoreCorrupt = "fxvpn-account-store-corrupt"
        ClassExitMismatch        = "fxvpn_exit_mismatch"
        // ClassExitProbeFailed is telemetry-distinct from the mismatch class
        // (review F9): a failed PROBE is not a verified MISMATCH.
        ClassExitProbeFailed = "fxvpn_exit_probe_failed"
)

// Sentinel errors. Callers branch with errors.Is; typed wrappers below add
// HTTP detail without leaking secrets into logs (bodies are truncated and
// never contain credentials by contract of the Mozilla APIs).
var (
        ErrStoreAbsent    = errors.New("fxvpn: store absent")
        ErrStoreCorrupt   = errors.New("fxvpn: store corrupt")
        ErrPinMismatch    = errors.New("fxvpn: api spki pin mismatch")
        ErrQuotaExceeded  = errors.New("fxvpn: quota exceeded")
        ErrTokenInvalid   = errors.New("fxvpn: token invalid")
        ErrChallenge      = errors.New("fxvpn: fastly challenge failed")
        ErrNoServers      = errors.New("fxvpn: no server for location")
        ErrAccountInvalid = errors.New("fxvpn: account invalid")
        ErrExitMismatch   = errors.New("fxvpn: exit country mismatch")
)

// QuotaError reports Guardian HTTP 429. RetryAfter carries the parsed
// Retry-After header (GuardianClient.sys.mjs respects it next to X-Quota-*);
// HasRetryAfter distinguishes "header present, zero" from "header absent".
type QuotaError struct {
        RetryAfter    time.Duration
        HasRetryAfter bool
        Status        int
        Body          string
}

func (e *QuotaError) Error() string {
        if e.HasRetryAfter {
                return "quota exceeded (HTTP 429, retry-after " + e.RetryAfter.String() + "): " + e.Body
        }
        return "quota exceeded (HTTP 429): " + e.Body
}

// Unwrap makes errors.Is(err, ErrQuotaExceeded) work for classification.
func (e *QuotaError) Unwrap() error { return ErrQuotaExceeded }

// TokenInvalidError reports Guardian HTTP 401/403: the FxA access token was
// rejected (e.g. no active entitlement). The pool answers with refresh ->
// activate -> retry, then rotates the account.
type TokenInvalidError struct {
        Status int
        Body   string
}

func (e *TokenInvalidError) Error() string {
        return "token invalid (HTTP " + strconv.Itoa(e.Status) + "): " + e.Body
}

func (e *TokenInvalidError) Unwrap() error { return ErrTokenInvalid }

// GuardianHTTPError is any other non-2xx Guardian response.
type GuardianHTTPError struct {
        Operation string
        Status    int
        Body      string
}

func (e *GuardianHTTPError) Error() string {
        return e.Operation + ": HTTP " + strconv.Itoa(e.Status) + ": " + e.Body
}

// FxAError carries an FxA API errno so callers can branch (errno 107 =
// invalid parameter triggers the plain-login fallback in the reference
// client). Body is truncated upstream.
type FxAError struct {
        Operation string
        Status    int
        Errno     int
        Body      string
}

func (e *FxAError) Error() string {
        status := strconv.Itoa(e.Status)
        if e.Errno != 0 {
                return "fxa " + e.Operation + " (HTTP " + status + ", errno " + strconv.Itoa(e.Errno) + "): " + e.Body
        }
        return "fxa " + e.Operation + " (HTTP " + status + "): " + e.Body
}

// Classify maps a control-plane error onto its FailureClass constant.
// Unknown errors map to "" (caller decides; not all failures are classes).
func Classify(err error) string {
        switch {
        case errors.Is(err, ErrQuotaExceeded):
                return ClassQuotaExhausted
        case errors.Is(err, ErrTokenInvalid):
                return ClassAuthRejected
        case errors.Is(err, ErrPinMismatch):
                return ClassAPIPinMismatch
        case errors.Is(err, ErrChallenge):
                return ClassChallengeFailed
        case errors.Is(err, ErrNoServers):
                return ClassNoServerForLocation
        case errors.Is(err, ErrStoreCorrupt):
                return ClassAccountStoreCorrupt
        case errors.Is(err, ErrExitMismatch):
                return ClassExitMismatch
        default:
                return ""
        }
}
