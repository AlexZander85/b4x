// Structural failure taxonomy for the WG/AWG layer (design §8). Every
// outcome carries a machine-readable class so downstream consumers
// (seek-ladder, supervisor, trace pipeline) never parse strings. The class
// set continues the MASQUE taxonomy §62 with the wg_/awg_ prefixes agreed
// in the design.
package transportwg

import (
	"errors"
	"fmt"
)

// FailureClass enumerates the structural outcomes of this transport.
type FailureClass string

const (
	// ClassHandshakeTimeout: endpoint never completed a Noise handshake
	// within the health budget (endpoint down / filtered / wrong port).
	ClassHandshakeTimeout FailureClass = "wg-handshake-timeout"
	// ClassStallRX: handshake (or established session) stopped producing
	// authenticated inbound traffic — silent DPI drop family.
	ClassStallRX FailureClass = "wg-stall-rx"
	// ClassVersionMismatch: handshake completes but the AWG parameter sets
	// disagree — the "92B received / 20 KB sent" signature family.
	ClassVersionMismatch FailureClass = "awg-version-mismatch"
	// ClassParamRejected: the daemon rejected the rendered IPC config
	// (validator bypassed it or upstream changed validation).
	ClassParamRejected FailureClass = "awg-param-rejected"
	// ClassJunkProfileFailed: junk/obfuscation profile could not be applied
	// at all (chain render or daemon acceptance failed).
	ClassJunkProfileFailed FailureClass = "awg-junk-profile-failed"
	// ClassReservedInvalid: reserved-byte discipline violated (hook absent
	// for a cf_warp identity, or client_id undecodable).
	ClassReservedInvalid FailureClass = "reserved-bytes-invalid"
	// ClassRestartCapExhausted: the restart budget (design §10 cap) ran
	// out — a TERMINAL session outcome. Structurally distinct from rx-stall
	// so consumers/metrics never conflate storm-stop with a live stall.
	ClassRestartCapExhausted FailureClass = "restart-cap-exhausted"
)

// Failure is a structured outcome. It implements error so it can travel
// through ordinary error paths while staying switchable by class.
type Failure struct {
	Class  FailureClass
	Reason string
	Err    error
}

func (f *Failure) Error() string {
	if f.Err != nil {
		return fmt.Sprintf("transportwg: %s: %s: %v", f.Class, f.Reason, f.Err)
	}
	return fmt.Sprintf("transportwg: %s: %s", f.Class, f.Reason)
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
