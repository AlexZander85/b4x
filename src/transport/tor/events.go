// Package tor is the E-TOR control plane (design tor-reserve-design.md):
// bridge parsing and storage, the collection conveyor, the egress dialer
// and loopback bridges, the in-process pluggable-transport proxy, the
// torrc renderer, the minimal control client and the process/bootstrap
// supervision primitives. The service assembly lives in src/torservice.
//
// Taxonomy canon (design §9.7, program-wide rule): event names are
// snake_case, event classes are kebab-case, metrics carry the tor_ prefix
// (names live in src/observability/tor.go). Every event ring is bounded.
package tor

import "time"

// Event names (snake_case) — the supervisor ring vocabulary.
const (
	EventTorStarted            = "tor_started"
	EventTorBinaryMissing      = "tor_binary_missing"
	EventTorBootstrapProgress  = "tor_bootstrap_progress"
	EventTorEstablished        = "tor_established"
	EventTorEntryWon           = "tor_entry_won"
	EventTorEntryFailed        = "tor_entry_failed"
	EventTorRotated            = "tor_rotated"
	EventTorBridgeStrike       = "tor_bridge_strike"
	EventTorCarrierSwitched    = "tor_carrier_switched"
	EventTorExitVerified       = "tor_exit_verified"
	EventTorExitMismatch       = "tor_exit_mismatch"
	EventTorProcessDied        = "tor_process_died"
	EventTorConfluxEnabled     = "tor_conflux_enabled"
	EventTorConfluxUnavailable = "tor_conflux_unavailable"
	EventTorBaitActive         = "tor_bait_active"
	EventTorBaitInactive       = "tor_bait_inactive"
)

// Event classes (kebab-case) — the failure taxonomy for status projection
// and event filtering. A class groups a family of events by cause: the
// name says what happened, the class says why it matters.
const (
	ClassTorBinaryMissing   = "tor-binary-missing"
	ClassTorNoBridges       = "tor-no-bridges"
	ClassTorBridgeDead      = "tor-bridge-dead"
	ClassTorEntryFailed     = "tor-entry-failed"
	ClassTorBootstrapStall  = "tor-bootstrap-stall"
	ClassTorBootstrapSilent = "tor-bootstrap-silent"
	ClassTorLivenessFailed  = "tor-liveness-failed"
	ClassTorCarrierDead     = "tor-carrier-dead"
	ClassTorExitMismatch    = "tor-exit-mismatch"
	ClassTorProcessDied     = "tor-process-died"
	ClassTorControlError    = "tor-control-error"
	ClassTorSelfLoop        = "tor-self-loop"
	ClassTorConfigInvalid   = "tor-config-invalid"
)

// TorEvent is one taxonomy trace point (the shape mirrors proton.Event /
// fxvpn.PoolEvent — the program canon). Detail carries only redacted-safe
// material: transport names, counts and states, never client IPs
// (SafeLogging 1 in tor, no client IPs in our events either).
type TorEvent struct {
	Name   string    `json:"name"`
	Class  string    `json:"class,omitempty"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at,omitempty"`
}

// EventsRingCap bounds the per-runtime event ring (canon: 32).
const EventsRingCap = 32
