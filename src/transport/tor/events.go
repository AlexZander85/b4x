// Package tor is the E-TOR control plane (design tor-reserve-design.md):
// bridge parsing and storage, the collection conveyor, the egress dialer
// and loopback bridges, the in-process pluggable-transport proxy, the
// torrc renderer, the minimal control client and the process/bootstrap
// supervision primitives. The service assembly lives in src/torservice.
package tor

import "time"

const (
	EventTorStarted                 = "tor_started"
	EventTorBinaryMissing           = "tor_binary_missing"
	EventTorBootstrapProgress       = "tor_bootstrap_progress"
	EventTorEstablished             = "tor_established"
	EventTorEntryWon                = "tor_entry_won"
	EventTorEntryFailed             = "tor_entry_failed"
	EventTorEntryAttributionUnknown = "tor_entry_attribution_unknown"
	EventTorRotated                 = "tor_rotated"
	EventTorBridgeStrike            = "tor_bridge_strike"
	EventTorCarrierSwitched         = "tor_carrier_switched"
	EventTorCarrierUnsupported      = "tor_carrier_unsupported"
	EventTorExitVerified            = "tor_exit_verified"
	EventTorExitMismatch            = "tor_exit_mismatch"
	EventTorProcessDied             = "tor_process_died"
	EventTorConfluxEnabled          = "tor_conflux_enabled"
	EventTorConfluxUnavailable      = "tor_conflux_unavailable"
	EventTorResourceWarning         = "tor_resource_warning"
	EventTorBaitActive              = "tor_bait_active"
	EventTorBaitInactive            = "tor_bait_inactive"
)

const (
	ClassTorBinaryMissing   = "tor-binary-missing"
	ClassTorNoBridges       = "tor-no-bridges"
	ClassTorBridgeDead      = "tor-bridge-dead"
	ClassTorEntryFailed     = "tor-entry-failed"
	ClassTorBootstrapStall  = "tor-bootstrap-stall"
	ClassTorBootstrapSilent = "tor-bootstrap-silent"
	ClassTorLivenessFailed  = "tor-liveness-failed"
	ClassTorCarrierDead     = "tor-carrier-dead"
	ClassTorCarrierPolicy   = "tor-carrier-policy"
	ClassTorExitMismatch    = "tor-exit-mismatch"
	ClassTorProcessDied     = "tor-process-died"
	ClassTorControlError    = "tor-control-error"
	ClassTorSelfLoop        = "tor-self-loop"
	ClassTorConfigInvalid   = "tor-config-invalid"
	ClassTorResourceLimit   = "tor-resource-limit"
)

type TorEvent struct {
	Name   string    `json:"name"`
	Class  string    `json:"class,omitempty"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at,omitempty"`
}

const EventsRingCap = 32
