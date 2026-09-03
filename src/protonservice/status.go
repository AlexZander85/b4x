// Status projection of the proton runtime (patch-plan §6.2): the honest
// running/listening split, the active profile/node/port view, the
// certificate timing, the profile issuance counters and the event tail.
// Everything leaving here is redacted-safe (no seed, no tokens).
package protonservice

import (
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/transport/proton"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// twgStateEstablished aliases the engine state (listening = established).
const twgStateEstablished = twg.StateEstablished

// FailureView is one classified failure for the status shape.
type FailureView struct {
	Class string `json:"class,omitempty"`
	At    string `json:"at,omitempty"`
}

// Status is the GET /api/proton/status payload.
type Status struct {
	Enabled       bool                  `json:"enabled"`
	Running       bool                  `json:"running"`
	Listening     bool                  `json:"listening"`
	State         string                `json:"state"`
	RestartCapHit bool                  `json:"restart_cap_hit"`
	Location      config.ProtonLocation `json:"location"`

	ActiveProfile string   `json:"active_profile,omitempty"`
	ActiveNode    string   `json:"active_node,omitempty"`
	ActivePort    uint16   `json:"active_port,omitempty"`
	VerifiedExit  ExitView `json:"verified_exit"`

	CertExpiresAt int64                   `json:"cert_expires_at,omitempty"`
	SessionAge    time.Duration           `json:"-"`
	Identity      proton.RedactedIdentity `json:"identity,omitempty"`

	ProfilesIssued int `json:"profiles_issued"`
	ProfilesLeft   int `json:"profiles_left"`

	LastFailure string         `json:"last_failure,omitempty"`
	Events      []proton.Event `json:"events,omitempty"`
}

// Status snapshots the runtime state (fxvpn parity: listening = a live
// session that reached established).
func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{
		Enabled:        r.cfg.Enabled,
		Running:        r.running && !r.stopped,
		State:          r.state,
		RestartCapHit:  !r.guard.allowed(),
		Location:       r.location,
		VerifiedExit:   r.exit,
		LastFailure:    r.lastFailure,
		Events:         append([]proton.Event(nil), r.events...),
		ProfilesIssued: len(r.profiles),
		ProfilesLeft:   len(r.profiles) - 1 - r.profIdx,
	}
	if st.ProfilesLeft < 0 {
		st.ProfilesLeft = 0
	}
	if s := r.sess; s != nil {
		st.Listening = s.State() == twgStateEstablished
	}
	if id := r.identity; id != nil {
		st.Identity = id.Redacted()
		st.CertExpiresAt = id.CertExpiresAt
		if idx := r.profIdx; idx >= 0 && idx < len(r.profiles) {
			p := r.profiles[idx]
			st.ActiveProfile = p.ProfileID
			st.ActiveNode = p.Node.Name
			st.ActivePort = p.Port
		}
	}
	return st
}

// sessionAge reports the wall time since the last established transition
// (0 when not established).
func (r *Runtime) sessionAge() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateEstablished {
		return 0
	}
	return r.now().Sub(r.stateSince)
}
