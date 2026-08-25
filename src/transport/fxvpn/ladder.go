// Instance-level carrier ladder H3 -> H2 for one fxvpn session (mechanics
// from E-H3 EH3, owner-approved reuse): prefer H3 when configured; fall back
// to H2 of the SAME node ONLY on confirmed transport-dead classes
// (udp-egress-blocked / h3-negotiation-failed). Every switch is observable;
// while blocked, dials go to H2 silently - zero H3 contacts, zero
// oscillation. H3 returns only after the cooldown expires. Account-level
// verdicts (CONNECT rejected / wrong bearer / 429) are deliberately NOT
// switch classes: they belong to the account pool, not the carrier.
package fxvpn

import (
	"errors"
	"sync"
	"time"
)

const DefaultH3ReturnCooldown = 300 * time.Second

// LadderConfig tunes the ladder. Zero values fall back to defaults.
type LadderConfig struct {
	PreferH3         bool
	H3ReturnCooldown time.Duration
	Now              func() time.Time // injectable clock for tests
}

// Ladder picks and tracks the carrier for one node session.
type Ladder struct {
	mu       sync.Mutex
	preferH3 bool
	cooldown time.Duration
	now      func() time.Time

	h3BlockedUntil time.Time
	switches       int
}

// NewLadder builds a ladder; cooldown <=0 takes DefaultH3ReturnCooldown.
func NewLadder(cfg LadderConfig) *Ladder {
	if cfg.H3ReturnCooldown <= 0 {
		cfg.H3ReturnCooldown = DefaultH3ReturnCooldown
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Ladder{preferH3: cfg.PreferH3, cooldown: cfg.H3ReturnCooldown, now: cfg.Now}
}

// Preferred reports which carrier the next dial must use.
func (l *Ladder) Preferred() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.preferH3 && !l.now().Before(l.h3BlockedUntil) {
		return CarrierH3
	}
	return CarrierH2
}

// ObserveDialFailure feeds a Dial outcome for carrier. It returns the
// carrier to switch to ("") when none applies, plus whether an observable
// switch happened. Only confirmed classes switch; failures INSIDE an active
// cooldown block are absorbed silently (anti-oscillation: one episode, one
// switch).
func (l *Ladder) ObserveDialFailure(carrier string, err error) (switchTo string, switched bool) {
	if err == nil || carrier != CarrierH3 {
		return "", false
	}
	class := ClassifyDialError(err)
	if class != "udp-egress-blocked" && class != "h3-negotiation-failed" {
		return "", false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Before(l.h3BlockedUntil) {
		return "", false // already switched for this episode
	}
	l.h3BlockedUntil = now.Add(l.cooldown)
	l.switches++
	if l.preferH3 {
		return CarrierH2, true
	}
	return "", false
}

// ObserveDialSuccess keeps the preference as-is (success sticks).
func (l *Ladder) ObserveDialSuccess(carrier string) {}

// Switches counts observable carrier switches so far.
func (l *Ladder) Switches() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.switches
}

// H3Allowed reports whether H3 is currently allowed (status/metrics view).
func (l *Ladder) H3Allowed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.now().Before(l.h3BlockedUntil)
}

// ClassifyDialError maps a session-dial error onto its stable class string
// ("" when unclassified). It unwraps the typed wrappers raised by DialH3 and
// the H2 negotiation sentinel.
func ClassifyDialError(err error) string {
	switch {
	case errors.Is(err, errUDPEgressBlocked):
		return "udp-egress-blocked"
	case errors.Is(err, errH3NegotiationFailed):
		return "h3-negotiation-failed"
	case errors.Is(err, errH2Unavailable):
		return "h2-unavailable"
	default:
		return ""
	}
}
