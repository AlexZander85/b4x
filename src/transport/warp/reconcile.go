// Identity reconciliation (design §5): the single decision point deciding,
// for the current local identity, between KEEP / RENEW / REPROVISION /
// STAY-BLOCKED, with rate-limit discipline enforced by persistent cooldown
// stamps.
//
// Decision table (refuse-vs-throttle, Aether account.rs + z2k lessons):
//
//	store absent/corrupt            -> enroll (provision)
//	account revalidation 200        -> keep; renew only inside RenewWindow
//	                                   (keep-old-on-failure)
//	revalidation 401/404/410        -> identity dead -> re-enroll
//	revalidation 403/429/5xx/net    -> keep identity, NEVER re-register,
//	                                   stamp cooldown
//
// Stamp discipline (z2k #8): an intent stamp is written BEFORE any enrollment
// attempt; if stamps cannot be written, no attempt happens; a stamp from the
// future (skewed clock) is reset rather than honored. Registrations are
// strictly sequential (single mutex); minimum interval between attempts is
// DefaultMinEnrollInterval (z2k reg-cooldown 600s).
package transportwarp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultMinEnrollInterval is the flat cooldown between enrollment
	// transactions regardless of outcome (z2k install/reg 600s).
	DefaultMinEnrollInterval = 600 * time.Second
	// DefaultRenewWindow starts renewal this long before ExpiresAt
	// (Aether: 7 days).
	DefaultRenewWindow = 7 * 24 * time.Hour
	// maxFutureStamp is the skew guard: a NextAllowed further ahead than
	// this is treated as clock corruption and reset.
	maxFutureStamp = 24 * time.Hour
)

// FailureClass values emitted in EnsureResult (§62.1-style structural codes).
const (
	ClassIdentityRefused    = "identity-refused"
	ClassIdentityThrottled  = "identity-throttled"
	ClassEnrollmentNetwork  = "enrollment-network"
	ClassEnrollmentInvalidK = "enrollment-invalid-key"
	ClassEnrollmentRequest  = "enrollment-request-error"
	ClassEnrollmentCooldown = "enrollment-cooldown"
)

// EnsureAction summarizes what Ensure did.
type EnsureAction string

const (
	ActionProvisioned     EnsureAction = "provisioned"       // fresh identity committed
	ActionRenewed         EnsureAction = "renewed"           // renewal transaction committed
	ActionKeptValid       EnsureAction = "kept-valid"        // remote validation passed
	ActionBlockedThrottle EnsureAction = "blocked-throttled" // API said no: kept old, no enroll
	ActionBlockedCooldown EnsureAction = "blocked-cooldown"  // stamp window active, zero requests
)

// EnsureResult is the structured outcome for supervisor traces (E3).
type EnsureResult struct {
	Action        EnsureAction
	Identity      *Identity // current committed identity; nil when none exists and enrolling was blocked
	FailureClass  string    // "" when Action is Provisioned/Renewed/KeptValid
	ThrottleUntil time.Time
	Quarantined   bool
}

// Reconciler coordinates identity state against the registration API.
type Reconciler struct {
	API   *EnrollClient
	Store *IdentityStore
	// StatePath persists cooldown stamps; default Store.Path + ".state".
	StatePath string

	MinEnrollInterval time.Duration
	RenewWindow       time.Duration
	Now               func() time.Time

	mu sync.Mutex // registrations are strictly sequential
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) minInterval() time.Duration {
	if r.MinEnrollInterval > 0 {
		return r.MinEnrollInterval
	}
	return DefaultMinEnrollInterval
}

func (r *Reconciler) renewWindow() time.Duration {
	if r.RenewWindow > 0 {
		return r.RenewWindow
	}
	return DefaultRenewWindow
}

func (r *Reconciler) statePath() string {
	if r.StatePath != "" {
		return r.StatePath
	}
	return r.Store.Path + ".state"
}

// enrollState is the persisted cooldown stamp set.
type enrollState struct {
	LastAttempt          time.Time `json:"last_attempt,omitempty"`
	NextAllowed          time.Time `json:"next_allowed,omitempty"`
	ConsecutiveThrottles int       `json:"consecutive_throttles,omitempty"`
}

// Ensure brings identity to its best reachable state under current API
// verdicts. It never performs live requests when a valid cooldown stamp
// forbids them, and it never deletes or overwrites the committed identity
// before a candidate has fully validated (transaction semantics).
func (r *Reconciler) Ensure(ctx context.Context) (EnsureResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	res := EnsureResult{}
	ident, err := r.Store.Load()
	switch {
	case err == nil:
	case errors.Is(err, ErrIdentityAbsent):
		ident = nil
	case errors.Is(err, ErrIdentityCorrupt):
		res.Quarantined = true
		ident = nil
	default:
		return res, err
	}

	now := r.now()
	if ident != nil {
		acct, outcome, ferr := r.API.RevalidateAccount(ctx, ident.ID, ident.Token)
		switch outcome {
		case OutcomeOK:
			_ = acct // account fields refresh opportunistically at renewal
			if !ident.NeedsRenewal(now, r.renewWindow()) {
				res.Action = ActionKeptValid
				res.Identity = ident
				return res, nil
			}
			return r.enroll(ctx, ident, now, res)
		case OutcomeRefused:
			// Dead identity: drop the reference (no renewal semantics, no
			// pointless DELETE of a device the API already refuses) and
			// fall through to plain reprovision.
			ident = nil
		default:
			// Throttled / network / request error on a LIVE identity:
			// never reprovision; stamp cooldown so supervisors cannot hammer.
			until := now.Add(r.minInterval())
			if ferr != nil {
				var hf *HTTPFailure
				if errors.As(ferr, &hf) && hf.RetryAfter > 0 && hf.RetryAfter > r.minInterval() {
					until = now.Add(hf.RetryAfter)
				}
			}
			st := r.loadState(now)
			st.ConsecutiveThrottles++
			st.LastAttempt = now
			st.NextAllowed = until
			if serr := r.saveState(st); serr != nil {
				return res, fmt.Errorf("cooldown stamp unwritable: %w", serr)
			}
			res.Action = ActionBlockedThrottle
			res.Identity = ident
			res.ThrottleUntil = until
			res.FailureClass = ClassIdentityThrottled
			if outcome == OutcomeNetwork || outcome == OutcomeInvalidKey || outcome == OutcomeRequestError {
				res.FailureClass = ClassEnrollmentNetwork
				if outcome == OutcomeInvalidKey {
					res.FailureClass = ClassEnrollmentInvalidK
				} else if outcome == OutcomeRequestError {
					res.FailureClass = ClassEnrollmentRequest
				}
			}
			return res, nil
		}
	}
	return r.enroll(ctx, ident, now, res)
}

// enroll runs one guarded enrollment transaction (provision or renewal).
// prev != nil marks a renewal of a live identity (commit-or-keep-old plus
// best-effort deletion of the replaced device).
func (r *Reconciler) enroll(ctx context.Context, prev *Identity, now time.Time, res EnsureResult) (EnsureResult, error) {
	st := r.loadState(now)
	if st.NextAllowed.After(now.Add(maxFutureStamp)) {
		// Stamp from the future: clock skewed; drop it instead of freezing.
		st = enrollState{}
	}
	if st.NextAllowed.After(now) {
		res.Action = ActionBlockedCooldown
		res.Identity = prev
		res.ThrottleUntil = st.NextAllowed
		res.FailureClass = ClassEnrollmentCooldown
		return res, nil
	}
	// Intent stamp BEFORE acting: unwriteable stamp means "do not do it".
	st.LastAttempt = now
	st.NextAllowed = now.Add(r.minInterval())
	if err := r.saveState(st); err != nil {
		return res, fmt.Errorf("intent stamp unwritable: %w", err)
	}

	cand, outcome, ferr := r.API.Enroll(ctx)
	if cand == nil {
		if ferr == nil { // defensive: Enroll always reports one of the two
			ferr = errors.New("enrollment failed without diagnostic")
		}
		var hf *HTTPFailure
		if outcome == OutcomeThrottled && errors.As(ferr, &hf) && hf.RetryAfter > r.minInterval() {
			st.NextAllowed = now.Add(hf.RetryAfter) // respect server hint (already capped)
		}
		st.ConsecutiveThrottles++
		if serr := r.saveState(st); serr != nil {
			return res, fmt.Errorf("cooldown stamp unwritable: %w", serr)
		}
		res.Action = ActionBlockedThrottle
		res.Identity = prev
		res.ThrottleUntil = st.NextAllowed
		res.FailureClass = classFor(outcome)
		return res, ferr
	}

	if err := r.Store.Save(cand); err != nil {
		// Candidate exists remotely but is not committed locally; next run
		// will enroll again after cooldown (documented orphan risk bounded
		// by MinEnrollInterval; cleanup of remote orphans is E3 scope).
		return res, fmt.Errorf("commit candidate: %w", err)
	}
	st.ConsecutiveThrottles = 0
	if err := r.saveState(st); err != nil {
		return res, err
	}

	if prev != nil {
		// Renewal replaced a LIVE device: free the license slot best-effort.
		// Failure is non-fatal (slot pressure, not correctness).
		_ = r.API.Delete(ctx, prev.ID, prev.Token)
		res.Action = ActionRenewed
	} else {
		res.Action = ActionProvisioned
	}
	res.Identity = cand
	return res, nil
}

func classFor(o Outcome) string {
	switch o {
	case OutcomeRefused:
		return ClassIdentityRefused
	case OutcomeThrottled:
		return ClassIdentityThrottled
	case OutcomeNetwork:
		return ClassEnrollmentNetwork
	case OutcomeInvalidKey:
		return ClassEnrollmentInvalidK
	default:
		return ClassEnrollmentRequest
	}
}

func (r *Reconciler) loadState(now time.Time) enrollState {
	blob, err := os.ReadFile(r.statePath())
	if err != nil {
		// Absent OR unreadable: start from empty. Availability-first is safe
		// here because every action still requires writing an intent stamp,
		// which surfaces an unwritable environment before any network call.
		return enrollState{}
	}
	var st enrollState
	if json.Unmarshal(blob, &st) != nil {
		return enrollState{} // corrupt guard file loses to availability
	}
	if st.NextAllowed.After(now.Add(maxFutureStamp)) {
		st.NextAllowed = time.Time{} // future stamp: reset (clock skew rule)
	}
	return st
}

func (r *Reconciler) saveState(st enrollState) error {
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(r.statePath())
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := writeSecretFile(tmp, blob); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, r.statePath()); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
