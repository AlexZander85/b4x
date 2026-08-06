// Production resource-ownership / cleanup / cutoff / non-RU hard-gate
// producers (SECT 73B ownership+cleanup block, addendum v1.2 sec. 62.5
// public-IP change, sec. 62.7 camouflage cutoff proof, sec. 62.8 resource
// ownership and cleanup proof).
//
// Like the other SECT 73B producers, the violating branches below are the
// production violation paths of the ownership/cutoff/non-RU lifecycle: a
// count != 0 in a validation window is a genuine WARP violation, not
// synthetic telemetry. The invariants enforced here are:
//
//   - strict non-RU revocation MUST start by the revocation deadline
//     (warp_nonru_revocation_exceeded_deadline_total);
//   - a public-IP change without a fresh attestation refresh keeps a strict
//     non-RU route unproven (warp_nonru_public_ip_change_without_refresh_total);
//   - a CONNECT-IP event claiming a generation different from the expected
//     process/config generation is invalid
//     (warp_connect_ip_event_wrong_generation_total);
//   - the sec. 62.7 invariant: CONNECT-IP confirmed -> camouflage cutoff ->
//     established bypass -> post_cutoff_mutations == 0
//     (warp_post_cutoff_mutation_total);
//   - cleanup is complete only when every generation-owned resource has a
//     terminal removal record or a verified already-absent record
//     (warp_cleanup_incomplete_total);
//   - a generation-owned resource without a terminal removal record at
//     finalize is a leak (warp_owned_resource_leak_total);
//   - a foreign resource must never receive a successful removed-by-b4
//     event (warp_foreign_resource_removed_total, sec. 62.8).
package warp

import (
	"errors"

	"github.com/daniellavrushin/b4/observability"
)

// NonRURevocationDeadline records the start of a strict non-RU route
// revocation. When a revocation deadline is set, revocation MUST have
// started by it; a deadline that passed with no revocation start (or a start
// after the deadline) is a violation
// (warp_nonru_revocation_exceeded_deadline_total).
func (rt *Runtime) NonRURevocationDeadline(t NonRURevocationTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if !t.RevocationDeadline.IsZero() &&
		(t.RevocationStartedAt.IsZero() || t.RevocationStartedAt.After(t.RevocationDeadline)) {
		observability.Default().Metrics.Inc(observability.MetricWarpNonRURevocationExceededDeadline, nil, 1)
		return errors.New("non-ru revocation exceeded deadline")
	}
	return nil
}

// NonRUPublicIPChange records a warp_geo_public_ip_changed event (sec. 62.5).
// The observed public IP differs from the previous one; the strict non-RU
// route stays proven only when a fresh attestation refresh was issued for
// the change. A change without refresh is a violation
// (warp_nonru_public_ip_change_without_refresh_total).
func (rt *Runtime) NonRUPublicIPChange(e PublicIPChangeEvent) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if e.ObservedIPHash != e.PreviousIPHash && !e.RefreshIssued {
		observability.Default().Metrics.Inc(observability.MetricWarpNonRUPublicIPChangeWithoutRefresh, nil, 1)
		return errors.New("non-ru public ip changed without attestation refresh")
	}
	return nil
}

// ConnectIPEvent records a CONNECT-IP request/result event. The event must
// claim the current process/config generation of the session; any event with
// a mismatching claimed generation is a violation
// (warp_connect_ip_event_wrong_generation_total).
func (rt *Runtime) ConnectIPEvent(t ConnectIPEventTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.EventProcessGeneration != t.ExpectedProcessGeneration ||
		t.EventConfigGeneration != t.ExpectedConfigGeneration {
		observability.Default().Metrics.Inc(observability.MetricWarpConnectIPEventWrongGeneration, nil, 1)
		return errors.New("connect-ip event with wrong generation")
	}
	return nil
}

// PostCutoffMutation records a camouflage cutoff trace (sec. 62.7). The hard
// invariant requires zero post-cutoff payload mutations once CONNECT-IP was
// confirmed, the camouflage cutoff was emitted and the established bypass
// was installed; any mutation after that is a violation
// (warp_post_cutoff_mutation_total).
func (rt *Runtime) PostCutoffMutation(t CamouflageTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if t.ConnectIPConfirmed && t.BypassEstablished && t.PostCutoffMutations > 0 {
		observability.Default().Metrics.Inc(observability.MetricWarpPostCutoffMutation, nil, 1)
		return errors.New("post-cutoff payload mutation after established bypass")
	}
	return nil
}

// CleanupComplete records a sec. 62.8 cleanup-completion claim. The claim is
// complete only when every generation-owned resource has a terminal removal
// record or a verified already-absent record; a completed claim over
// resources still without a terminal record is a violation
// (warp_cleanup_incomplete_total).
func (rt *Runtime) CleanupComplete(r CleanupReport) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if r.Completed {
		for _, res := range r.Resources {
			if !res.Foreign && !terminalRemoveResult(res.RemoveResult) {
				observability.Default().Metrics.Inc(observability.MetricWarpCleanupIncomplete, nil, 1)
				return errors.New("cleanup incomplete: owned resource without terminal removal record")
			}
		}
	}
	return nil
}

// OwnedResourceLeak records a generation-owned resource at finalize. A
// generation-owned resource without a terminal removal record or a verified
// already-absent record is a leak (warp_owned_resource_leak_total, sec.
// 62.8).
func (rt *Runtime) OwnedResourceLeak(res OwnedResourceTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if !res.Foreign && !terminalRemoveResult(res.RemoveResult) {
		observability.Default().Metrics.Inc(observability.MetricWarpOwnedResourceLeak, nil, 1)
		return errors.New("generation-owned resource leaked without terminal removal record")
	}
	return nil
}

// ForeignResourceRemoved records a removal event over a foreign resource
// (sec. 62.8). A foreign resource MUST never receive a successful
// removed-by-b4 event; any such event is a violation
// (warp_foreign_resource_removed_total).
func (rt *Runtime) ForeignResourceRemoved(res OwnedResourceTrace) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if res.Foreign && res.RemoveResult == "removed-by-b4" {
		observability.Default().Metrics.Inc(observability.MetricWarpForeignResourceRemoved, nil, 1)
		return errors.New("foreign resource received successful removed-by-b4 event")
	}
	return nil
}
