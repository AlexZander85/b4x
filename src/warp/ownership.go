// Clean resource-ownership and cleanup-proof types (addendum v1.2 §62.5
// public-IP change, §62.7 camouflage cutoff proof, §62.8 resource ownership
// and cleanup proof). These are pure primitives; the violating-branch
// producers live in ownership_runtime.go.
package warp

import "time"

// OwnedResourceTrace is the §62.8 ownership record of a tracked resource
// (process-group, control-socket, TUN, NDM object, route rule, routing table,
// mark allocation, destination set, NAT rule, MSS rule, network namespace,
// veth pair, inner listener, bypass token, camouflage token, attestation
// lease). Cleanup is complete only when all generation-owned resources have
// terminal removal records or an explicit verified already-absent record.
// A foreign resource MUST never receive a successful removed-by-b4 event.
type OwnedResourceTrace struct {
	ResourceType       string
	ResourceHash       string
	OwnerInstanceID    string
	OwnerSessionGen    uint64
	CreatedByConfigGen uint64

	Foreign      bool
	CreateResult string
	RemoveResult string
}

// terminalRemoveResult reports whether a removal record is terminal for
// ownership tracking (§62.8): a successful removed-by-b4, a failed removal
// attempt, or an explicit verified already-absent record.
func terminalRemoveResult(result string) bool {
	switch result {
	case "removed-by-b4", "remove-failed", "already-absent":
		return true
	}
	return false
}

// CleanupReport is the §62.8 cleanup-completion claim for one session
// generation. The claim is complete only when every generation-owned
// resource has a terminal removal record or a verified already-absent
// record.
type CleanupReport struct {
	SessionGen uint64
	Resources  []OwnedResourceTrace
	Completed  bool
}

// CamouflageTrace is the §62.7 camouflage/cutoff trace. The hard invariant:
// CONNECT-IP confirmed -> camouflage cutoff emitted -> established bypass
// installed -> post_cutoff_mutations == 0. Any post-cutoff payload mutation
// after an established bypass is a violation.
type CamouflageTrace struct {
	PolicyID     string
	CandidateID  string
	CandidateGen uint64

	ConnectIPConfirmed bool
	CutoffSource       string
	CutoffAtSequence   uint64
	BypassEstablished  bool

	PostCutoffPacketsObserved uint64
	PostCutoffMutations       uint64
}

// PublicIPChangeEvent is the §62.5 warp_geo_public_ip_changed event. A
// public-IP change MUST be followed by a fresh attestation refresh before
// the strict non-RU route may stay active; a change with no refresh issued is
// a violation (warp_nonru_public_ip_change_without_refresh_total).
type PublicIPChangeEvent struct {
	AttestationID  string
	PreviousIPHash string
	ObservedIPHash string
	RefreshIssued  bool
}

// NonRURevocationTrace is the §62.5 prompt-revocation deadline record of a
// strict non-RU route. Revocation MUST start no later than the revocation
// deadline (gate-close reasons: provider-ru, provider-disagreement,
// attestation-stale, public-ip-changed, parent-reconnected, dns-path-failed,
// ipv6-path-failed, direct-wan-observed, inner-path-lost,
// target-service-geo-failed, manual-disable, config-generation-change).
type NonRURevocationTrace struct {
	AttestationID       string
	RevocationStartedAt time.Time
	RevocationDeadline  time.Time
}

// ConnectIPEventTrace is a CONNECT-IP request/result event with the
// generations it claims. An event whose claimed generation does not match
// the expected process/config generation of the session is a violation
// (warp_connect_ip_event_wrong_generation_total).
type ConnectIPEventTrace struct {
	InstanceID string
	SessionID  string

	EventProcessGeneration uint64
	EventConfigGeneration  uint64

	ExpectedProcessGeneration uint64
	ExpectedConfigGeneration  uint64
}
