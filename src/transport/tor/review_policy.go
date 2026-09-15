package tor

// ClassPTRendezvous is an ACTIVE pluggable-transport rendezvous leg
// (Snowflake broker/front). Unlike bootstrap-source, it must honor a pinned
// egress carrier: operator-selected `through=<kind>` is a strict no-direct
// contract, not an availability hint.
const ClassPTRendezvous ConnClass = "pt-rendezvous"

// IsPinnedCarrierPolicy reports whether direct network access is forbidden
// by the configured egress policy. "none" explicitly permits direct and
// "auto" is the availability profile; every named carrier is strict.
func IsPinnedCarrierPolicy(through string) bool {
	switch through {
	case "", "none", "auto":
		return false
	default:
		return true
	}
}
