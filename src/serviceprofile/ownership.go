package serviceprofile

import "time"

type Ownership string

const (
	Manual  Ownership = "manual"
	Managed Ownership = "managed"
)

type OverrideState string

const (
	NoOverride OverrideState = "none"
	Pinned     OverrideState = "pinned"
	Excluded   OverrideState = "excluded"
	Overridden OverrideState = "overridden"
)

type OwnershipMeta struct {
	Ownership   Ownership     `json:"ownership"`
	ProfileID   string        `json:"profile_id,omitempty"`
	ComponentID string        `json:"component_id,omitempty"`
	Version     string        `json:"version,omitempty"`
	Override    OverrideState `json:"override"`
	Pinned      bool          `json:"pinned"`
	Excluded    bool          `json:"excluded"`
	Provenance  string        `json:"provenance,omitempty"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// MigrateOwnership deliberately keeps existing objects manual. A profile must
// opt an object into management explicitly during compilation.
func MigrateOwnership(existing *OwnershipMeta, now time.Time) OwnershipMeta {
	if existing == nil {
		return OwnershipMeta{Ownership: Manual, Override: NoOverride, UpdatedAt: now}
	}
	o := *existing
	if o.Ownership == "" {
		o.Ownership = Manual
	}
	if o.Override == "" {
		o.Override = NoOverride
	}
	if o.UpdatedAt.IsZero() {
		o.UpdatedAt = now
	}
	return o
}

func (o OwnershipMeta) CanReplace() bool {
	return o.Ownership == Managed && !o.Pinned && !o.Excluded && o.Override != Pinned && o.Override != Excluded
}
