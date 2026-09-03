package discovery

import "time"

type ProfileBadge string

const (
	BadgeFresh       ProfileBadge = "fresh"
	BadgeStale       ProfileBadge = "stale"
	BadgeSuppressed  ProfileBadge = "suppressed"
	BadgeUnavailable ProfileBadge = "unavailable"
)

type ProfileSelectorView struct {
	ProfileID         string
	Badge             ProfileBadge
	ExpiresAt         time.Time
	CompatibilityHash string
	Explanation       string
}

func ProfileView(p NetworkDiagnosticProfile, now time.Time, suppressed bool) ProfileSelectorView {
	v := ProfileSelectorView{ProfileID: p.ProfileID, ExpiresAt: p.ExpiresAt}
	if suppressed {
		v.Badge = BadgeSuppressed
		v.Explanation = "profile hint suppressed by context or capture gate"
	} else if p.Valid(now) {
		v.Badge = BadgeFresh
		v.Explanation = "profile applied as search prior only"
	} else {
		v.Badge = BadgeStale
		v.Explanation = "profile requires revalidation"
	}
	return v
}

type DiscoveryEvent struct {
	Event     string
	ProfileID string
	Applied   bool
	Reason    string
	At        time.Time
}
type SearchSavingsReport struct {
	ProfileID                        string
	BaselineProbes, GuidedProbes     int
	SavedProbes                      int
	BaselineDuration, GuidedDuration time.Duration
	FallbackUsed                     bool
}

func (r SearchSavingsReport) Valid() bool {
	return r.BaselineProbes >= 0 && r.GuidedProbes >= 0 && r.SavedProbes == r.BaselineProbes-r.GuidedProbes && r.GuidedProbes <= r.BaselineProbes
}
