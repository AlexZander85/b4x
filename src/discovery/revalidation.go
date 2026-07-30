package discovery

import (
	"errors"
	"time"
)

type RevalidationStatus string

const (
	RevalidationPending  RevalidationStatus = "pending"
	RevalidationRunning  RevalidationStatus = "running"
	RevalidationFresh    RevalidationStatus = "fresh"
	RevalidationConflict RevalidationStatus = "conflict"
	RevalidationExpired  RevalidationStatus = "expired"
)

type RevalidationProbe struct {
	Kind, Target string
	Budget       int
	NoSideEffect bool
}
type RevalidationPlan struct {
	ProfileID   string
	Probes      []RevalidationProbe
	Deadline    time.Time
	Status      RevalidationStatus
	Explanation string
}

func BuildRevalidationPlan(p NetworkDiagnosticProfile, now time.Time) (RevalidationPlan, error) {
	if !p.Valid(now) {
		return RevalidationPlan{}, errors.New("profile is stale or invalid")
	}
	return RevalidationPlan{ProfileID: p.ProfileID, Probes: []RevalidationProbe{{Kind: "dns-consensus", Target: p.ProfileID, Budget: 1, NoSideEffect: true}, {Kind: "target-http", Target: p.ProfileID, Budget: 2, NoSideEffect: true}}, Deadline: now.Add(30 * time.Second), Status: RevalidationPending, Explanation: "bounded read-only revalidation"}, nil
}
func ResolveRevalidation(p RevalidationPlan, profileHash, currentHash string, now time.Time) RevalidationPlan {
	if !now.Before(p.Deadline) {
		p.Status = RevalidationExpired
		p.Explanation = "revalidation deadline expired"
	} else if profileHash != currentHash {
		p.Status = RevalidationConflict
		p.Explanation = "current evidence conflicts with stored profile"
	} else {
		p.Status = RevalidationFresh
		p.Explanation = "profile revalidated without side effects"
	}
	return p
}
