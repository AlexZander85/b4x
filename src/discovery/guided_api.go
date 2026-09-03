package discovery

import (
	"errors"
	"time"
)

type ProfileSelectionMode string

const (
	SelectionNone     ProfileSelectionMode = "none"
	SelectionAuto     ProfileSelectionMode = "auto"
	SelectionExplicit ProfileSelectionMode = "explicit"
)

type GuidedDiscoveryOptions struct {
	ProfileID    string
	Selection    ProfileSelectionMode
	UseHints     bool
	RequireFresh bool
	BaselineOnly bool
}

func DefaultGuidedOptions() GuidedDiscoveryOptions {
	return GuidedDiscoveryOptions{Selection: SelectionNone, UseHints: false, RequireFresh: true}
}

type DiscoveryRequest struct {
	Domains     []string
	Options     GuidedDiscoveryOptions
	RequestedAt time.Time
}
type DiscoveryPlanSnapshot struct {
	SnapshotID string
	Domains    []string
	Options    GuidedDiscoveryOptions
	Profile    NetworkDiagnosticProfile
	CreatedAt  time.Time
}

func BuildDiscoverySnapshot(req DiscoveryRequest, profile NetworkDiagnosticProfile, now time.Time) (DiscoveryPlanSnapshot, error) {
	if req.RequestedAt.IsZero() {
		req.RequestedAt = now
	}
	if req.Options.Selection == SelectionNone && req.Options.UseHints {
		return DiscoveryPlanSnapshot{}, errors.New("hints require profile selection")
	}
	if req.Options.RequireFresh && !profile.Valid(now) && req.Options.Selection != SelectionNone {
		return DiscoveryPlanSnapshot{}, errors.New("selected profile is stale")
	}
	return DiscoveryPlanSnapshot{SnapshotID: profile.ProfileID + "/" + now.UTC().Format("20060102T150405.000000000Z"), Domains: append([]string(nil), req.Domains...), Options: req.Options, Profile: profile, CreatedAt: now}, nil
}
