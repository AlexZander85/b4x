package detector

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type FingerprintProfile string

const (
	FingerprintCanonical FingerprintProfile = "canonical"
	FingerprintBrowser   FingerprintProfile = "browser"
	FingerprintAndroid   FingerprintProfile = "android"
)

type HTTPMethod string

const (
	MethodGET  HTTPMethod = "GET"
	MethodHEAD HTTPMethod = "HEAD"
)

type DeadlineStages struct{ Connect, TLS, TTFB, InterChunk, Overall time.Duration }
type BodyProgressEvidence struct {
	UniqueBytes    uint64
	Chunks         uint32
	LastProgressAt time.Time
	StallDuration  time.Duration
	SuitableObject bool
	MediaProgress  bool
}

func (b BodyProgressEvidence) Valid() bool {
	return b.UniqueBytes > 0 && b.Chunks > 0 && !b.LastProgressAt.IsZero()
}

type ComponentMilestone string

const (
	MilestoneHeaders       ComponentMilestone = "headers"
	MilestoneBodyProgress  ComponentMilestone = "body-progress"
	MilestoneMediaProgress ComponentMilestone = "media-progress"
)

type TLSHTTPEvidence struct {
	Scope               monitor.MonitorScopeKey
	TargetID            string
	Fingerprint         FingerprintProfile
	Method              HTTPMethod
	VerifiedCertificate bool
	TLSVersion          string
	FailureCode         ProbeFailureCode
	Attribution         monitor.FailureAttribution
	Authority           monitor.EvidenceAuthority
	Stage               string
	StatusCode          int
	Milestone           ComponentMilestone
	Body                BodyProgressEvidence
	ObservedAt          time.Time
}

func (e TLSHTTPEvidence) Valid() bool {
	return e.Scope.Valid() && e.TargetID != "" && e.Fingerprint != "" && e.Method != "" && e.TLSVersion != "" && e.Authority != "" && !e.ObservedAt.IsZero()
}
func (e TLSHTTPEvidence) SupportsMITM() bool {
	return e.VerifiedCertificate && e.FailureCode == FailureTLSAlert && e.Authority == monitor.AuthorityAuthoritativeABD
}
func (e TLSHTTPEvidence) SupportsBodyBlock() bool {
	return e.Body.SuitableObject && e.Body.MediaProgress && e.Milestone == MilestoneMediaProgress && e.Body.Valid() && e.FailureCode == FailureBodyStall
}
func (e TLSHTTPEvidence) SupportsThrottling() bool {
	return e.Body.SuitableObject && e.Body.MediaProgress && e.Body.Valid() && e.Body.StallDuration > 0
}
func ValidateStageEvidence(local TLSHTTPEvidence, observer VantageObservation, now time.Time) error {
	if !local.Valid() {
		return errors.New("invalid TLS/HTTP evidence")
	}
	if observer.Available && observer.Stage != VantageStage(local.Stage) {
		return errors.New("observer stage mismatch")
	}
	if observer.Available && !observer.Capability.Fresh(now) {
		return errors.New("observer capability stale")
	}
	return nil
}
