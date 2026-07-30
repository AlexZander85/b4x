package silentpath

import "time"

type ProbeResult struct {
	Path                             string
	ReachedMilestone, ControlHealthy bool
	CompletedAt                      time.Time
}
type DifferentialReport struct {
	Current, Candidate, Control ProbeResult
	Confirmed                   bool
	Reason                      string
}

func ComparePaths(current, candidate, control ProbeResult) DifferentialReport {
	r := DifferentialReport{Current: current, Candidate: candidate, Control: control}
	if !control.ReachedMilestone || !control.ControlHealthy {
		r.Reason = "control_unhealthy"
		return r
	}
	if current.ReachedMilestone {
		r.Reason = "current_path_healthy"
		return r
	}
	if !candidate.ReachedMilestone {
		r.Reason = "candidate_failed"
		return r
	}
	r.Confirmed = true
	r.Reason = "candidate_differential_success"
	return r
}
