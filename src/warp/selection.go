package warp

import (
	"sort"
	"time"
)

// candidateSelectionTTL is the validity window of a least-invasive selection
// decision (SECT C.7 promotion hold). Normative source: addendum v1.2 §41
// success_hold_minimum: 120s / §53 stability_window: 120s.
const candidateSelectionTTL = 120 * time.Second

type Candidate struct {
	ID                                  string
	Invasive                            int
	Protocol, Router, Forwarded, Stable bool
	Generation                          uint64
}
type CandidateResult struct {
	CandidateID string
	Winner      bool
	Reason      string
	ExpiresAt   int64
}

func SelectLeastInvasive(cs []Candidate, now time.Time) CandidateResult {
	valid := make([]Candidate, 0, len(cs))
	for _, c := range cs {
		if c.ID != "" && c.Protocol && c.Router && c.Forwarded && c.Stable {
			valid = append(valid, c)
		}
	}
	if len(valid) == 0 {
		return CandidateResult{Reason: "no stable candidate", ExpiresAt: now.Add(candidateSelectionTTL).Unix()}
	}
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].Invasive != valid[j].Invasive {
			return valid[i].Invasive < valid[j].Invasive
		}
		return valid[i].ID < valid[j].ID
	})
	return CandidateResult{CandidateID: valid[0].ID, Winner: true, Reason: "least invasive stable candidate", ExpiresAt: now.Add(candidateSelectionTTL).Unix()}
}
