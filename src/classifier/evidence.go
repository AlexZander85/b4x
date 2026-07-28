package classifier

import (
	"sort"
	"strings"
	"time"
)

func EffectiveConfidence(e Evidence) uint8 {
	cap := sourceConfidenceCap(e.Source)
	confidence := e.Confidence
	if confidence == 0 {
		confidence = sourceDefaultConfidence(e.Source)
	}
	if confidence > cap {
		return cap
	}
	return confidence
}

func NormalizeEvidence(e Evidence) Evidence {
	e.Domain = strings.ToLower(strings.TrimSpace(e.Domain))
	e.SetID = strings.TrimSpace(e.SetID)
	e.Confidence = EffectiveConfidence(e)
	return e
}

func IsFresh(e Evidence, now time.Time) bool {
	if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
		return false
	}
	return e.CreatedAt.IsZero() || !e.CreatedAt.After(now)
}

func ValidForContext(e Evidence, ctx DecisionContext) bool {
	if strings.TrimSpace(e.SetID) == "" {
		return false
	}
	if !IsFresh(e, ctx.Now) {
		return false
	}
	if ctx.ConfigGen != 0 && e.ConfigGen != 0 && e.ConfigGen != ctx.ConfigGen {
		return false
	}
	if ctx.DestinationPort != 0 && e.DestinationPort != 0 && ctx.DestinationPort != e.DestinationPort {
		return false
	}
	if ctx.L4Proto != 0 && e.L4Proto != 0 && ctx.L4Proto != e.L4Proto {
		return false
	}
	if ctx.SourceDevice != "" && e.SourceDevice != "" && ctx.SourceDevice != e.SourceDevice {
		return false
	}
	if !ctx.Client.IsZero() && !e.Client.IsZero() && ctx.Client != e.Client {
		return false
	}
	if isClientScopedSource(e.Source) && !ctx.Client.IsZero() && e.Client.IsZero() {
		return false
	}
	return ctx.EvidenceValid == nil || ctx.EvidenceValid(e)
}

func sortEvidence(evidence []Evidence) {
	sort.SliceStable(evidence, func(i, j int) bool {
		a, b := evidence[i], evidence[j]
		if sourceRank(a.Source) != sourceRank(b.Source) {
			return sourceRank(a.Source) > sourceRank(b.Source)
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if !a.ExpiresAt.Equal(b.ExpiresAt) {
			if a.ExpiresAt.IsZero() {
				return false
			}
			if b.ExpiresAt.IsZero() {
				return true
			}
			return a.ExpiresAt.After(b.ExpiresAt)
		}
		if a.CreatedAt != b.CreatedAt {
			return a.CreatedAt.After(b.CreatedAt)
		}
		if a.SetID != b.SetID {
			return a.SetID < b.SetID
		}
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		return a.Reason < b.Reason
	})
}

func candidateStrength(a, b Evidence) bool {
	return sourceRank(a.Source) == sourceRank(b.Source) && absInt(int(a.Confidence)-int(b.Confidence)) <= 10
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
