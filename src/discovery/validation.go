package discovery

import "time"

type CausalABComparison struct {
	Seed               uint64
	WithoutProfile     SearchSavingsReport
	WithProfile        SearchSavingsReport
	StaleSuppressed    bool
	ConflictSuppressed bool
	SameControls       bool
	FalsePromotion     bool
	CreatedAt          time.Time
}

func (c CausalABComparison) Valid() bool {
	return c.WithoutProfile.BaselineProbes > 0 && c.WithProfile.GuidedProbes > 0 && c.WithProfile.GuidedProbes <= c.WithoutProfile.BaselineProbes && c.StaleSuppressed && c.ConflictSuppressed && c.SameControls && !c.FalsePromotion
}

type IssueBundle struct {
	IssueID    string
	ProfileID  string
	Events     []DiscoveryEvent
	Comparison CausalABComparison
	Redacted   bool
}

func (b IssueBundle) Valid() bool { return b.IssueID != "" && b.Redacted && b.Comparison.Valid() }
