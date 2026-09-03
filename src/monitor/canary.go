package monitor

import (
	"sort"
	"sync"
	"time"
)

type CanaryMilestone string

const (
	MilestoneRouterBound    CanaryMilestone = "router-bound"
	MilestoneAndroidSeen    CanaryMilestone = "android-seen"
	MilestoneTargetHealthy  CanaryMilestone = "target-healthy"
	MilestoneControlHealthy CanaryMilestone = "control-healthy"
	MilestoneRollbackSignal CanaryMilestone = "rollback-signal"
)

type CanaryObservation struct {
	ObservationID string
	Scope         MonitorScopeKey
	BindingID     string
	PathID        string
	Origin        string // router | android | passive
	Milestone     CanaryMilestone
	ObservedAt    time.Time
	Success       bool
	Explanation   string
}

func (o CanaryObservation) Valid() bool {
	return o.ObservationID != "" && o.Scope.Valid() && o.BindingID != "" && o.PathID != "" && o.Origin != "" && o.Milestone != "" && !o.ObservedAt.IsZero()
}

type CanarySummary struct {
	Scope            MonitorScopeKey
	BindingID        string
	PathID           string
	Milestones       []CanaryMilestone
	TargetHealthy    bool
	ControlHealthy   bool
	AndroidSeen      bool
	RollbackObserved bool
	LastObserved     time.Time
}

type CanarySummaryAdapter struct {
	mu    sync.Mutex
	byKey map[string]*CanarySummary
}

func NewCanarySummaryAdapter() *CanarySummaryAdapter {
	return &CanarySummaryAdapter{byKey: map[string]*CanarySummary{}}
}
func canaryKey(o CanaryObservation) string {
	return correlationKey(o.Scope) + "|" + o.BindingID + "|" + o.PathID
}

func (a *CanarySummaryAdapter) Observe(o CanaryObservation) bool {
	if a == nil || !o.Valid() {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	k := canaryKey(o)
	s := a.byKey[k]
	if s == nil {
		s = &CanarySummary{Scope: o.Scope, BindingID: o.BindingID, PathID: o.PathID}
		a.byKey[k] = s
	}
	s.LastObserved = o.ObservedAt
	found := false
	for _, m := range s.Milestones {
		if m == o.Milestone {
			found = true
			break
		}
	}
	if !found {
		s.Milestones = append(s.Milestones, o.Milestone)
		sort.Slice(s.Milestones, func(i, j int) bool { return s.Milestones[i] < s.Milestones[j] })
	}
	if o.Milestone == MilestoneAndroidSeen && o.Origin == "android" && o.Success {
		s.AndroidSeen = true
	}
	if o.Milestone == MilestoneTargetHealthy && o.Success {
		s.TargetHealthy = true
	}
	if o.Milestone == MilestoneControlHealthy && o.Success {
		s.ControlHealthy = true
	}
	if o.Milestone == MilestoneRollbackSignal {
		s.RollbackObserved = true
	}
	return true
}

func (a *CanarySummaryAdapter) Snapshot(scope MonitorScopeKey, bindingID, pathID string) (CanarySummary, bool) {
	if a == nil {
		return CanarySummary{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.byKey[correlationKey(scope)+"|"+bindingID+"|"+pathID]
	if !ok {
		return CanarySummary{}, false
	}
	s.Milestones = append([]CanaryMilestone(nil), s.Milestones...)
	return *s, true
}
