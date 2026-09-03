package warp

import "time"

type RSTObservation struct {
	FlowID, InstanceID string
	Early              bool
	SequenceValid      bool
	WindowValid        bool
	ObservedAt         time.Time
}

func (o RSTObservation) SpoofLike() bool { return o.Early && o.SequenceValid && o.WindowValid }

type RSTDefense struct {
	EnforcementEnabled bool
	CanaryUntil        time.Time
}

func (d RSTDefense) AllowEnforcement(now time.Time) bool {
	return d.EnforcementEnabled && now.Before(d.CanaryUntil)
}
func (d *RSTDefense) Rollback() {
	if d != nil {
		d.EnforcementEnabled = false
		d.CanaryUntil = time.Time{}
	}
}
