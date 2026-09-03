package fieldtest

import "time"

type CausalEvent struct {
	EventID, TraceID, ParentEventID, InstanceID, ParentInstanceID string
	Sequence                                                      uint64
	Timestamp                                                     time.Time
	MonotonicNS                                                   uint64
	BootIDHash, ProcessStartID, Role, Event                       string
	ConfigGen, RouteGen, SessionGen                               uint64
	Priority                                                      int
	Required                                                      bool
}

func (e CausalEvent) Valid(prev uint64) bool {
	return e.EventID != "" && e.TraceID != "" && e.Sequence > prev && !e.Timestamp.IsZero() && e.MonotonicNS > 0 && e.BootIDHash != "" && e.ProcessStartID != "" && e.Event != "" && e.ConfigGen > 0
}

type TraceCausalReport struct {
	Events                                                                []CausalEvent
	RuntimeState, TraceState                                              string
	RequiredDropped, SequenceGaps, DuplicateEvents, ImpossibleTransitions int
	Redacted                                                              bool
}

func (r TraceCausalReport) Ready() bool {
	return len(r.Events) > 0 && r.RequiredDropped == 0 && r.SequenceGaps == 0 && r.DuplicateEvents == 0 && r.ImpossibleTransitions == 0 && r.RuntimeState == r.TraceState && r.Redacted
}
func ValidateEventOrder(events []CausalEvent) TraceCausalReport {
	r := TraceCausalReport{Events: append([]CausalEvent(nil), events...), Redacted: true}
	var prev uint64
	seen := map[string]bool{}
	for _, e := range events {
		if !e.Valid(prev) {
			if e.Sequence <= prev {
				r.SequenceGaps++
			} else {
				r.ImpossibleTransitions++
			}
		}
		if seen[e.EventID] {
			r.DuplicateEvents++
		}
		seen[e.EventID] = true
		prev = e.Sequence
	}
	return r
}
