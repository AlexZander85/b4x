package warp

type ProductStatus struct {
	Enabled            bool
	Candidate          string
	Established        bool
	TraceComplete      bool
	GenerationMismatch bool
	Explanation        string
}
type ProductControl string

const (
	ControlTest   ProductControl = "test"
	ControlSelect ProductControl = "select"
	ControlReset  ProductControl = "reset"
)

type TraceExport struct {
	Events   []TransportTraceEnvelope
	Redacted bool
	Complete bool
	MaxBytes int
}

func (e TraceExport) Valid() bool {
	return e.Redacted && e.Complete && e.MaxBytes > 0 && len(e.Events) > 0
}
func (e TraceExport) Bounded() TraceExport {
	if len(e.Events) > e.MaxBytes {
		e.Events = e.Events[:e.MaxBytes]
	}
	for i := range e.Events {
		e.Events[i].Payload = nil
	}
	return e
}
