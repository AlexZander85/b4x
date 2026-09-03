# ABD-9 — evidence graph and confidence engine

The graph distinguishes observations, hypotheses, controls, assessments, and resolution provenance. Only authoritative active ABD nodes can add confidence; passive monitoring recurrence and provisional fast-lane nodes remain trigger provenance and never count as independent active families.

Contradictory control results reduce confidence, excluded or invalid nodes remain visible in the summary, and duplicate independent keys cannot inflate the score. This graph is deterministic and has no action-plane or production-config dependency.

Validation: `go test ./detector` passes.

