package silentpath

type Status struct {
	ConfiguredMode, EffectiveMode, DegradedReason string
	ActiveSuspicions, ActiveLeases                int
	Rollbacks, RemainingBudget                    int
}

func BuildStatus(configured string, s CapabilitySnapshot, suspicions, leases, rollbacks, max int) Status {
	m, r := EffectiveMode(configured, s)
	remaining := max - rollbacks
	if remaining < 0 {
		remaining = 0
	}
	return Status{configured, m, r, suspicions, leases, rollbacks, remaining}
}
