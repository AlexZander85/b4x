package silentpath

import (
	"sync"
	"time"
)

type Budget struct{ MaxRollbacks, Rollbacks int }
type RollbackMonitor struct {
	mu          sync.Mutex
	leases      *LeaseStore
	budget      Budget
	ObserveOnly bool
}

func NewRollbackMonitor(l *LeaseStore, b Budget) *RollbackMonitor {
	return &RollbackMonitor{leases: l, budget: b}
}
func (m *RollbackMonitor) Rollback(id string, scope Scope, reason string, nowUnix int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.leases.Get(id, scope, unixTime(nowUnix))
	if !ok {
		return false
	}
	m.budget.Rollbacks++
	if m.budget.MaxRollbacks > 0 && m.budget.Rollbacks >= m.budget.MaxRollbacks {
		m.ObserveOnly = true
	}
	return true
}
func unixTime(v int64) time.Time { return time.Unix(v, 0) }
