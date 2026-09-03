package mtproto

import "time"

type HandshakeState string

const (
	HandshakeWaiting     HandshakeState = "waiting"
	HandshakeProgress    HandshakeState = "progress"
	HandshakeAccepted    HandshakeState = "accepted"
	HandshakeSoftExpired HandshakeState = "soft-expired"
	HandshakeHardExpired HandshakeState = "hard-expired"
)

type FirstDataPolicy struct {
	SoftDeadline, HardDeadline time.Duration
	ProgressExtension          time.Duration
}

func DefaultFirstDataPolicy() FirstDataPolicy {
	return FirstDataPolicy{SoftDeadline: 5 * time.Second, HardDeadline: 30 * time.Second, ProgressExtension: 5 * time.Second}
}

type FirstDataMachine struct {
	StartedAt, LastProgressAt time.Time
	Bytes                     int
	State                     HandshakeState
	Policy                    FirstDataPolicy
}

func NewFirstDataMachine(now time.Time, p FirstDataPolicy) FirstDataMachine {
	if p.SoftDeadline <= 0 || p.HardDeadline <= 0 {
		p = DefaultFirstDataPolicy()
	}
	return FirstDataMachine{StartedAt: now, LastProgressAt: now, State: HandshakeWaiting, Policy: p}
}
func (m *FirstDataMachine) Observe(n int, now time.Time) {
	if n <= 0 {
		return
	}
	m.Bytes += n
	m.LastProgressAt = now
	if m.State == HandshakeWaiting || m.State == HandshakeSoftExpired {
		m.State = HandshakeProgress
	}
}
func (m *FirstDataMachine) Accept(now time.Time) {
	if m.Bytes > 0 {
		m.State = HandshakeAccepted
		m.LastProgressAt = now
	}
}
func (m *FirstDataMachine) Tick(now time.Time) HandshakeState {
	if m.State == HandshakeAccepted {
		return m.State
	}
	if now.Sub(m.StartedAt) >= m.Policy.HardDeadline {
		m.State = HandshakeHardExpired
		return m.State
	}
	if now.Sub(m.LastProgressAt) >= m.Policy.SoftDeadline {
		m.State = HandshakeSoftExpired
	}
	return m.State
}
