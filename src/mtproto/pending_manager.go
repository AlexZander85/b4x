package mtproto

import (
	"errors"
	"sync"
	"time"
)

var ErrPendingOverflow = errors.New("pending handshake budget exceeded")

type PendingToken struct {
	ID, ClientKey string
	Generation    uint64
	StartedAt     time.Time
}
type PendingHandshakeManager struct {
	mu                   sync.Mutex
	maxGlobal, maxClient int
	generation           uint64
	next                 uint64
	pending              map[string]PendingToken
	perClient            map[string]int
	closed               bool
}

func NewPendingHandshakeManager(maxGlobal, maxClient int) *PendingHandshakeManager {
	if maxGlobal <= 0 {
		maxGlobal = 128
	}
	if maxClient <= 0 {
		maxClient = 8
	}
	return &PendingHandshakeManager{maxGlobal: maxGlobal, maxClient: maxClient, generation: 1, pending: map[string]PendingToken{}, perClient: map[string]int{}}
}
func (m *PendingHandshakeManager) Acquire(client string, now time.Time) (PendingToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || len(m.pending) >= m.maxGlobal || m.perClient[client] >= m.maxClient {
		return PendingToken{}, ErrPendingOverflow
	}
	m.next++
	t := PendingToken{ID: "pending-" + itoaPending(m.next), ClientKey: client, Generation: m.generation, StartedAt: now}
	m.pending[t.ID] = t
	m.perClient[client]++
	return t, nil
}
func itoaPending(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := 20
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
func (m *PendingHandshakeManager) Release(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.pending[id]
	if !ok {
		return false
	}
	delete(m.pending, id)
	if m.perClient[t.ClientKey] > 0 {
		m.perClient[t.ClientKey]--
	}
	return true
}
func (m *PendingHandshakeManager) Reload() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	m.pending = map[string]PendingToken{}
	m.perClient = map[string]int{}
}
func (m *PendingHandshakeManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.pending = map[string]PendingToken{}
	m.perClient = map[string]int{}
}
func (m *PendingHandshakeManager) Len() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.pending) }
