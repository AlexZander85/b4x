package dnspath

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const maxManagedProductionInstances = 2

// ResolveCandidate resolves one production query through a prepared candidate
// binding without promoting it globally. This is the source-scoped LAN canary
// data path: only the canary client sees the candidate until Transaction.Run
// completes all gates and atomically promotes it.
func (m *Manager) ResolveCandidate(ctx context.Context, binding *DNSPathBinding, q DNSQuery) (DNSResponse, error) {
	if binding == nil {
		return DNSResponse{}, errors.New("candidate binding required")
	}
	m.mu.RLock()
	profile := m.profile
	generation := m.generation
	epoch := m.epoch
	networkCtx := m.networkCtx
	m.mu.RUnlock()
	if profile == nil {
		return DNSResponse{}, errors.New("candidate resolve requires adopted profile")
	}
	now := time.Now()
	if err := profile.Validated(now); err != nil {
		return DNSResponse{}, fmt.Errorf("candidate profile invalid/unproven: %w", err)
	}
	if profile.ProfileID != binding.ProfileID || profile.ContentHash == "" {
		return DNSResponse{}, errors.New("candidate binding/profile mismatch")
	}
	if profile.NetworkContextID != networkCtx || !binding.CompatibleWith(generation, epoch, now) {
		return DNSResponse{}, errors.New("candidate binding stale or wrong network context")
	}
	if binding.Primary.Hash() != profile.Primary.Hash() {
		return DNSResponse{}, errors.New("candidate primary differs from adopted profile")
	}

	resp, err := m.resolveVia(ctx, binding.Primary, q)
	if err == nil && !resp.Truncated {
		return resp, nil
	}
	for _, fb := range binding.Fallbacks {
		if !m.pathReady(fb) {
			continue
		}
		if resp2, err2 := m.resolveVia(ctx, fb, q); err2 == nil && !resp2.Truncated {
			return resp2, nil
		}
	}
	if err != nil {
		return DNSResponse{}, err
	}
	return DNSResponse{}, errors.New("candidate returned only truncated/unusable responses")
}

type newlyPreparedPath struct {
	path     DNSPathID
	provider DNSPathProvider
	prepared PreparedDNSPath
}

// PrepareProfilePaths prepares exactly the selected primary and fallbacks for
// production use. Diagnostic probe handles are retired by the detector and
// are never reused as production readiness evidence. Preparation is
// transactional: handles started by this call are retired if a later selected
// path fails. Already-ready same-generation handles are reused instead of
// spawning duplicate managed processes/listeners.
func (m *Manager) PrepareProfilePaths(ctx context.Context, profile *DNSPathProfile) error {
	if profile == nil {
		return errors.New("profile required")
	}
	if err := profile.Validated(time.Now()); err != nil {
		return fmt.Errorf("cannot prepare invalid/unproven profile: %w", err)
	}
	selected := make([]DNSPathID, 0, 1+len(profile.Fallbacks))
	selected = append(selected, profile.Primary)
	selected = append(selected, profile.Fallbacks...)
	managedCount := 0
	for _, path := range selected {
		if path.Family.Managed() {
			managedCount++
		}
	}
	if managedCount > maxManagedProductionInstances {
		return fmt.Errorf("profile requires %d managed DNS instances; budget is %d", managedCount, maxManagedProductionInstances)
	}

	started := make([]newlyPreparedPath, 0, len(selected))
	cleanupStarted := func() {
		for i := len(started) - 1; i >= 0; i-- {
			item := started[i]
			_ = item.provider.Retire(ctx, item.prepared)
			m.mu.Lock()
			current, ok := m.prepared[item.path.Hash()]
			if ok && current.Generation == item.prepared.Generation && current.PreparedAt.Equal(item.prepared.PreparedAt) {
				delete(m.prepared, item.path.Hash())
				delete(m.health, item.path.Hash())
			}
			m.mu.Unlock()
		}
	}

	for _, path := range selected {
		provider, ok := m.Provider(path.Hash())
		if !ok {
			cleanupStarted()
			return fmt.Errorf("selected provider %s is not registered", path.Family)
		}

		m.mu.RLock()
		existing, exists := m.prepared[path.Hash()]
		m.mu.RUnlock()
		if exists && existing.Generation == profile.ConfigGeneration {
			health := provider.Health(ctx, existing)
			m.MarkPathHealth(path, health)
			if health.State == CapReady || health.State == CapAvailable {
				continue
			}
		}

		if err := m.PreparePath(ctx, provider, false); err != nil {
			cleanupStarted()
			return fmt.Errorf("prepare selected %s: %w", path.Family, err)
		}
		m.mu.RLock()
		prepared, ok := m.prepared[path.Hash()]
		m.mu.RUnlock()
		if !ok {
			cleanupStarted()
			return fmt.Errorf("selected provider %s did not retain prepared handle", path.Family)
		}
		started = append(started, newlyPreparedPath{path: path, provider: provider, prepared: prepared})
		health := provider.Health(ctx, prepared)
		m.MarkPathHealth(path, health)
		if health.State != CapReady && health.State != CapAvailable {
			cleanupStarted()
			return fmt.Errorf("selected provider %s not ready after prepare: %s", path.Family, health.State)
		}
	}
	return nil
}
