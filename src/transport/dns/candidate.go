package dnspath

import (
	"context"
	"errors"
	"fmt"
	"time"
)

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
	if err := profile.Valid(now); err != nil {
		return DNSResponse{}, fmt.Errorf("candidate profile invalid: %w", err)
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

// PrepareProfilePaths prepares exactly the selected primary and fallbacks for
// production use. Diagnostic probe handles are retired by the detector and
// are never reused as production readiness evidence.
func (m *Manager) PrepareProfilePaths(ctx context.Context, profile *DNSPathProfile) error {
	if profile == nil {
		return errors.New("profile required")
	}
	if err := profile.Valid(time.Now()); err != nil {
		return fmt.Errorf("cannot prepare invalid profile: %w", err)
	}
	selected := make([]DNSPathID, 0, 1+len(profile.Fallbacks))
	selected = append(selected, profile.Primary)
	selected = append(selected, profile.Fallbacks...)
	for _, path := range selected {
		provider, ok := m.Provider(path.Hash())
		if !ok {
			return fmt.Errorf("selected provider %s is not registered", path.Family)
		}
		if err := m.PreparePath(ctx, provider, false); err != nil {
			return fmt.Errorf("prepare selected %s: %w", path.Family, err)
		}
		m.mu.RLock()
		prepared, ok := m.prepared[path.Hash()]
		m.mu.RUnlock()
		if !ok {
			return fmt.Errorf("selected provider %s did not retain prepared handle", path.Family)
		}
		health := provider.Health(ctx, prepared)
		m.MarkPathHealth(path, health)
		if health.State != CapReady && health.State != CapAvailable {
			return fmt.Errorf("selected provider %s not ready after prepare: %s", path.Family, health.State)
		}
	}
	return nil
}
