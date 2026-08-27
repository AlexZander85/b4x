package transportwarp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ---- M3-06: partial-save of registration (POST is never lost) ----

// seedPending plants a device on the (fake) CF side plus a matching persisted
// pending registration, simulating a crash right after POST /reg. The committed
// identity stays absent, so Ensure will have to finish the registration.
func (h *harness) seedPending(t *testing.T) *PendingRegistration {
	t.Helper()
	h.fake.mu.Lock()
	h.fake.seq++
	p := &PendingRegistration{
		ID:        "dev-" + "0c0ffee",
		Token:     "tok-" + "0c0ffee",
		CreatedAt: h.clock.now,
	}
	h.fake.devices[p.ID] = &fakeDevice{id: p.ID, token: p.Token}
	h.fake.mu.Unlock()

	pend := &PendingStore{Path: h.store.Path + ".pending"}
	if err := pend.Save(p); err != nil {
		t.Fatalf("seed pending: %v", err)
	}
	return p
}

// Interruption between POST and PATCH: a persisted pending registration is
// resumed on the next Ensure WITHOUT minting a second device (POST count 0 for
// the resume), and PATCH+GET complete it into a committed identity.
func TestPendingResumeWithoutSecondPost(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)
	h.seedPending(t)

	res := h.ensure(t)
	if res.Action != ActionProvisioned || res.Identity == nil {
		t.Fatalf("resume must provision the pending registration, got %+v", res)
	}
	post, patch, get, _, _ := h.fake.counters()
	if post != 0 {
		t.Fatalf("resume must not mint a new device, POST=%d", post)
	}
	if patch != 1 || get != 1 {
		t.Fatalf("resume must run exactly one PATCH+GET, patch=%d get=%d", patch, get)
	}
	// The interim pending token must be cleared once the identity committed.
	if _, err := (&PendingStore{Path: h.store.Path + ".pending"}).Load(); !errors.Is(err, ErrPendingAbsent) {
		t.Fatalf("pending must be cleared after commit, err=%v", err)
	}
	assertNoProtocolViolations(t, h.fake)
}

// PATCH permanently fails on a pending registration: the orphan device is
// best-effort DELETEd exactly once, the pending record is cleared, and a fresh
// POST mints a new device. No identity is committed while PATCH is broken.
func TestRetryablePATCHFinallyFailsDeletesOrphan(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)
	h.seedPending(t)
	h.fake.patchStatus = 500 // PATCH fails permanently

	res, err := h.rec.Ensure(context.Background())
	// PATCH dead => Ensure surfaces the resume failure (blocked, not provisioned).
	if err == nil {
		t.Fatalf("broken PATCH must fail Ensure, got res=%+v", res)
	}
	if res.Identity != nil {
		t.Fatalf("broken PATCH must not commit an identity, got %+v", res.Identity)
	}
	if res.Action == ActionProvisioned {
		t.Fatalf("broken PATCH must not report provisioned")
	}
	// Orphan DELETE issued exactly once (for the pre-seeded pending device).
	if _, _, _, _, del := h.fake.counters(); del != 1 {
		t.Fatalf("orphan DELETE must fire exactly once, del=%d", del)
	}
	// A fresh POST was attempted for the fallback device.
	if post, _, _, _, _ := h.fake.counters(); post != 1 {
		t.Fatalf("fallback must mint one fresh device, POST=%d", post)
	}
}

// Nothing is lost across a full process restart modeled as an absent identity
// + present pending: Ensure finishes the partial registration.
func TestPendingContinuesAfterCrashState(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)
	h.seedPending(t)
	// No prior committed identity exists (crash happened mid-enrollment).
	if _, err := h.store.Load(); !errors.Is(err, ErrIdentityAbsent) {
		t.Fatalf("expected no committed identity, err=%v", err)
	}
	res := h.ensure(t)
	if res.Action != ActionProvisioned || res.Identity == nil {
		t.Fatalf("crash continuation must provision, got %+v", res)
	}
	if _, err := h.store.Load(); err != nil {
		t.Fatalf("identity must be committed after continuation: %v", err)
	}
}

// A stale pending registration (older than PendingExpiry) is not resumed; it
// is cleared and a fresh device is minted instead.
func TestStalePendingIsDiscardedAndReMinted(t *testing.T) {
	h := newHarness(t, DefaultMinEnrollInterval)
	p := h.seedPending(t)
	// Age the pending past the expiry by serving a much later "now".
	h.clock.now = p.CreatedAt.Add(PendingExpiry + time.Hour)

	res := h.ensure(t)
	if res.Action != ActionProvisioned || res.Identity == nil {
		t.Fatalf("fresh mint expected for stale pending, got %+v", res)
	}
	if post, _, _, _, _ := h.fake.counters(); post != 1 {
		t.Fatalf("stale pending must be replaced by a fresh POST, POST=%d", post)
	}
}
