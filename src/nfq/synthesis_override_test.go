package nfq

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/fixtures"
)

func synthesisOverrideWorker(t *testing.T, fake *fakePacketInjector) *Worker {
	t.Helper()
	w := NewWorkerWithQueue(nil, 0)
	w.actionSender = fake
	w.actionMark = capture.ProcessedMarkFor(1)
	return w
}

// TestExecuteActionPlanUsesSynthesisOverride proves the AFS probe seam: while an
// override is armed for the exact destination, the candidate compiler supplies
// the plan; after release the configured plan path is restored.
func TestExecuteActionPlanUsesSynthesisOverride(t *testing.T) {
	t.Cleanup(clearSynthesisOverrides)
	_, set := actionExecutorTestConfig(t)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := synthesisOverrideWorker(t, fake)

	called := 0
	release := ArmSynthesisOverride(dst, func(input action.PlanInput) (action.ActionPlan, error) {
		called++
		return action.Plan(input)
	}, time.Minute)
	defer release()

	w.dropAndInjectTCP(set, raw, dst)
	if called != 1 {
		t.Fatalf("override compiler called %d times, want 1", called)
	}
	if fake.sent4 != 1 {
		t.Fatalf("injected packets = %d, want 1", fake.sent4)
	}
	if err := action.ValidatePacket(fake.last4); err != nil {
		t.Fatalf("override-built packet invalid: %v", err)
	}
	if got := fake.last4[40:]; !bytes.Equal(got, hello) {
		t.Fatalf("payload not preserved through override")
	}

	release()
	called = 0
	w.dropAndInjectTCP(set, raw, dst)
	if called != 0 {
		t.Fatal("override still active after release")
	}
	if fake.sent4 != 2 {
		t.Fatalf("default path injected %d packets, want 2 total", fake.sent4)
	}
}

// TestExecuteActionPlanOverrideFailsOpen covers the safety contract: a compiler
// error must leave the configured plan in place, never break the flow.
func TestExecuteActionPlanOverrideFailsOpen(t *testing.T) {
	t.Cleanup(clearSynthesisOverrides)
	_, set := actionExecutorTestConfig(t)
	hello := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	raw := buildTestIPv4TCPPacket(t, hello, 1000, 51000, 443)
	dst := net.IPv4(203, 0, 113, 10)

	fake := &fakePacketInjector{}
	w := synthesisOverrideWorker(t, fake)

	called := 0
	release := ArmSynthesisOverride(dst, func(action.PlanInput) (action.ActionPlan, error) {
		called++
		return action.ActionPlan{}, errors.New("candidate compile failed")
	}, time.Minute)
	defer release()

	w.dropAndInjectTCP(set, raw, dst)
	if called != 1 {
		t.Fatalf("override compiler called %d times, want 1", called)
	}
	if fake.sent4 != 1 {
		t.Fatalf("fail-open injected %d packets, want 1", fake.sent4)
	}
	if err := action.ValidatePacket(fake.last4); err != nil {
		t.Fatalf("fail-open packet invalid: %v", err)
	}
}

// TestSynthesisOverrideScopedAndExpiring proves the override is bound to one
// destination and a bounded window.
func TestSynthesisOverrideScopedAndExpiring(t *testing.T) {
	t.Cleanup(clearSynthesisOverrides)
	dst := net.IPv4(203, 0, 113, 10)
	other := net.IPv4(198, 51, 100, 7)
	compiler := func(input action.PlanInput) (action.ActionPlan, error) { return action.Plan(input) }

	release := ArmSynthesisOverride(dst, compiler, 20*time.Millisecond)
	if _, ok := activeSynthesisCompiler(dst, time.Now()); !ok {
		t.Fatal("override not active immediately after arm")
	}
	if _, ok := activeSynthesisCompiler(other, time.Now()); ok {
		t.Fatal("override leaked to a different destination")
	}
	time.Sleep(30 * time.Millisecond)
	if _, ok := activeSynthesisCompiler(dst, time.Now()); ok {
		t.Fatal("override still active after expiry")
	}
	release() // idempotent, must not panic
	release()
	if _, ok := activeSynthesisCompiler(dst, time.Now()); ok {
		t.Fatal("override present after release")
	}
}
