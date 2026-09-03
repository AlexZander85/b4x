package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
)

// l5ppeFakeBackend simulates kernel state for keepalive tests. failVerify
// models an external mangle wipe: Verify (assert path) fails until Install
// restores the owned rules.
type l5ppeFakeBackend struct {
	failVerify bool
	installs   int
}

func (b *l5ppeFakeBackend) Snapshot(_ context.Context, _ ppe.FamilyPlan) (ppe.FamilySnapshot, error) {
	return ppe.FamilySnapshot{
		Family:    "ipv4",
		PreExists: !b.failVerify,
		FwdExists: !b.failVerify,
	}, nil
}

func (b *l5ppeFakeBackend) Install(_ context.Context, _ ppe.FamilyPlan) error {
	b.installs++
	b.failVerify = false
	return nil
}

func (b *l5ppeFakeBackend) Verify(_ context.Context, _ ppe.FamilyPlan) error {
	if b.failVerify {
		return errors.New("owned PPE chains are missing")
	}
	return nil
}

func (b *l5ppeFakeBackend) Remove(context.Context, ppe.FamilyPlan) error { return nil }

func (b *l5ppeFakeBackend) VerifyRemoved(context.Context, ppe.FamilyPlan) error { return nil }

func (b *l5ppeFakeBackend) Restore(context.Context, ppe.FamilySnapshot) error { return nil }

func l5ppeTestDesired() ppe.DesiredState {
	return ppe.DesiredState{
		Generation: "testgen1234",
		Families: []ppe.FamilyPlan{{
			Family:        "ipv4",
			Binary:        "iptables",
			WaitSupported: true,
			Enabled:       true,
			Rules:         []string{"-A B4_PPE_PRE -p tcp --dport 443 -m comment --comment b4:ppe:v1:tcp -j PPE"},
		}},
	}
}

func TestL5ppeKeepaliveTickRepairsAfterExternalWipe(t *testing.T) {
	be := &l5ppeFakeBackend{}
	tm := ppe.NewTransactionManager(be)
	ctx := context.Background()
	if _, err := tm.Apply(ctx, l5ppeTestDesired()); err != nil {
		t.Fatalf("setup apply: %v", err)
	}
	installsAfterSetup := be.installs

	if repaired := l5ppeKeepaliveTick(ctx, tm); repaired {
		t.Fatal("healthy window must not be reported as repaired")
	}
	if be.installs != installsAfterSetup {
		t.Fatalf("healthy window was reinstalled %d times", be.installs-installsAfterSetup)
	}

	be.failVerify = true // external wipe
	if repaired := l5ppeKeepaliveTick(ctx, tm); !repaired {
		t.Fatal("wiped window was not repaired")
	}
	if be.installs == installsAfterSetup {
		t.Fatal("reapply did not reach Install")
	}
	if err := tm.Assert(ctx); err != nil {
		t.Fatalf("assert after repair: %v", err)
	}
}

func TestL5ppeKeepaliveTickWithoutActiveGeneration(t *testing.T) {
	tm := ppe.NewTransactionManager(&l5ppeFakeBackend{})
	if repaired := l5ppeKeepaliveTick(context.Background(), tm); repaired {
		t.Fatal("no-active-generation tick must not report repair")
	}
}

func TestL5ppeKeepaliveLoopStopsOnContextCancel(t *testing.T) {
	be := &l5ppeFakeBackend{}
	tm := ppe.NewTransactionManager(be)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l5ppeKeepaliveLoop(ctx, tm)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keepalive loop did not stop on context cancel")
	}
}
