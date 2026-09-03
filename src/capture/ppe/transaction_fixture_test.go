package ppe

import (
	"context"
	"errors"
	"reflect"
)

type fakeTransactionBackend struct {
	current          map[string]FamilySnapshot
	failOperation    string
	failFamily       string
	restoreCancelled bool
}

func newFakeTransactionBackend() *fakeTransactionBackend {
	return &fakeTransactionBackend{current: make(map[string]FamilySnapshot)}
}

func (f *fakeTransactionBackend) Snapshot(_ context.Context, plan FamilyPlan) (FamilySnapshot, error) {
	if f.shouldFail("snapshot", plan.Family) {
		return FamilySnapshot{}, errors.New("snapshot failed")
	}
	if snapshot, ok := f.current[plan.Family]; ok {
		return cloneFamilySnapshot(snapshot), nil
	}
	return FamilySnapshot{Family: plan.Family, Binary: plan.Binary, WaitSupported: plan.WaitSupported}, nil
}

func (f *fakeTransactionBackend) Install(_ context.Context, plan FamilyPlan) error {
	if f.shouldFail("install", plan.Family) {
		return context.Canceled
	}
	f.current[plan.Family] = snapshotForPlan(plan)
	return nil
}

func (f *fakeTransactionBackend) Verify(_ context.Context, plan FamilyPlan) error {
	if f.shouldFail("verify", plan.Family) {
		return errors.New("verify failed")
	}
	current, ok := f.current[plan.Family]
	if !ok {
		return errors.New("rules missing")
	}
	want := snapshotForPlan(plan)
	if !reflect.DeepEqual(current, want) {
		return errors.New("rules differ")
	}
	return nil
}

func (f *fakeTransactionBackend) Remove(_ context.Context, plan FamilyPlan) error {
	if f.shouldFail("remove", plan.Family) {
		return errors.New("remove failed")
	}
	delete(f.current, plan.Family)
	return nil
}

func (f *fakeTransactionBackend) VerifyRemoved(_ context.Context, plan FamilyPlan) error {
	if f.shouldFail("verify-removed", plan.Family) {
		return errors.New("remove verify failed")
	}
	if _, ok := f.current[plan.Family]; ok {
		return errors.New("rules remain")
	}
	return nil
}

func (f *fakeTransactionBackend) Restore(ctx context.Context, snapshot FamilySnapshot) error {
	if ctx.Err() != nil {
		f.restoreCancelled = true
		return ctx.Err()
	}
	f.current[snapshot.Family] = cloneFamilySnapshot(snapshot)
	return nil
}

func (f *fakeTransactionBackend) shouldFail(operation, family string) bool {
	return f.failOperation == operation && f.failFamily == family
}

func desiredTransactionState(generation string) DesiredState {
	return DesiredState{
		Generation: generation,
		Families: []FamilyPlan{
			{Family: "ipv4", Binary: "iptables", WaitSupported: true, Enabled: true, Rules: []string{"-A B4_PPE_PRE -p tcp --dport 443 -j PPE", "-A B4_PPE_FWD -p tcp --dport 443 -j PPE"}},
			{Family: "ipv6", Binary: "ip6tables", WaitSupported: true, Enabled: true, Rules: []string{"-A B4_PPE_PRE -p udp --dport 443 -j PPE", "-A B4_PPE_FWD -p udp --dport 443 -j PPE"}},
		},
	}
}

func oldSnapshot(family, binary, marker string) FamilySnapshot {
	return FamilySnapshot{
		Family: family, Binary: binary, WaitSupported: true, PreExists: true, FwdExists: true,
		PreRules: [][]string{{"-A", ChainPre, "-m", "comment", "--comment", marker, "-j", "PPE"}},
		FwdRules: [][]string{{"-A", ChainFwd, "-m", "comment", "--comment", marker, "-j", "PPE"}},
		PreJumps: []PositionedRule{{Position: 2, Args: []string{"-A", "PREROUTING", "-m", "comment", "--comment", CommentJumpPre, "-j", ChainPre}}},
		FwdJumps: []PositionedRule{{Position: 3, Args: []string{"-A", "FORWARD", "-m", "comment", "--comment", CommentJumpFwd, "-j", ChainFwd}}},
	}
}

func snapshotForPlan(plan FamilyPlan) FamilySnapshot {
	pre, fwd, _ := desiredChainRules(plan)
	return FamilySnapshot{
		Family: plan.Family, Binary: plan.Binary, WaitSupported: plan.WaitSupported, PreExists: true, FwdExists: true,
		PreRules: pre, FwdRules: fwd,
		PreJumps: []PositionedRule{{Position: 1, Args: []string{"-A", "PREROUTING", "-m", "comment", "--comment", CommentJumpPre, "-j", ChainPre}}},
		FwdJumps: []PositionedRule{{Position: 1, Args: []string{"-A", "FORWARD", "-m", "comment", "--comment", CommentJumpFwd, "-j", ChainFwd}}},
	}
}

func cloneFamilySnapshot(in FamilySnapshot) FamilySnapshot {
	out := in
	cloneRules := func(rules [][]string) [][]string {
		cloned := make([][]string, len(rules))
		for i := range rules {
			cloned[i] = cloneArgs(rules[i])
		}
		return cloned
	}
	clonePositioned := func(rules []PositionedRule) []PositionedRule {
		cloned := make([]PositionedRule, len(rules))
		for i := range rules {
			cloned[i] = PositionedRule{Position: rules[i].Position, Args: cloneArgs(rules[i].Args)}
		}
		return cloned
	}
	out.PreRules = cloneRules(in.PreRules)
	out.FwdRules = cloneRules(in.FwdRules)
	out.PreJumps = clonePositioned(in.PreJumps)
	out.FwdJumps = clonePositioned(in.FwdJumps)
	return out
}
