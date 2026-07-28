package ppe

import (
	"context"
	"errors"
	"fmt"
)

func (b *IPTablesBackend) Install(ctx context.Context, plan FamilyPlan) error {
	if !plan.WaitSupported {
		return ErrXTablesLockMissing
	}
	if err := b.cleanup(ctx, plan); err != nil {
		return err
	}
	if _, err := b.run(ctx, plan, "-N", ChainPre); err != nil {
		return fmt.Errorf("create %s: %w", ChainPre, err)
	}
	if _, err := b.run(ctx, plan, "-N", ChainFwd); err != nil {
		return fmt.Errorf("create %s: %w", ChainFwd, err)
	}
	if _, err := b.run(ctx, plan, "-I", "PREROUTING", "1", "-m", "comment", "--comment", CommentJumpPre, "-j", ChainPre); err != nil {
		return fmt.Errorf("install PREROUTING jump: %w", err)
	}
	if _, err := b.run(ctx, plan, "-I", "FORWARD", "1", "-m", "comment", "--comment", CommentJumpFwd, "-j", ChainFwd); err != nil {
		return fmt.Errorf("install FORWARD jump: %w", err)
	}
	for _, rule := range plan.Rules {
		args, err := splitRuleLine(rule)
		if err != nil {
			return err
		}
		if len(args) < 3 || args[0] != "-A" || (args[1] != ChainPre && args[1] != ChainFwd) {
			return fmt.Errorf("refusing non-owned PPE rule %q", rule)
		}
		if _, err := b.run(ctx, plan, args...); err != nil {
			return fmt.Errorf("install rule %q: %w", rule, err)
		}
	}
	return nil
}

func (b *IPTablesBackend) Verify(ctx context.Context, plan FamilyPlan) error {
	snapshot, err := b.Snapshot(ctx, plan)
	if err != nil {
		return err
	}
	if !snapshot.PreExists || !snapshot.FwdExists {
		return errors.New("owned PPE chains are missing")
	}
	if len(snapshot.PreJumps) != 1 || len(snapshot.FwdJumps) != 1 {
		return fmt.Errorf("owned PPE jumps are not canonical: pre=%d fwd=%d", len(snapshot.PreJumps), len(snapshot.FwdJumps))
	}
	if snapshot.PreJumps[0].Position != 1 || snapshot.FwdJumps[0].Position != 1 {
		return fmt.Errorf("owned PPE jumps are not first in forwarding hooks: pre=%d fwd=%d", snapshot.PreJumps[0].Position, snapshot.FwdJumps[0].Position)
	}
	wantPre, wantFwd, err := desiredChainRules(plan)
	if err != nil {
		return err
	}
	if !equalRules(snapshot.PreRules, wantPre) || !equalRules(snapshot.FwdRules, wantFwd) {
		return fmt.Errorf("owned PPE rules differ from desired generation")
	}
	return nil
}

func (b *IPTablesBackend) Remove(ctx context.Context, plan FamilyPlan) error {
	return b.cleanup(ctx, plan)
}

func (b *IPTablesBackend) VerifyRemoved(ctx context.Context, plan FamilyPlan) error {
	snapshot, err := b.Snapshot(ctx, plan)
	if err != nil {
		return err
	}
	if snapshot.PreExists || snapshot.FwdExists || len(snapshot.PreJumps) != 0 || len(snapshot.FwdJumps) != 0 {
		return errors.New("owned PPE state remains after remove")
	}
	return nil
}
