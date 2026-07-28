package ppe

import (
	"context"
	"fmt"
	"sort"
	"strconv"
)

func (b *IPTablesBackend) Restore(ctx context.Context, snapshot FamilySnapshot) error {
	plan := FamilyPlan{Family: snapshot.Family, Binary: snapshot.Binary, WaitSupported: snapshot.WaitSupported}
	if !plan.WaitSupported {
		return ErrXTablesLockMissing
	}
	if err := b.cleanup(ctx, plan); err != nil {
		return err
	}
	if snapshot.PreExists {
		if _, err := b.run(ctx, plan, "-N", ChainPre); err != nil {
			return err
		}
	}
	if snapshot.FwdExists {
		if _, err := b.run(ctx, plan, "-N", ChainFwd); err != nil {
			return err
		}
	}
	for _, rule := range append(snapshot.PreRules, snapshot.FwdRules...) {
		if _, err := b.run(ctx, plan, rule...); err != nil {
			return err
		}
	}
	if err := b.restoreJumps(ctx, plan, snapshot.PreJumps); err != nil {
		return err
	}
	return b.restoreJumps(ctx, plan, snapshot.FwdJumps)
}

func (b *IPTablesBackend) restoreJumps(ctx context.Context, plan FamilyPlan, jumps []PositionedRule) error {
	sort.Slice(jumps, func(i, j int) bool { return jumps[i].Position < jumps[j].Position })
	for _, jump := range jumps {
		if len(jump.Args) < 3 || jump.Args[0] != "-A" {
			return fmt.Errorf("invalid jump snapshot")
		}
		args := []string{"-I", jump.Args[1], strconv.Itoa(jump.Position)}
		args = append(args, jump.Args[2:]...)
		if _, err := b.run(ctx, plan, args...); err != nil {
			return err
		}
	}
	return nil
}
