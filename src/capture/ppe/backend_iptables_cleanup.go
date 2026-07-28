package ppe

import (
	"context"
	"fmt"
)

func (b *IPTablesBackend) cleanup(ctx context.Context, plan FamilyPlan) error {
	if err := b.validateOwnedReferences(ctx, plan); err != nil {
		return err
	}
	for _, spec := range []struct {
		hook, chain, comment string
	}{
		{hook: "PREROUTING", chain: ChainPre, comment: CommentJumpPre},
		{hook: "FORWARD", chain: ChainFwd, comment: CommentJumpFwd},
	} {
		lines, err := b.listChain(ctx, plan, spec.hook)
		if err != nil && !isMissingChain(err) {
			return err
		}
		for _, line := range lines {
			args, err := splitRuleLine(line)
			if err != nil {
				return err
			}
			if !isOwnedJump(args, spec.hook, spec.chain, spec.comment) {
				continue
			}
			args[0] = "-D"
			if _, err := b.run(ctx, plan, args...); err != nil {
				return fmt.Errorf("remove owned jump: %w", err)
			}
		}
	}
	for _, chain := range []string{ChainPre, ChainFwd} {
		if _, err := b.run(ctx, plan, "-F", chain); err != nil && !isMissingChain(err) {
			return fmt.Errorf("flush %s: %w", chain, err)
		}
		if _, err := b.run(ctx, plan, "-X", chain); err != nil && !isMissingChain(err) {
			return fmt.Errorf("delete %s: %w", chain, err)
		}
	}
	return nil
}

func (b *IPTablesBackend) validateOwnedReferences(ctx context.Context, plan FamilyPlan) error {
	lines, err := b.list(ctx, plan)
	if err != nil {
		return err
	}
	for _, line := range lines {
		args, err := splitRuleLine(line)
		if err != nil {
			return err
		}
		if len(args) < 3 || args[0] != "-A" {
			continue
		}
		targetsPre := hasArgPair(args, "-j", ChainPre)
		targetsFwd := hasArgPair(args, "-j", ChainFwd)
		if !targetsPre && !targetsFwd {
			continue
		}
		owned := isOwnedJump(args, "PREROUTING", ChainPre, CommentJumpPre) || isOwnedJump(args, "FORWARD", ChainFwd, CommentJumpFwd)
		if !owned {
			return fmt.Errorf("foreign rule references owned PPE chain: %s", line)
		}
	}
	return nil
}
