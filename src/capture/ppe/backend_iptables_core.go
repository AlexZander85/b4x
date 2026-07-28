package ppe

import "context"

type IPTablesBackend struct {
	runner Runner
}

func NewIPTablesBackend(runner Runner) *IPTablesBackend {
	if runner == nil {
		runner = OSRunner{}
	}
	return &IPTablesBackend{runner: runner}
}

func (b *IPTablesBackend) Snapshot(ctx context.Context, plan FamilyPlan) (FamilySnapshot, error) {
	lines, err := b.list(ctx, plan)
	if err != nil {
		return FamilySnapshot{}, err
	}
	snapshot := FamilySnapshot{
		Family:        plan.Family,
		Binary:        plan.Binary,
		WaitSupported: plan.WaitSupported,
	}
	positions := map[string]int{"PREROUTING": 0, "FORWARD": 0}
	for _, line := range lines {
		args, err := splitRuleLine(line)
		if err != nil {
			return FamilySnapshot{}, err
		}
		if len(args) < 2 {
			continue
		}
		switch {
		case args[0] == "-N" && args[1] == ChainPre:
			snapshot.PreExists = true
		case args[0] == "-N" && args[1] == ChainFwd:
			snapshot.FwdExists = true
		case args[0] == "-A" && args[1] == ChainPre:
			snapshot.PreExists = true
			snapshot.PreRules = append(snapshot.PreRules, cloneArgs(args))
		case args[0] == "-A" && args[1] == ChainFwd:
			snapshot.FwdExists = true
			snapshot.FwdRules = append(snapshot.FwdRules, cloneArgs(args))
		case args[0] == "-A" && args[1] == "PREROUTING":
			positions["PREROUTING"]++
			if isOwnedJump(args, "PREROUTING", ChainPre, CommentJumpPre) {
				snapshot.PreJumps = append(snapshot.PreJumps, PositionedRule{Position: positions["PREROUTING"], Args: cloneArgs(args)})
			}
		case args[0] == "-A" && args[1] == "FORWARD":
			positions["FORWARD"]++
			if isOwnedJump(args, "FORWARD", ChainFwd, CommentJumpFwd) {
				snapshot.FwdJumps = append(snapshot.FwdJumps, PositionedRule{Position: positions["FORWARD"], Args: cloneArgs(args)})
			}
		}
	}
	return snapshot, nil
}
