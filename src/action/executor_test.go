package action

import (
	"context"
	"errors"
	"testing"
	"time"
)

type recordingSender struct {
	packets [][]byte
	marks   []uint32
	failAt  int
}

func (s *recordingSender) Send(packet []byte, mark uint32) error {
	if s.failAt > 0 && len(s.packets)+1 == s.failAt {
		return errors.New("injected send failure")
	}
	s.packets = append(s.packets, packet)
	s.marks = append(s.marks, mark)
	return nil
}

func executorPlan(t *testing.T, dryRun bool) (ActionPlan, []byte) {
	t.Helper()
	payload := []byte("original payload")
	original := buildActionIPv4Packet(payload, []byte{1, 1, 1, 1})
	plan, err := Plan(PlanInput{BaseSequence: 7000, Payload: payload, SplitPositions: []SplitPosition{{Offset: 8}}, MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 24, ProcessedMark: 0x4000, DryRun: dryRun})
	if err != nil {
		t.Fatal(err)
	}
	return plan, original
}

func TestExecutorDryRunAndProvenanceValidation(t *testing.T) {
	plan, original := executorPlan(t, true)
	sender := &recordingSender{}
	executor := NewExecutor(ExecutorConfig{MTU: 1500, MaxWrites: 4, MaxBytes: 1024, ProcessedMark: 0x4000, RequirePlanMark: true}, sender)
	result := executor.Execute(original, plan)
	if result.FailOpen || result.Applied || !result.DryRun || len(sender.packets) != 0 || result.Reason == "" {
		t.Fatalf("dry-run result=%+v sent=%d", result, len(sender.packets))
	}
	plan.ProcessedMark = 0
	if result := executor.Execute(original, plan); !result.FailOpen || result.Reason == "" {
		t.Fatalf("missing mark result=%+v", result)
	}
}

func TestExecutorSendsValidatedPacketsAndHandlesPartialFailure(t *testing.T) {
	plan, original := executorPlan(t, false)
	originalCopy := append([]byte(nil), original...)
	sender := &recordingSender{}
	executor := NewExecutor(ExecutorConfig{MTU: 1500, MaxWrites: 4, MaxBytes: 1024, ProcessedMark: 0x4000, RequirePlanMark: true}, sender)
	result := executor.Execute(original, plan)
	if !result.Applied || result.FailOpen || result.Sent != 2 || len(sender.packets) != 2 || original[40] != originalCopy[40] {
		t.Fatalf("successful execution result=%+v sent=%d", result, len(sender.packets))
	}
	for _, mark := range sender.marks {
		if mark != 0x4000 {
			t.Fatalf("sent mark=%#x", mark)
		}
	}

	failing := &recordingSender{failAt: 2}
	executor = NewExecutor(ExecutorConfig{MTU: 1500, MaxWrites: 4, MaxBytes: 1024, ProcessedMark: 0x4000, RequirePlanMark: true}, failing)
	result = executor.Execute(original, plan)
	if !result.FailOpen || !result.PartialSend || result.Sent != 1 || len(failing.packets) != 1 {
		t.Fatalf("partial failure result=%+v sent=%d", result, len(failing.packets))
	}
}

func TestExecutorCancellationDelayAndBudgetFailOpen(t *testing.T) {
	plan, original := executorPlan(t, false)
	plan.Writes[0].Delay = 20 * time.Millisecond
	sender := &recordingSender{}
	executor := NewExecutor(ExecutorConfig{MTU: 1500, MaxWrites: 4, MaxBytes: 1024, MaxDelay: time.Millisecond, ProcessedMark: 0x4000, RequirePlanMark: true}, sender)
	if result := executor.Execute(original, plan); !result.FailOpen || result.Sent != 0 {
		t.Fatalf("delay budget result=%+v", result)
	}
	plan.Writes[0].Delay = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := executor.ExecuteContext(ctx, original, plan); !result.FailOpen || result.Sent != 0 {
		t.Fatalf("cancelled result=%+v", result)
	}
	plan.Writes = plan.Writes[:1]
	plan.TotalBytes = len(plan.Writes[0].Payload)
	executor = NewExecutor(ExecutorConfig{MTU: 1500, MaxWrites: 0, MaxBytes: 1, ProcessedMark: 0x4000, RequirePlanMark: true}, sender)
	if result := executor.Execute(original, plan); !result.FailOpen || result.Reason == "" {
		t.Fatalf("byte budget result=%+v", result)
	}
}

func FuzzExecutorNeverPanics(f *testing.F) {
	f.Add([]byte("not a packet"), []byte("payload"), uint32(0x4000))
	f.Fuzz(func(t *testing.T, original, payload []byte, mark uint32) {
		if len(payload) == 0 {
			payload = []byte("x")
		}
		if mark == 0 {
			mark = 1
		}
		executor := NewExecutor(ExecutorConfig{MTU: 1500, MaxWrites: 4, MaxBytes: 4096, ProcessedMark: mark, RequirePlanMark: true}, &recordingSender{})
		plan := ActionPlan{Valid: true, ProcessedMark: mark, TotalBytes: len(payload), Writes: []PlannedWrite{{StreamStart: 0, StreamEnd: uint64(len(payload)), Sequence: 1, Payload: payload}}}
		_ = executor.Execute(original, plan)
	})
}
