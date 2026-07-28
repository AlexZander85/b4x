package action

import "fmt"

type ActionBudgets struct {
	MaxWritesPerHello uint16
	MaxFakeBytes      uint32
	MaxAmplification  float64
}

func DefaultActionBudgets() ActionBudgets {
	return ActionBudgets{MaxWritesPerHello: 16, MaxFakeBytes: 64 * 1024, MaxAmplification: 4}
}

func (b ActionBudgets) normalized() ActionBudgets {
	defaults := DefaultActionBudgets()
	if b.MaxWritesPerHello == 0 {
		b.MaxWritesPerHello = defaults.MaxWritesPerHello
	}
	if b.MaxFakeBytes == 0 {
		b.MaxFakeBytes = defaults.MaxFakeBytes
	}
	if b.MaxAmplification <= 0 {
		b.MaxAmplification = defaults.MaxAmplification
	}
	return b
}

func (b ActionBudgets) Check(inputBytes int, writes int, generatedBytes int) error {
	b = b.normalized()
	if inputBytes <= 0 || writes < 0 || generatedBytes < 0 {
		return fmt.Errorf("%w: invalid action budget input", ErrPlanBudget)
	}
	if writes > int(b.MaxWritesPerHello) {
		return fmt.Errorf("%w: writes=%d max=%d", ErrPlanBudget, writes, b.MaxWritesPerHello)
	}
	if generatedBytes > int(b.MaxFakeBytes) {
		return fmt.Errorf("%w: generated_bytes=%d max=%d", ErrPlanBudget, generatedBytes, b.MaxFakeBytes)
	}
	amplification := float64(inputBytes+generatedBytes) / float64(inputBytes)
	if amplification > b.MaxAmplification {
		return fmt.Errorf("%w: amplification=%.2f max=%.2f", ErrPlanBudget, amplification, b.MaxAmplification)
	}
	return nil
}

func IsProcessedMark(mark, processedMask uint32) bool {
	return processedMask != 0 && mark&processedMask == processedMask
}
