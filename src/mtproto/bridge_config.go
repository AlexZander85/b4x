package mtproto

import "errors"

type BridgeConfig struct {
	Enabled                         bool
	SoftDeadlineMS, HardDeadlineMS  int
	MaxPending, MaxPendingPerClient int
	Generation                      uint64
}

func DefaultBridgeConfig() BridgeConfig {
	return BridgeConfig{SoftDeadlineMS: 5000, HardDeadlineMS: 30000, MaxPending: 128, MaxPendingPerClient: 8, Generation: 1}
}
func (c BridgeConfig) Valid() bool {
	return c.HardDeadlineMS >= c.SoftDeadlineMS && c.SoftDeadlineMS > 0 && c.MaxPending > 0 && c.MaxPendingPerClient > 0 && c.Generation > 0
}
func MergeLegacyBridgeConfig(enabled bool, soft, hard int) BridgeConfig {
	c := DefaultBridgeConfig()
	c.Enabled = enabled
	if soft > 0 {
		c.SoftDeadlineMS = soft
	}
	if hard > 0 {
		c.HardDeadlineMS = hard
	}
	return c
}

type BridgeStatus struct {
	Enabled         bool
	Pending, Active int
	Generation      uint64
	LastOutcome     BridgeOutcome
}

func ValidateBridgeConfig(c BridgeConfig) error {
	if !c.Valid() {
		return errors.New("invalid bridge config")
	}
	return nil
}
