package mtproto

import "testing"

func TestBridgeConfigLegacyDefaultsAndValidation(t *testing.T) {
	c := MergeLegacyBridgeConfig(true, 0, 0)
	if !c.Valid() || c.HardDeadlineMS != 30000 {
		t.Fatal(c)
	}
	c.HardDeadlineMS = 1
	if ValidateBridgeConfig(c) == nil {
		t.Fatal("invalid deadline accepted")
	}
}
