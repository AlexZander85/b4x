package warp

import "testing"

func TestCutoffRejectsWrongGenerationAndDuplicate(t *testing.T) {
	m := CutoffMachine{InstanceID: "i", SessionID: "s", ProcessGeneration: 1, ConfigGeneration: 2, State: CutoffPending}
	e := MasqueConnectedEvent{InstanceID: "i", SessionID: "s", ProcessGeneration: 1, ConfigGeneration: 2, Success: true, Sequence: 1}
	if !m.Apply(e) || m.State != CutoffEstablished {
		t.Fatal("connect event failed")
	}
	if m.Apply(e) {
		t.Fatal("duplicate accepted")
	}
	e.Sequence = 2
	e.ConfigGeneration = 3
	if m.Apply(e) {
		t.Fatal("wrong generation accepted")
	}
}
