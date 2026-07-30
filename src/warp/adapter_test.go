package warp

import "testing"

func TestAdapterIsHandshakeOnlyAndBounded(t *testing.T) {
	a := TransportCamouflageAdapter{Budget: AdapterBudget{MaxPackets: 4, MaxBytes: 1024, MaxDurationMS: 100}, Authorized: true}
	if a.Apply(1, 10) != nil {
		t.Fatal("valid adapter failed")
	}
	if a.Apply(5, 10) == nil {
		t.Fatal("packet budget ignored")
	}
	a.Cutoff()
	if a.Apply(1, 1) == nil {
		t.Fatal("established mutation accepted")
	}
}
