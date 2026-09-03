package mtproto

import "testing"

func TestBridgeOutcomeRequiresReasonAndPreservesPrefix(t *testing.T) {
	o := LegacyBridgeOutcome(false, PrefixSnapshot{Data: []byte{1, 2, 3}}, ReasonPartialPrefix)
	if !o.Valid() || len(o.Prefix) != 3 {
		t.Fatalf("invalid outcome: %+v", o)
	}
	if LegacyBridgeOutcome(true, nil, ReasonHandshakeAccepted).Disposition != BridgeHandled {
		t.Fatal("handled adapter failed")
	}
}
