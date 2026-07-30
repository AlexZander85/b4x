package mtproto

import "testing"

func TestBridgeDiagnosticsRedactsSecret(t *testing.T) {
	x := BridgeTrace{Reason: ReasonHandshakeAccepted, SecretPresent: true}
	if x.Redacted().SecretPresent {
		t.Fatal("secret leaked in trace")
	}
	if DefaultBridgeDiagnostics().Mode != BridgeBeginnerAuto {
		t.Fatal("beginner default missing")
	}
}
