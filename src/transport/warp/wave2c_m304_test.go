package transportwarp

import "testing"

// ---- M3-04: pin-family errors must never masquerade as a network verdict ----

// The full pin family (rotation ErrPinNotECDSA, bad cert ErrBadEndpointCert,
// and the classic ErrPinMismatch) must classify as FailureTLSPin on the H3
// path, and FailureTLSPin must never be a ladder transport-switch class.
func TestClassifyH3HandshakeErrorPinFamilyIsTLSPin(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"mismatch", ErrPinMismatch},
		{"not-ecdsa-rotation", ErrPinNotECDSA},
		{"bad-endpoint-cert", ErrBadEndpointCert},
	}
	for _, tc := range cases {
		if got := classifyH3HandshakeError(tc.err); got != FailureTLSPin {
			t.Fatalf("%s: classifyH3HandshakeError = %q, want %q", tc.name, got, FailureTLSPin)
		}
		if isLadderSwitchClass(FailureTLSPin) {
			t.Fatalf("%s: FailureTLSPin must never be a ladder switch class", tc.name)
		}
	}
}

// Same family on the H2 dial path: FailureTLSPin, NOT the generic TCP failure.
func TestClassifyDialErrorPinFamilyIsTLSPin(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"mismatch", ErrPinMismatch},
		{"not-ecdsa-rotation", ErrPinNotECDSA},
		{"bad-endpoint-cert", ErrBadEndpointCert},
	}
	for _, tc := range cases {
		if got := classifyDialError(tc.err); got != FailureTLSPin {
			t.Fatalf("%s: classifyDialError = %q, want %q", tc.name, got, FailureTLSPin)
		}
	}
}

// isLadderSwitchClass is future-proofed: pin stays outside the switch set, and
// the network verdicts that ARE switch classes keep being switch classes.
func TestLadderSwitchClassExcludesPinKeepsNetwork(t *testing.T) {
	if isLadderSwitchClass(FailureTLSPin) {
		t.Fatal("FailureTLSPin must not be in the ladder switch classes")
	}
	for _, cls := range []string{FailureUDPEgressBlocked, FailureTLSAlert} {
		if !isLadderSwitchClass(cls) {
			t.Fatalf("%s must remain a ladder switch class", cls)
		}
	}
}
