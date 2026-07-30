package warp

import "testing"

func TestCoverSNIAlwaysRequiresPin(t *testing.T) {
	c := CoverSNIConfig{Mode: CoverBuiltin, Name: "cover.example", EndpointPin: "pin", DataVersion: "v1"}
	if !c.Valid() {
		t.Fatal("valid cover rejected")
	}
	c.EndpointPin = ""
	if c.Valid() || !c.Insecure() {
		t.Fatal("insecure cover accepted")
	}
}
