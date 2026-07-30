package warp

import (
	"testing"
	"time"
)

func TestRSTDefenseDefaultsObservationOnly(t *testing.T) {
	o := RSTObservation{Early: true, SequenceValid: true, WindowValid: true}
	if !o.SpoofLike() {
		t.Fatal("rst classification failed")
	}
	d := RSTDefense{}
	if d.AllowEnforcement(time.Now()) {
		t.Fatal("rst enforcement enabled by observation")
	}
}
