package mtproto

import (
	"errors"
	"testing"
)

func TestRouteLadderFallsBackWithoutRecursion(t *testing.T) {
	p := DefaultRoutePlan()
	seen := []BridgeRoute{}
	a := ExecuteRoutePlan(p, func(r BridgeRoute) error {
		seen = append(seen, r)
		if r != RouteDirect {
			return errors.New("down")
		}
		return nil
	})
	if !a.Success || a.Route != RouteDirect || len(seen) != 3 {
		t.Fatalf("ladder failed: %+v %v", a, seen)
	}
}
