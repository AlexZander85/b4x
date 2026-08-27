package transportwarp

import (
	"errors"
	"testing"
)

// ---- M3-11: inner MTU must leave NestedMTUMargin headroom under the outer ----

// The gradient rule is enforced as inner <= outer-NestedMTUMargin: the
// exactly-marginal case (1200 under 1280) is valid, anything tighter is
// rejected before the inner packets start dropping at the outbound-MTU guard.
func TestNestedMTUMarginTable(t *testing.T) {
	cases := []struct {
		name         string
		inner, outer int
		want         error
	}{
		{"comfortable", 1199, 1280, nil},
		{"exact boundary", 1200, 1280, nil},
		{"margin violated", 1279, 1280, ErrMTUGradient},
		{"equal mtus", 1280, 1280, ErrMTUGradient},
		{"defaults honor margin", 0, 0, nil}, // -> 1200 under 1280
	}
	for _, tc := range cases {
		cfg := validNestedConfig()
		if tc.inner > 0 {
			cfg.InnerTemplate.MTU = tc.inner
		}
		if tc.outer > 0 {
			cfg.BaseTemplate.MTU = tc.outer
		}
		err := cfg.Validate()
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}
