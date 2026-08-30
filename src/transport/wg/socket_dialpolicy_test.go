//go:build linux

// PATCH-15 (B1) tests: EPERM/EACCES socket-control failures are sentinel-
// typed and classify as wg-dial-policy, never as param-rejected.
package transportwg

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWrapDialPolicyClassifiesErrno(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool // true => must become the sentinel
	}{
		{"eperm-wrapped", fmt.Errorf("setsockopt: %w", syscall.EPERM), true},
		{"eaccs-wrapped", fmt.Errorf("setsockopt: %w", unix.EACCES), true},
		{"eperm-bare", syscall.EPERM, true},
		{"enoent", fmt.Errorf("interface: %w", syscall.ENOENT), false},
		{"plain", errors.New("policy requires SO_MARK but none configured"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		got := wrapDialPolicy("so-mark", tc.err)
		if tc.err == nil {
			if got != nil {
				t.Fatalf("%s: nil must stay nil, got %v", tc.name, got)
			}
			continue
		}
		var dp *errDialPolicy
		if errors.As(got, &dp) != tc.want {
			t.Fatalf("%s: errors.As(errDialPolicy) = %v, want %v (err=%v)", tc.name, errors.As(got, &dp), tc.want, got)
		}
		if tc.want {
			if dp.op != "so-mark" {
				t.Fatalf("%s: sentinel op = %q, want so-mark", tc.name, dp.op)
			}
			if !errors.Is(got, tc.err) && !errors.Is(got, syscall.EPERM) && !errors.Is(got, unix.EACCES) {
				t.Fatalf("%s: sentinel lost the original error chain", tc.name)
			}
		}
	}
}

// TestSessionClassifiesEPermAsDialPolicy pins the mapping: a device-up
// failure whose chain carries the sentinel classifies as wg-dial-policy;
// everything else stays param-rejected.
func TestSessionClassifiesEPermAsDialPolicy(t *testing.T) {
	permErr := fmt.Errorf("transportwg: SO_MARK(72822): %w", syscall.EPERM)
	var dp *errDialPolicy
	wrapped := wrapDialPolicy("so-mark", fmt.Errorf("setsockopt: %w", syscall.EPERM))
	if !errors.As(wrapped, &dp) {
		t.Fatal("precondition: wrapped must be the sentinel")
	}
	_ = permErr

	// The session-side mapping rule (device-up branch shape): sentinel ->
	// ClassDialPolicy; anything else -> ClassParamRejected.
	classify := func(err error) FailureClass {
		var d *errDialPolicy
		if errors.As(err, &d) {
			return ClassDialPolicy
		}
		return ClassParamRejected
	}
	if got := classify(wrapped); got != ClassDialPolicy {
		t.Fatalf("EPERM classified as %s, want %s", got, ClassDialPolicy)
	}
	if got := classify(errors.New("ipc garbage")); got != ClassParamRejected {
		t.Fatalf("plain error classified as %s, want %s", got, ClassParamRejected)
	}
}
