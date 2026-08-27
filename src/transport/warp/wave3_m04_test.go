package transportwarp

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// TestM04EPERMClassifiedDialPolicy covers M-04: SO_MARK / source-bind
// privilege errnos must classify as FailureDialPolicy, whether the errno is
// naked or already wrapped in a net.OpError by the dialer. Before M-04 these
// fell through to FailureTCPConnect.
func TestM04EPERMClassifiedDialPolicy(t *testing.T) {
	cases := map[string]error{
		"naked EPERM":  unix.EPERM,
		"naked EACCES": unix.EACCES,
		// Source path wraps the errno, matching what the classifier sees.
		"SO_MARK wrapped":  fmt.Errorf("transportwarp: SO_MARK: %w", unix.EPERM),
		"bind device wrap": fmt.Errorf("transportwarp: bind device %q: %w", "wlan0", unix.EPERM),
	}
	for name, err := range cases {
		if got, want := classifyDialError(err), FailureDialPolicy; got != want {
			t.Errorf("%s: classifyDialError = %q want %q", name, got, want)
		}
	}
}
