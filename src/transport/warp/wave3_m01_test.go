package transportwarp

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestM01AbortRaceDoesNotLeakH2Conn covers M-01: an abort that races an
// in-flight CONNECT must not strand the response/connection. The abort can win
// the select while the server handler is still holding the live h2 conn; M-01
// reaps the late response during an untaken lead and gives the transport a
// second CloseIdleConnections so the conn can't sit in the x/net/http2 idle
// pool with no idle-scavenger.
//
// The 200-commit-vs-abort race is a narrow window (closeQuietly promptly
// cancels the request context), so the test sweeps the handshake budget across
// the server's commit delay repeatedly. Every iteration — abort or untaken
// lead — must drain every server-side handler to zero within the poll window;
// a leak pins a handler + conn and trips the assert.
//
// LIMITATION: the request context is cancelled as soon as the abort branch is
// taken (closeQuietly), so a truly *late* 200 often fails the request outright
// and the harness can't force the sub-millisecond success-race deterministically.
// The sweep maximizes coverage of the boundary nonetheless, and the assertion
// still guards the invariant the finding cares about: no conn may survive an
// abort.
func TestM01AbortRaceDoesNotLeakH2Conn(t *testing.T) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for i := 0; i < 48; i++ {
		fs := newFakeServer(t)
		// Commit the CONNECT within a stable band; the sweep walks the budget
		// across it so ~half the iterations land before and ~half after.
		commit := 60 * time.Millisecond
		fs.setConnectDelay(commit)

		cfg := cfgForServer(t, fs)
		budget := 40*time.Millisecond + time.Duration(i%8)*8*time.Millisecond
		cfg.HandshakeBudget = budget

		parent, cancel := context.WithCancel(context.Background())

		wg.Add(1)
		go func(i int, fs *fakeServer, cancel context.CancelFunc) {
			defer wg.Done()
			sess, res, err := DialSession(parent, cfg)
			if err == nil && res.FailureClass == "" && sess != nil {
				sess.Close() // untaken lead: still close cleanly
			}
			cancel()

			deadline := time.Now().Add(1500 * time.Millisecond)
			for time.Now().Before(deadline) && fs.activeConns() != 0 {
				time.Sleep(20 * time.Millisecond)
			}
			if n := fs.activeConns(); n != 0 {
				t.Errorf("M-01 iter %d (budget=%s): leaked %d active server conns", i, budget, n)
			}
			fs.close()
		}(i, fs, cancel)
	}
}
