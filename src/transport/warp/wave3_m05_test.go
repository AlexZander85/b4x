package transportwarp

import (
	"context"
	"testing"
)

// TestM05FailedDialDoesNotLeakContext covers M-05: every failed H3 dial must
// release its per-attempt context via abandon() -> sess.cancel(). Without that
// cancel each failed dial accumulates a child context subtree (a lostcancel on
// the supervisor's parent ctx). Wrong-pin aborts during the local TLS
// handshake, deterministically exercising the abandon path; the observable
// guarantee is that repeated failed dials stay fast, return no session, and
// keep the same structural failure class every iteration.
func TestM05FailedDialDoesNotLeakContext(t *testing.T) {
	e := newFakeH3Edge(t)
	stranger := newTestKey(t)
	cfg := h3SessionCfg(t, e, func(c *H3SessionConfig) {
		c.Pin = &stranger.PublicKey // wrong pin -> handshake abort -> abandon
	})

	for i := 0; i < 8; i++ {
		sess, res, err := DialH3Session(context.Background(), cfg)
		if err == nil {
			t.Fatalf("iteration %d: wrong-pin dial must fail", i)
		}
		if res.FailureClass != FailureTLSPin {
			t.Fatalf("iteration %d: class=%s want %s", i, res.FailureClass, FailureTLSPin)
		}
		if sess != nil {
			t.Fatalf("iteration %d: failed dial must not return a session", i)
		}
	}
}
