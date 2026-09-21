package fxvpservice

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestTickRenewsLiveSessionBearer pins b4x-0rw8: when the pool re-mints the
// proxy pass (2-min renewal lead / quota poll), the LIVE session's bearer must
// be updated in place. Before the fix the pool's pass was refreshed but the
// serving H2 session kept the old one, so the nested data plane 401'd at pass
// expiry while the connection stayed alive (keepalive PING still answered).
func TestTickRenewsLiveSessionBearer(t *testing.T) {
	// A 30s pass lifetime is already inside the pool's 2-min renewal lead, so
	// the first tick renews it.
	fx := newLiveFixtureTTL(t, 15, 30*time.Second)
	ctx := context.Background()

	sess := newFakeSession()
	fx.rt.session = sess
	fx.rt.sessionHost = "atn1.m1.fastly-masque.net:2499"

	fx.rt.tick(ctx)

	tok := sess.lastToken()
	if tok == "" {
		t.Fatal("renewed proxy pass was not applied to the live session in place")
	}
	if strings.HasPrefix(tok, "Bearer ") {
		t.Fatalf("UpdateToken must receive the RAW pass (carriers add the scheme): %q", tok)
	}
	if sess.closed != 0 {
		t.Fatalf("renewal must not tear down the live session (closes=%d)", sess.closed)
	}
	var renewed bool
	for _, ev := range fx.rt.Status().Events {
		if ev.Type == "fxvpn_session_bearer_rotated" {
			renewed = true
		}
	}
	if !renewed {
		t.Fatal("fxvpn_session_bearer_rotated event missing on pass renewal")
	}
}
