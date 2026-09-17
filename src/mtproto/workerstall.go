package mtproto

import (
	"sync"
	"time"

	"github.com/daniellavrushin/b4/log"
)

// A Cloudflare Worker relay stops forwarding partway through a session and then
// holds the WebSocket open in silence - no close frame, no reset - so the relay
// has nothing to fail on and the client waits out its own receive timeout,
// reconnects, and is handed the same dead route again. Measured against a real
// Worker from a censored network: not one of 73 sessions carried past 17 KB,
// while Telegram's own WebSocket edge carried 1.1 MB on the same box at the same
// time. Record the Worker that did it and rank it below the other transports for
// a while, so the reconnect lands somewhere else.
//
// Field complement (b4x 17.09): dead-deployed shared Workers also produce the
// pure EOF-zero signature (up>0 down=0, 52/84 sessions) and 503 bursts on the
// shared pool; both funnel into the same cooldown map through
// recordCFProgress/workerRecordStall so planTransports demotes them alike.
const workerStallCooldown = 10 * time.Minute

var (
	workerStallMu    sync.Mutex
	workerStallUntil = map[string]time.Time{}
)

func workerInCooldown(domain string) bool {
	if domain == "" {
		return false
	}
	workerStallMu.Lock()
	defer workerStallMu.Unlock()
	t, ok := workerStallUntil[domain]
	if !ok {
		return false
	}
	if time.Now().After(t) {
		delete(workerStallUntil, domain)
		return false
	}
	return true
}

func workerRecordStall(domain string) {
	if domain == "" {
		return
	}
	workerStallMu.Lock()
	_, had := workerStallUntil[domain]
	workerStallUntil[domain] = time.Now().Add(workerStallCooldown)
	workerStallMu.Unlock()
	if !had {
		log.Infof("%s worker %s stopped relaying mid-session; ranking it below other transports for %s",
			tg(""), domain, workerStallCooldown)
	}
}

func workerResetStall() {
	workerStallMu.Lock()
	defer workerStallMu.Unlock()
	workerStallUntil = map[string]time.Time{}
}
