package nfq

import (
	"context"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/log"
)

// Storm gauge (Часть 3 follow-up, поле 23.08): during Google edge-churn
// storms the phone's masked-QUIC traffic scatters across dozens/hundreds of
// endpoints per hour (observed 105 vs norm ~20-45), while our own layers
// behave normally. This gauge turns that observation into ONE grep-able
// hourly line, so the next "it lags" report is answered without log
// archaeology:
//
//	[storm] uniqueDst=105 level=STORM (calm<40<=churn<80<=storm)
//
// Purely observational: counts distinct fake-UDP destinations, never acts.

const (
	stormWindow   = time.Hour
	stormCalmMax  = 40 // unique dst/hour
	stormChurnMax = 80 // >= this is STORM
)

type stormStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var stormG = &stormStore{seen: make(map[string]time.Time)}

func stormNote(dst string, now time.Time) {
	if !stormEnabled || dst == "" {
		return
	}
	stormG.mu.Lock()
	stormG.seen[dst] = now
	stormG.mu.Unlock()
}

func (s *stormStore) snapshot(now time.Time) (unique int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, ts := range s.seen {
		if now.Sub(ts) > stormWindow {
			delete(s.seen, ip)
			continue
		}
		unique++
	}
	return unique
}

func stormLevel(unique int) string {
	switch {
	case unique >= stormChurnMax:
		return "STORM"
	case unique >= stormCalmMax:
		return "CHURN"
	default:
		return "CALM"
	}
}

func StartStormGauge(ctx context.Context, pool *Pool) {
	if !stormEnabled || ctx == nil || pool == nil || len(pool.Workers) == 0 {
		return
	}
	log.Infof("[storm] gauge started (window=%v calm<%d<=churn<%d<=storm)",
		stormWindow, stormCalmMax, stormChurnMax)
	go func() {
		// First summary after one window so the number means something.
		t := time.NewTicker(stormWindow)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				unique := stormG.snapshot(now)
				log.Warnf("[storm] uniqueDst=%d level=%s", unique, stormLevel(unique))
				if unique >= stormCalmMax {
					log.Warnf("[storm] external Google edge churn suspected; router-side layers are NOT the cause (see state_packet %s)", "2026-08-23")
				}
			}
		}
	}()
}
