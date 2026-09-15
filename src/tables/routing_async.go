// Async DNS-routing application (upstream b4 lesson, issue #296): the
// synchronous RoutingHandleDNS ran `ip`/`ipset`/`nft` subprocesses directly
// inside the nfqueue reader goroutine (nfq/dns.go and the escalation path
// both called it per DNS response). While the reader was blocked in exec,
// the kernel silently dropped every packet that arrived at the queue —
// observed in the field as multi-second resolution stalls under load with
// no error logged anywhere.
//
// This file moves the whole route-application path onto ONE background
// goroutine fed by a bounded channel:
//
//   - jobs are (cfg, set, ips) snapshots; the config pointer semantics are
//     the package canon (immutable swap-on-update snapshots), so running
//     them off-thread is safe;
//   - a (setID|ip) dedup cache with IPTTL/2 refresh skips the exec entirely
//     for addresses already routed — one DNS answer per address per
//     half-TTL, instead of one per every response;
//   - overflow DROPS the job (routing is eventually-consistent: the next
//     matching DNS response re-submits) and logs throttled (max once per
//     10 s) with a drop counter for observability;
//   - every job runs under recover(): a panic in firewall plumbing must
//     never take the daemon down.
//
// The worker starts lazily on first submit and outlives individual calls
// (process lifetime); tests can drain it via RoutingAsyncDrain.
package tables

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

const (
	// routingAsyncQueueCap bounds the pending job count. Overflow drops
	// (with a metric) rather than blocking the packet path — the whole
	// point of the async seam.
	routingAsyncQueueCap = 1024
	// routingAsyncDropLogEvery throttles overflow warnings: a DNS burst
	// must not turn the log into a second queue.
	routingAsyncDropLogEvery = 10 * time.Second
)

// RoutingAsyncDrops counts jobs dropped on queue overflow (observability;
// exposed via status/diagnostics consumers of the tables package).
var RoutingAsyncDrops atomic.Int64

type routingAsyncJob struct {
	cfg *config.Config
	set *config.SetConfig
	ips []net.IP
}

var (
	routingAsyncOnce    sync.Once
	routingAsyncCh      chan routingAsyncJob
	routingAsyncDedup   sync.Map // "setID|ip" -> last applied time.Time
	routingAsyncDropLog sync.Map // single throttle key -> last log time
)

// routingAsyncStart launches the single worker goroutine (idempotent).
func routingAsyncStart() {
	routingAsyncOnce.Do(func() {
		routingAsyncCh = make(chan routingAsyncJob, routingAsyncQueueCap)
		go func() {
			for job := range routingAsyncCh {
				routingAsyncApply(job)
			}
		}()
	})
}

// routingAsyncDedupKey builds the dedup cache key for one address.
func routingAsyncDedupKey(setID string, ip net.IP) string {
	return setID + "|" + ip.String()
}

// routingAsyncSkipFresh reports whether (setID, ip) was applied recently
// enough (inside the IPTTL/2 refresh window) that re-applying it is a
// no-op exec. Mirrors the RoutingLearnIP canon (routeLearnLast).
func routingAsyncSkipFresh(set *config.SetConfig, ip net.IP, now time.Time) bool {
	ttl := set.Routing.IPTTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}
	refresh := time.Duration(ttl) * time.Second / 2
	key := routingAsyncDedupKey(set.Id, ip)
	if v, ok := routingAsyncDedup.Load(key); ok {
		if t, ok2 := v.(time.Time); ok2 && now.Sub(t) < refresh {
			return true
		}
	}
	routingAsyncDedup.Store(key, now)
	// Bound the dedup map: drop entries older than the TTL horizon.
	if n := routingAsyncDedupSize(); n > 4096 {
		cutoff := now.Add(-time.Duration(ttl) * time.Second)
		routingAsyncDedup.Range(func(k, v any) bool {
			if t, ok := v.(time.Time); ok && t.Before(cutoff) {
				routingAsyncDedup.Delete(k)
			}
			return true
		})
	}
	return false
}

// routingAsyncDedupSize is a cheap length estimate for the bound check.
func routingAsyncDedupSize() int {
	n := 0
	routingAsyncDedup.Range(func(_, _ any) bool { n++; return true })
	return n
}

// routingAsyncThrottledWarn logs the overflow at most once per window.
func routingAsyncThrottledWarn(now time.Time) {
	const key = "overflow"
	if v, ok := routingAsyncDropLog.Load(key); ok {
		if t, ok2 := v.(time.Time); ok2 && now.Sub(t) < routingAsyncDropLogEvery {
			return
		}
	}
	routingAsyncDropLog.Store(key, now)
	log.Warnf("Routing: async queue overflow (%d cap), DNS-routing job dropped — next matching response re-submits",
		routingAsyncQueueCap)
}

// routingAsyncApply runs one job under recover with per-address dedup.
func routingAsyncApply(job routingAsyncJob) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Routing: async job panicked (recovered): %v", r)
		}
	}()
	if job.cfg == nil || job.set == nil || len(job.ips) == 0 {
		return
	}
	if !job.set.Routing.Enabled || job.set.Targets.DomainOnly {
		return
	}
	now := time.Now()
	pending := job.ips[:0:0]
	for _, ip := range job.ips {
		if !routingAsyncSkipFresh(job.set, ip, now) {
			pending = append(pending, ip)
		}
	}
	if len(pending) == 0 {
		return
	}
	RoutingHandleDNS(job.cfg, job.set, pending)
}

// RoutingHandleDNSAsync is the packet-path-safe entry: it filters cheap
// conditions inline (identical to the RoutingHandleDNS preconditions) and
// enqueues the job. Callers on the nfqueue read path must use THIS entry;
// RoutingHandleDNS stays exported for the sync paths (apply-time,
// discovery, tests).
func RoutingHandleDNSAsync(cfg *config.Config, set *config.SetConfig, ips []net.IP) {
	if cfg == nil || set == nil || len(ips) == 0 || !set.Routing.Enabled {
		return
	}
	if set.Targets.DomainOnly {
		return
	}
	if cfg.Queue.IsDiscovery {
		return
	}
	routingAsyncStart()
	select {
	case routingAsyncCh <- routingAsyncJob{cfg: cfg, set: set, ips: append([]net.IP(nil), ips...)}:
	default:
		RoutingAsyncDrops.Add(1)
		routingAsyncThrottledWarn(time.Now())
	}
}

// RoutingAsyncDrain waits until every queued job has been applied (test
// seam: the async seam must stay observable, not sleep-and-hope).
func RoutingAsyncDrain(timeout time.Duration) bool {
	if routingAsyncCh == nil {
		return true
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(routingAsyncCh) == 0 {
			// One extra beat: the worker may be mid-job.
			time.Sleep(20 * time.Millisecond)
			if len(routingAsyncCh) == 0 {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// RoutingAsyncReset clears the dedup cache (test seam).
func RoutingAsyncReset() {
	routingAsyncDedup.Range(func(k, _ any) bool {
		routingAsyncDedup.Delete(k)
		return true
	})
}
