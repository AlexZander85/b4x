package proton

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// RTTProbeDial is the minimal dial seam used by the Proton latency sampler.
// It intentionally measures only a TCP connect to the node's literal entry
// address on port 443: no DNS and no TLS handshake. A successful sample is
// only a ranking hint; the AWG/WireGuard trust gate remains authoritative.
type RTTProbeDial func(ctx context.Context, network, address string) (net.Conn, error)

const (
	DefaultRTTProbeParallel = 16
	DefaultRTTProbeTimeout  = 1500 * time.Millisecond
)

// ProbeTCP443RTT measures each unique Proton entry IP in parallel. Failures
// are omitted from the returned map so callers can keep those nodes as
// unmeasured fallbacks instead of treating TCP reachability as a VPN verdict.
func ProbeTCP443RTT(ctx context.Context, cands []Candidate, dial RTTProbeDial) map[string]time.Duration {
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}

	unique := make([]string, 0, len(cands))
	seen := make(map[string]struct{}, len(cands))
	for _, cand := range cands {
		ip := cand.Node.EntryIP
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}

	parallel := DefaultRTTProbeParallel
	if len(unique) < parallel {
		parallel = len(unique)
	}
	if parallel == 0 {
		return map[string]time.Duration{}
	}

	type job struct{ ip string }
	jobs := make(chan job)
	out := make(chan struct {
		ip  string
		rtt time.Duration
		ok  bool
	}, len(unique))

	var wg sync.WaitGroup
	wg.Add(parallel)
	for i := 0; i < parallel; i++ {
		go func() {
			defer wg.Done()
			for j := range jobs {
				pctx, cancel := context.WithTimeout(ctx, DefaultRTTProbeTimeout)
				start := time.Now()
				conn, err := dial(pctx, "tcp", net.JoinHostPort(j.ip, "443"))
				rtt := time.Since(start)
				cancel()
				if conn != nil {
					_ = conn.Close()
				}
				select {
				case out <- struct {
					ip  string
					rtt time.Duration
					ok  bool
				}{j.ip, rtt, err == nil}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range unique {
			select {
			case jobs <- job{ip: ip}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	rtts := make(map[string]time.Duration, len(unique))
	for r := range out {
		if r.ok {
			rtts[r.ip] = r.rtt
		}
	}
	return rtts
}

// RankCandidatesByRTT returns a stable copy ordered by measured TCP/443 RTT.
// Measured nodes come first; unmeasured nodes retain their previous queue
// order (load/score/country interleave). This is deliberately NOT a health
// filter: a TCP success does not prove UDP/WireGuard works, and a TCP failure
// does not remove a candidate from the AWG trust-gated seek ladder.
func RankCandidatesByRTT(cands []Candidate, rtts map[string]time.Duration) []Candidate {
	out := append([]Candidate(nil), cands...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := rtts[out[i].Node.EntryIP]
		rj, jok := rtts[out[j].Node.EntryIP]
		if iok != jok {
			return iok
		}
		if !iok {
			return false
		}
		if ri == rj {
			return false
		}
		return ri < rj
	})
	return out
}
