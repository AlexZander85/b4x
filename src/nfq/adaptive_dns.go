package nfq

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/dns"
	"github.com/daniellavrushin/b4/log"
)

// RawAdaptiveDNSResolver changes only the upstream DNS path/transport. The
// original client wire message is supplied verbatim so EDNS/DNSSEC options are
// preserved.
type RawAdaptiveDNSResolver func(ctx context.Context, query []byte) ([]byte, error)

var adaptiveDNSRuntime struct {
	sync.RWMutex
	ready    func() bool
	resolver RawAdaptiveDNSResolver
	canary   *adaptiveDNSCanarySession
}

// ConfigureAdaptiveDNSRuntime wires the globally promoted adaptive resolver.
// When ready returns false NFQ leaves ordinary client DNS untouched.
func ConfigureAdaptiveDNSRuntime(ready func() bool, resolver RawAdaptiveDNSResolver) {
	adaptiveDNSRuntime.Lock()
	adaptiveDNSRuntime.ready = ready
	adaptiveDNSRuntime.resolver = resolver
	adaptiveDNSRuntime.Unlock()
}

type adaptiveDNSCanarySession struct {
	clientMAC string
	resolver  RawAdaptiveDNSResolver
	minimum   int
	deadline  time.Time

	mu        sync.Mutex
	successes int
	failures  int
	done      chan struct{}
	resultErr error
	closed    bool
}

// DNSCanaryResult is returned only after traffic from the requested LAN
// source actually traversed the candidate DNS path.
type DNSCanaryResult struct {
	ClientMAC string
	Successes int
	Failures  int
}

// RunAdaptiveDNSCanary arms a single source-scoped LAN canary and waits for
// fresh DNS queries from that source. Router-origin probes cannot satisfy this
// gate. Any candidate resolution failure aborts the canary; promotion remains
// fail-closed.
func RunAdaptiveDNSCanary(ctx context.Context, clientMAC string, minimum int, window time.Duration, resolver RawAdaptiveDNSResolver) (DNSCanaryResult, error) {
	clientMAC = normalizeCanaryMAC(clientMAC)
	if clientMAC == "" {
		return DNSCanaryResult{}, errors.New("LAN canary requires client MAC")
	}
	if resolver == nil {
		return DNSCanaryResult{}, errors.New("LAN canary resolver is not wired")
	}
	if minimum <= 0 {
		minimum = 3
	}
	if window <= 0 {
		window = 30 * time.Second
	}
	s := &adaptiveDNSCanarySession{
		clientMAC: clientMAC,
		resolver:  resolver,
		minimum:   minimum,
		deadline:  time.Now().Add(window),
		done:      make(chan struct{}),
	}
	adaptiveDNSRuntime.Lock()
	if adaptiveDNSRuntime.canary != nil {
		adaptiveDNSRuntime.Unlock()
		return DNSCanaryResult{}, errors.New("another adaptive DNS LAN canary is active")
	}
	adaptiveDNSRuntime.canary = s
	adaptiveDNSRuntime.Unlock()
	defer func() {
		adaptiveDNSRuntime.Lock()
		if adaptiveDNSRuntime.canary == s {
			adaptiveDNSRuntime.canary = nil
		}
		adaptiveDNSRuntime.Unlock()
	}()

	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return s.snapshot(), ctx.Err()
	case <-timer.C:
		return s.snapshot(), fmt.Errorf("adaptive DNS LAN canary timed out before %d successful queries", minimum)
	case <-s.done:
		result := s.snapshot()
		s.mu.Lock()
		err := s.resultErr
		s.mu.Unlock()
		if err != nil {
			return result, err
		}
		return result, nil
	}
}

func (s *adaptiveDNSCanarySession) snapshot() DNSCanaryResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return DNSCanaryResult{ClientMAC: s.clientMAC, Successes: s.successes, Failures: s.failures}
}

func (s *adaptiveDNSCanarySession) record(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if err != nil {
		s.failures++
		s.resultErr = fmt.Errorf("candidate DNS failed for LAN canary: %w", err)
		s.closed = true
		close(s.done)
		return
	}
	s.successes++
	if s.successes >= s.minimum {
		s.closed = true
		close(s.done)
	}
}

func normalizeCanaryMAC(mac string) string {
	mac = strings.TrimSpace(strings.ToLower(mac))
	if mac == "" {
		return ""
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return ""
	}
	return strings.ToLower(hw.String())
}

func adaptiveDNSResolverForClient(srcMAC string) (RawAdaptiveDNSResolver, *adaptiveDNSCanarySession, bool) {
	srcMAC = normalizeCanaryMAC(srcMAC)
	adaptiveDNSRuntime.RLock()
	defer adaptiveDNSRuntime.RUnlock()
	if s := adaptiveDNSRuntime.canary; s != nil && s.clientMAC == srcMAC && time.Now().Before(s.deadline) {
		return s.resolver, s, true
	}
	if adaptiveDNSRuntime.ready != nil && adaptiveDNSRuntime.resolver != nil && adaptiveDNSRuntime.ready() {
		return adaptiveDNSRuntime.resolver, nil, true
	}
	return nil, nil, false
}

// tryAdaptiveDNSRedirect consumes one client UDP/53 query when either an
// active global binding or a matching source-scoped canary is available.
// Explicit per-set DNS redirects call this only after their own precedence has
// been evaluated.
func (w *Worker) tryAdaptiveDNSRedirect(vc *verdictCtx, ipVersion byte, clientPort uint16, payload, raw []byte, srcMAC string, set *config.SetConfig, cfg *config.Config) bool {
	resolver, canary, ok := adaptiveDNSResolverForClient(srcMAC)
	if !ok {
		return false
	}
	var clientIP, originalDst net.IP
	if ipVersion == IPv4 {
		if len(raw) < 20 {
			return false
		}
		clientIP = append(net.IP(nil), raw[12:16]...)
		originalDst = append(net.IP(nil), raw[16:20]...)
	} else {
		if len(raw) < 40 {
			return false
		}
		clientIP = append(net.IP(nil), raw[8:24]...)
		originalDst = append(net.IP(nil), raw[24:40]...)
	}
	if _, _, _, valid := dns.ParseQuestion(payload); !valid {
		// Once adaptive DNS owns this client path, unsupported/malformed DNS is
		// failed closed rather than leaked to a potentially intercepted UDP/53.
		vc.drop()
		w.sendDNSResponseToClient(ipVersion, originalDst, clientIP, clientPort, dns.BuildServfailResponse(payload))
		if canary != nil {
			canary.record(errors.New("unsupported DNS question shape"))
		}
		return true
	}

	query := append([]byte(nil), payload...)
	vc.drop()
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.resolveAdaptiveDNSForClient(ipVersion, query, clientIP, clientPort, originalDst, srcMAC, set, cfg, resolver, canary)
	}()
	return true
}

func (w *Worker) resolveAdaptiveDNSForClient(ipVersion byte, query []byte, clientIP net.IP, clientPort uint16, originalDst net.IP, srcMAC string, set *config.SetConfig, cfg *config.Config, resolver RawAdaptiveDNSResolver, canary *adaptiveDNSCanarySession) {
	ctx, cancel := context.WithTimeout(w.ctx, dohRedirectTimeout)
	defer cancel()
	resp, err := resolver(ctx, query)
	if err != nil || len(resp) == 0 {
		if err == nil {
			err = errors.New("empty adaptive DNS response")
		}
		log.Tracef("adaptive DNS: candidate/active path failed for %s: %v", srcMAC, err)
		w.sendDNSResponseToClient(ipVersion, originalDst, clientIP, clientPort, dns.BuildServfailResponse(query))
		if canary != nil {
			canary.record(err)
		}
		return
	}
	w.sendDNSResponseToClient(ipVersion, originalDst, clientIP, clientPort, resp)
	if cfg != nil && cfg.System.Classifier.Flags.ScopedDNSHintsEnabled {
		w.observeDNSResponse(cfg, resp, clientIP, srcMAC, "adaptive-dns")
	}
	if set != nil && cfg != nil && set.Routing.Enabled && !set.Targets.DomainOnly && !cfg.Queue.IsDiscovery && RoutingHandleDNSFunc != nil {
		if ips := dns.ParseResponseIPs(resp); len(ips) > 0 {
			RoutingHandleDNSFunc(cfg, set, ips)
		}
	}
	if canary != nil {
		canary.record(nil)
	}
}
