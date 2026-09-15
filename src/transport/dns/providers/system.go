package providers

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// SystemForwardProvider uses the current system/router resolver path
// (addendum §32). It records the effective nameserver identity and detects
// recursion when the system resolver points back at a B4X loopback listener.
type SystemForwardProvider struct {
	ResolvConfPath string
	// B4XListeners lists loopback addresses:port owned by B4X; if the system
	// nameserver resolves to one of them the path is recursive.
	B4XListeners []string
	Mark         int
	Timeout      time.Duration
}

func NewSystemForwardProvider(resolvConf string, b4xListeners []string, mark int) *SystemForwardProvider {
	if resolvConf == "" {
		resolvConf = "/etc/resolv.conf"
	}
	return &SystemForwardProvider{ResolvConfPath: resolvConf, B4XListeners: b4xListeners, Mark: mark, Timeout: 3 * time.Second}
}

// EffectiveNameservers parses the system resolver configuration.
func (p *SystemForwardProvider) EffectiveNameservers() ([]netip.Addr, error) {
	f, err := os.Open(p.ResolvConfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if addr, err := netip.ParseAddr(fields[1]); err == nil {
			out = append(out, addr)
		}
	}
	return out, sc.Err()
}

// DetectRecursion reports whether the system resolver path loops back into a
// B4X-owned listener (addendum §32/§47.4).
func (p *SystemForwardProvider) DetectRecursion() (bool, error) {
	ns, err := p.EffectiveNameservers()
	if err != nil {
		return false, err
	}
	owned := map[string]bool{}
	for _, l := range p.B4XListeners {
		host, _, err := net.SplitHostPort(l)
		if err != nil {
			host = l
		}
		owned[host] = true
	}
	for _, addr := range ns {
		if addr.IsLoopback() && owned[addr.String()] {
			return true, nil
		}
	}
	return false, nil
}

func (p *SystemForwardProvider) ID() dnspath.DNSPathID {
	ns, _ := p.EffectiveNameservers()
	seed := "system"
	if len(ns) > 0 {
		seed = ns[0].String()
	}
	sum := sha256.Sum256([]byte(seed))
	ipfam := "ipv4"
	if len(ns) > 0 && ns[0].Is6() {
		ipfam = "ipv6"
	}
	return dnspath.DNSPathID{
		Family:     dnspath.DNSPathSystemForward,
		ResolverID: "r-sys-" + hex.EncodeToString(sum[:6]),
		IPFamily:   ipfam,
	}
}

func (p *SystemForwardProvider) Capabilities() dnspath.DNSPathCapabilities {
	recursive, err := p.DetectRecursion()
	if err != nil {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnknown, Reason: "resolv.conf unreadable: " + err.Error()}
	}
	if recursive {
		return dnspath.DNSPathCapabilities{State: dnspath.CapBlockedByDependency, Reason: "system resolver points at B4X loopback listener (recursion)"}
	}
	ns, _ := p.EffectiveNameservers()
	if len(ns) == 0 {
		return dnspath.DNSPathCapabilities{State: dnspath.CapUnsupported, Reason: "no system nameserver"}
	}
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: true}
}

// Prepare delegates to a UDP provider bound to the first effective
// nameserver, keeping the system-forward family identity.
func (p *SystemForwardProvider) Prepare(ctx context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	caps := p.Capabilities()
	if caps.State == dnspath.CapBlockedByDependency || caps.State == dnspath.CapUnsupported {
		return dnspath.PreparedDNSPath{}, fmt.Errorf("system forward unavailable: %s", caps.Reason)
	}
	ns, err := p.EffectiveNameservers()
	if err != nil || len(ns) == 0 {
		return dnspath.PreparedDNSPath{}, fmt.Errorf("system forward: no effective nameserver")
	}
	inner := NewUDPProvider(ns[0], 53, p.Mark, "")
	inner.Timeout = p.Timeout
	prepared, err := inner.Prepare(ctx, req)
	if err != nil {
		return dnspath.PreparedDNSPath{}, err
	}
	prepared.PathID = p.ID()
	prepared.Handle = inner
	return prepared, nil
}

func (p *SystemForwardProvider) inner(prepared dnspath.PreparedDNSPath) (*UDPProvider, error) {
	inner, ok := prepared.Handle.(*UDPProvider)
	if !ok || inner == nil {
		return nil, fmt.Errorf("system forward: prepared handle missing")
	}
	return inner, nil
}

func (p *SystemForwardProvider) Probe(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	inner, err := p.inner(prepared)
	if err != nil {
		return dnspath.DNSPathProbeOutcome{PathID: prepared.PathID, Class: dnspath.OutcomeObserverUnavailable}, nil
	}
	out, err := inner.Probe(ctx, prepared, q)
	out.PathID = prepared.PathID
	return out, err
}

func (p *SystemForwardProvider) Resolve(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	inner, err := p.inner(prepared)
	if err != nil {
		return dnspath.DNSResponse{}, err
	}
	return inner.Resolve(ctx, prepared, q)
}

func (p *SystemForwardProvider) Health(ctx context.Context, prepared dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	caps := p.Capabilities()
	if caps.State != dnspath.CapAvailable {
		return dnspath.DNSPathHealth{State: caps.State}
	}
	return dnspath.DNSPathHealth{State: dnspath.CapAvailable}
}

func (p *SystemForwardProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error {
	return nil
}
