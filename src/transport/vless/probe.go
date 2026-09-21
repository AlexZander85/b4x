package vless

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ProbeResult is one node's health + exit-geo verdict.
type ProbeResult struct {
	Node      Node   `json:"-"`
	OK        bool   `json:"ok"`
	LatencyMs int64  `json:"latency_ms"`
	Loc       string `json:"loc,omitempty"`  // exit country ("RU","DE",...)
	Colo      string `json:"colo,omitempty"` // edge code
	Err       string `json:"error,omitempty"`
}

// NodeStreamFunc opens a raw stream to target through node n (in-process dial
// or the helper's SOCKS5 CONNECT — both reduce to one net.Conn).
type NodeStreamFunc func(ctx context.Context, n Node, target netip.AddrPort) (net.Conn, error)

// DefaultTraceURL is the Cloudflare trace endpoint used for geo attestation.
const DefaultTraceURL = "https://1.1.1.1/cdn-cgi/trace"

// Prober measures latency and the exit `loc`/`colo` by fetching a trace URL
// through the node (the attestation pattern: `loc` says what sites see, not
// where the server's IP is registered).
type Prober struct {
	Stream          NodeStreamFunc
	TraceURL        string
	TraceHostHeader string // Host header when tracing by IP (default 1.1.1.1)
	ServerName      string // TLS SNI for the trace target
	Timeout         time.Duration
	Insecure        bool
	RootCAs         *x509.CertPool
}

// Probe runs one measurement. It never panics and always returns a result
// (OK=false with Err on any failure).
func (p *Prober) Probe(ctx context.Context, n Node) ProbeResult {
	res := ProbeResult{Node: n}
	if p.Stream == nil {
		res.Err = "no stream func"
		return res
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	traceURL := p.TraceURL
	if traceURL == "" {
		traceURL = DefaultTraceURL
	}
	target, scheme, host := traceTarget(traceURL)
	if !target.IsValid() {
		res.Err = "invalid trace url"
		return res
	}
	start := time.Now()
	stream, err := p.Stream(ctx, n, target)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer stream.Close()

	tr := &http.Transport{
		DialContext:       func(context.Context, string, string) (net.Conn, error) { return stream, nil },
		DisableKeepAlives: true,
	}
	if scheme == "https" {
		tr.TLSClientConfig = &tls.Config{
			ServerName:         p.ServerName,
			InsecureSkipVerify: p.Insecure,
			RootCAs:            p.RootCAs,
		}
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if h := p.TraceHostHeader; h != "" {
		req.Host = h
	} else if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.LatencyMs = time.Since(start).Milliseconds()
	res.Loc, res.Colo = ParseTrace(string(body))
	if resp.StatusCode != http.StatusOK {
		res.Err = fmt.Sprintf("trace http %d", resp.StatusCode)
		return res
	}
	res.OK = true
	return res
}

// traceTarget resolves a trace URL into a dial target (default 1.1.1.1:443/80).
func traceTarget(raw string) (netip.AddrPort, string, string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return netip.MustParseAddrPort("1.1.1.1:443"), "https", "1.1.1.1"
	}
	scheme := u.Scheme
	port := u.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return netip.AddrPort{}, scheme, u.Hostname()
	}
	return ap, scheme, u.Hostname()
}

// ParseTrace extracts loc/colo from a /cdn-cgi/trace body.
func ParseTrace(body string) (loc, colo string) {
	for _, line := range strings.Split(body, "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "loc":
			loc = strings.TrimSpace(kv[1])
		case "colo":
			colo = strings.TrimSpace(kv[1])
		}
	}
	return loc, colo
}

// ProbeAll probes nodes with bounded concurrency, preserving input order of
// results is not required (the selector sorts by latency).
func ProbeAll(ctx context.Context, prober ProbeRunner, nodes []Node, parallel int) []ProbeResult {
	if parallel <= 0 {
		parallel = 4
	}
	sem := make(chan struct{}, parallel)
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out []ProbeResult
	)
	for i := range nodes {
		n := nodes[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := prober.Probe(ctx, n)
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}
