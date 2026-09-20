package health

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/netip"
	"time"

	"github.com/daniellavrushin/b4/reserve"
)

// Config parameterizes one prober. Zero values resolve to DefaultConfig
// values via normalize.
type Config struct {
	// Target is the in-tunnel TCP destination (IP:port). A literal IP keeps
	// the probe carrier-agnostic (no in-tunnel DNS required).
	Target netip.AddrPort
	// ServerName is the TLS SNI / Host of the probe request.
	ServerName string
	// Path is the HTTP path fetched for the TTFB/throughput sample.
	Path string
	// Timeout bounds one attempt (dial + TLS + first byte + drain).
	Timeout time.Duration
	// Samples is the number of attempts (loss = failures/samples).
	Samples int
	// MaxBytes bounds the download (quota-safe: fxvpn is 50 GiB/month).
	MaxBytes int64
	// InsecureSkipVerify is the test-only seam (self-signed stands).
	InsecureSkipVerify bool
}

// DefaultConfig is the shipping probe: Cloudflare trace via 1.0.0.1, one
// 64 KiB sample.
func DefaultConfig() Config {
	return Config{
		Target:     netip.MustParseAddrPort("1.0.0.1:443"),
		ServerName: "www.cloudflare.com",
		Path:       "/cdn-cgi/trace",
		Timeout:    8 * time.Second,
		Samples:    1,
		MaxBytes:   64 << 10,
	}
}

func (c Config) normalize() Config {
	d := DefaultConfig()
	if !c.Target.IsValid() {
		c.Target = d.Target
	}
	if c.ServerName == "" {
		c.ServerName = d.ServerName
	}
	if c.Path == "" {
		c.Path = d.Path
	}
	if c.Timeout <= 0 {
		c.Timeout = d.Timeout
	}
	if c.Samples <= 0 {
		c.Samples = d.Samples
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = d.MaxBytes
	}
	return c
}

// Prober measures one carrier.
type Prober struct{ cfg Config }

// New builds a prober with defaults filled in.
func New(cfg Config) *Prober { return &Prober{cfg: cfg.normalize()} }

// Measure runs cfg.Samples probes through carrier c and aggregates Metrics.
func (p *Prober) Measure(ctx context.Context, c reserve.Carrier) Metrics {
	m := Metrics{Kind: "unknown", Probes: p.cfg.Samples, MeasuredAt: time.Now().UTC()}
	if c == nil {
		m.Score = 0
		m.Verdict = VerdictUnavailable
		m.Error = "no carrier"
		return m
	}
	m.Kind = string(c.Kind())

	var rttSum, ttfbSum, elapsedSum, bytes int64
	ok := 0
	var lastErr error
	for i := 0; i < p.cfg.Samples; i++ {
		attemptCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
		start := time.Now()
		n, rtt, ttfb, err := p.probeOnce(attemptCtx, c)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		ok++
		bytes += n
		rttSum += rtt.Milliseconds()
		ttfbSum += ttfb.Milliseconds()
		elapsedSum += time.Since(start).Milliseconds()
	}

	m.Failures = p.cfg.Samples - ok
	if p.cfg.Samples > 0 {
		m.LossPct = math.Round(float64(m.Failures)/float64(p.cfg.Samples)*10000) / 100
	}
	m.Available = ok > 0
	if ok > 0 {
		m.RTTms = rttSum / int64(ok)
		m.TTFBms = ttfbSum / int64(ok)
		m.Bytes = bytes
		if elapsedSum > 0 {
			m.ThroughputMbps = math.Round(float64(bytes*8)/(float64(elapsedSum)/1000)/1e6*100) / 100
		}
	}
	if lastErr != nil {
		m.Error = lastErr.Error()
	}
	m.Score = scoreOf(m)
	m.Verdict = verdictOf(m.Available, m.Score)
	return m
}

// probeOnce opens one stream through the carrier, completes a TLS handshake
// and fetches Path, returning bytes read, handshake RTT and TTFB.
func (p *Prober) probeOnce(ctx context.Context, c reserve.Carrier) (int64, time.Duration, time.Duration, error) {
	start := time.Now()
	conn, err := c.DialStream(ctx, p.cfg.Target)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	tconn := tls.Client(conn, &tls.Config{
		ServerName:         p.cfg.ServerName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: p.cfg.InsecureSkipVerify,
	})
	_ = tconn.SetDeadline(time.Now().Add(p.cfg.Timeout))
	if err := tconn.HandshakeContext(ctx); err != nil {
		return 0, 0, 0, fmt.Errorf("tls: %w", err)
	}
	rtt := time.Since(start)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: b4x-health/1\r\nConnection: close\r\n\r\n",
		p.cfg.Path, p.cfg.ServerName)
	if _, err := tconn.Write([]byte(req)); err != nil {
		return 0, 0, 0, fmt.Errorf("write: %w", err)
	}

	br := bufio.NewReader(tconn)
	if _, err := br.Peek(1); err != nil {
		return 0, 0, 0, fmt.Errorf("ttfb: %w", err)
	}
	ttfb := time.Since(start)

	n, err := io.CopyN(io.Discard, br, p.cfg.MaxBytes)
	if err != nil && err != io.EOF {
		return 0, 0, 0, fmt.Errorf("read: %w", err)
	}
	return n, rtt, ttfb, nil
}
