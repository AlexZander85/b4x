// Exit verification probe (design Part II II.2.3; reference -verify-exit,
// main.go:190-192): after a tunnel is established, fetch the Cloudflare
// trace endpoint THROUGH it and compare the exit country against the
// configured location. Mismatch = typed fxvpn_exit_mismatch verdict; the
// supervisor answers with re-discover (FX4 wiring).
package fxvpn

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	exitProbeHost    = "www.cloudflare.com"
	exitProbePath    = "/cdn-cgi/trace"
	exitProbeTimeout = 10 * time.Second
)

// ExitInfo is what the trace probe observed on the far side of the tunnel.
type ExitInfo struct {
	IP      string
	Country string // ISO code from loc=
}

// ExitMismatchError reports verified-exit vs configured-location divergence.
type ExitMismatchError struct {
	Got  string
	Want string
}

func (e *ExitMismatchError) Error() string {
	return fmt.Sprintf("fxvpn: exit country %q does not match configured location %q", e.Got, e.Want)
}

// Unwrap ties the typed verdict to the sentinel for Classify.
func (e *ExitMismatchError) Unwrap() error { return ErrExitMismatch }

// ProbeExit opens a CONNECT to the trace host through opener and speaks
// TLS + HTTP/1.1 inside the relay (default certificate verification).
func ProbeExit(ctx context.Context, opener TunnelOpener) (ExitInfo, error) {
	return probeExit(ctx, opener, nil)
}

// ProbeExitTLS is the test/bootstrap seam variant with an explicit TLS base
// (fake origins carry self-signed certs; production passes nil).
func ProbeExitTLS(ctx context.Context, opener TunnelOpener, tlsBase *tls.Config) (ExitInfo, error) {
	return probeExit(ctx, opener, tlsBase)
}

func probeExit(ctx context.Context, opener TunnelOpener, tlsBase *tls.Config) (ExitInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, exitProbeTimeout)
	defer cancel()

	conn, err := opener.OpenTunnel(ctx, net.JoinHostPort(exitProbeHost, "443"))
	if err != nil {
		return ExitInfo{}, fmt.Errorf("fxvpn: exit probe connect: %w", err)
	}
	defer conn.Close()

	tlsCfg := &tls.Config{ServerName: exitProbeHost}
	if tlsBase != nil {
		tlsCfg = tlsBase.Clone()
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = exitProbeHost
		}
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return ExitInfo{}, fmt.Errorf("fxvpn: exit probe tls: %w", err)
	}
	defer tlsConn.Close()

	req := "GET " + exitProbePath + " HTTP/1.1\r\n" +
		"Host: " + exitProbeHost + "\r\n" +
		"User-Agent: " + mozillaVPNUserAgent + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return ExitInfo{}, fmt.Errorf("fxvpn: exit probe request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		return ExitInfo{}, fmt.Errorf("fxvpn: exit probe response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ExitInfo{}, fmt.Errorf("fxvpn: exit probe HTTP %d", resp.StatusCode)
	}

	info := ExitInfo{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			info.IP = v
		case "loc":
			info.Country = v
		}
	}
	if err := sc.Err(); err != nil {
		return ExitInfo{}, fmt.Errorf("fxvpn: exit probe body: %w", err)
	}
	if info.Country == "" {
		return ExitInfo{}, fmt.Errorf("fxvpn: exit probe trace has no loc")
	}
	return info, nil
}

// VerifyExit probes and compares against wantCountry ("" disables check).
func VerifyExit(ctx context.Context, opener TunnelOpener, wantCountry string) (ExitInfo, error) {
	info, err := ProbeExit(ctx, opener)
	if err != nil {
		return info, err
	}
	return verifyExitInfo(info, wantCountry)
}

// VerifyExitTLS is the seam variant of VerifyExit (tests).
func VerifyExitTLS(ctx context.Context, opener TunnelOpener, tlsBase *tls.Config, wantCountry string) (ExitInfo, error) {
	info, err := ProbeExitTLS(ctx, opener, tlsBase)
	if err != nil {
		return info, err
	}
	return verifyExitInfo(info, wantCountry)
}

func verifyExitInfo(info ExitInfo, wantCountry string) (ExitInfo, error) {
	if wantCountry != "" && !strings.EqualFold(info.Country, wantCountry) {
		return info, &ExitMismatchError{Got: info.Country, Want: wantCountry}
	}
	return info, nil
}
