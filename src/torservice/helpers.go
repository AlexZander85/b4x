package torservice

// Runtime helper seams: the SOCKS5-through-tor liveness dial, the exit
// probe through tor, and the platform mark control for the snowflake
// adapter. These live HERE (not in transport/tor) because they import the
// config-coupled socks5/dns packages — the transport layer stays clean.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/packetmark"
	"github.com/daniellavrushin/b4/socks5"
)

// socksDialUpstream dials one TCP stream THROUGH tor's SOCKS port (the
// liveness shape: a successful CONNECT means the exit opened TCP; never
// HTTP 200 — Cloudflare challenges Tor exits, G165).
func socksDialUpstream(ctx context.Context, socksAddr, host string, port int) (net.Conn, error) {
	sHost, sPort, err := net.SplitHostPort(socksAddr)
	if err != nil {
		return nil, fmt.Errorf("tor socks addr: %w", err)
	}
	p := 0
	if _, err := fmt.Sscanf(sPort, "%d", &p); err != nil {
		return nil, fmt.Errorf("tor socks port: %w", err)
	}
	cfg := socks5.ClientConfig{
		Host:    sHost,
		Port:    p,
		Timeout: 10 * time.Second,
	}
	return socks5.DialUpstream(ctx, cfg, host, port)
}

// exitProbeThroughTor fetches https://check.torproject.org/api/ip through
// tor's SOCKS port: {"IsTor":true,"IP":"...","CountryCode":"..."} — exit
// verification AND the displayed exit country in one probe.
func exitProbeThroughTor(ctx context.Context, socksAddr string) (ExitInfo, error) {
	sHost, sPort, err := net.SplitHostPort(socksAddr)
	if err != nil {
		return ExitInfo{}, fmt.Errorf("tor socks addr: %w", err)
	}
	p := 0
	if _, err := fmt.Sscanf(sPort, "%d", &p); err != nil {
		return ExitInfo{}, fmt.Errorf("tor socks port: %w", err)
	}
	cfg := socks5.ClientConfig{Host: sHost, Port: p, Timeout: 12 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port := 0
			if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
				return nil, err
			}
			return socks5.DialUpstream(ctx, cfg, host, port)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return ExitInfo{}, err
	}
	req.Header.Set("User-Agent", "b4x-tor-exitprobe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return ExitInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return ExitInfo{}, fmt.Errorf("exit probe status %d", resp.StatusCode)
	}
	var payload struct {
		IsTor       bool   `json:"IsTor"`
		IP          string `json:"IP"`
		CountryCode string `json:"CountryCode"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&payload); err != nil {
		return ExitInfo{}, err
	}
	return ExitInfo{IP: payload.IP, Country: payload.CountryCode, IsTor: payload.IsTor}, nil
}

// torEgressMarkControl returns the platform SO_MARK control for the
// snowflake adapter's UDP sockets (nil off-linux / in sandboxes — the
// adapter treats nil as unmarked).
func torEgressMarkControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var ctrlErr error
		if err := c.Control(func(fd uintptr) {
			ctrlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(packetmark.MarkTorEgress))
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}
