// Package socks is the shared SOCKS5 egress seam (bd b4x-9wg): one TCP-only
// dialer reused by every consumer that reaches the network through a local or
// remote SOCKS5 proxy.
//
// Two consumers today:
//   - the MASQUE carrier (`system.warp.socks5`, bd b4x-rnn/b4x-w4c): Cloudflare
//     sees the proxy's country and assigns a non-RU WARP egress;
//   - the VLESS reserve (`system.vless.socks_addr`, bd b4x-9wg): the local
//     inbound exposed by the external xray/sing-box helper.
//
// SOCKS5 carries TCP only, so the dialer refuses non-tcp networks honestly
// instead of silently falling back to a direct connection.
package socks

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/proxy"
)

// Addr is a parsed SOCKS5 endpoint.
type Addr struct {
	Host string
	Port int
	User string
	Pass string
}

// ParseAddr parses "host:port" or "socks5://[user:pass@]host:port".
func ParseAddr(raw string) (Addr, error) {
	s := strings.TrimSpace(raw)
	var a Addr
	if s == "" {
		return a, fmt.Errorf("empty socks5 address")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return a, fmt.Errorf("parse %q: %w", raw, err)
		}
		s = u.Host
		if u.User != nil {
			a.User = u.User.Username()
			a.Pass, _ = u.User.Password()
		}
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return a, fmt.Errorf("socks5 address %q must be host:port", raw)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return a, fmt.Errorf("socks5 address %q has invalid port", raw)
	}
	if host == "" {
		return a, fmt.Errorf("empty socks5 address")
	}
	a.Host = host
	a.Port = p
	return a, nil
}

// DialFunc builds a dialer that opens a TCP stream through the SOCKS5 proxy at
// addr. addr accepts "host:port" or "socks5://[user:pass@]host:port".
func DialFunc(addr string) (func(ctx context.Context, network, target string) (net.Conn, error), error) {
	parsed, err := ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	host := net.JoinHostPort(parsed.Host, strconv.Itoa(parsed.Port))
	var auth *proxy.Auth
	if parsed.User != "" || parsed.Pass != "" {
		auth = &proxy.Auth{User: parsed.User, Password: parsed.Pass}
	}
	d, err := proxy.SOCKS5("tcp", host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	ctxDialer, ok := d.(proxy.ContextDialer)
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("socks: carries tcp only, got %q", network)
		}
		if ok {
			return ctxDialer.DialContext(ctx, network, target)
		}
		return d.Dial(network, target)
	}, nil
}
