// SOCKS5 egress seam for the MASQUE carrier (bd b4x-rnn). When
// B4_WARP_SOCKS5 is set, every MASQUE generation's control TCP is dialed
// through that proxy instead of the local WAN. Cloudflare then sees the
// proxy's country and assigns a non-RU WARP egress (the WARP `loc` is a
// property of the connection's vantage, not of the registration — proven by
// enrolling through a GB proxy and still observing loc=RU on a direct
// connect). SOCKS5 carries TCP only, so the seam forces the H2 carrier and
// the H3 (UDP) ladder is bypassed.
package warpservice

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

// socks5DialFunc builds a SessionConfig.DialFunc that opens a TCP stream
// through the SOCKS5 proxy at addr. addr accepts "host:port" or
// "socks5://user:pass@host:port".
func socks5DialFunc(addr string) (func(ctx context.Context, network, target string) (net.Conn, error), error) {
	host := strings.TrimSpace(addr)
	var auth *proxy.Auth
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", addr, err)
		}
		host = u.Host
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
	}
	if host == "" {
		return nil, fmt.Errorf("empty socks5 address")
	}
	d, err := proxy.SOCKS5("tcp", host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	ctxDialer, ok := d.(proxy.ContextDialer)
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("warpservice: socks5 seam carries tcp only, got %q", network)
		}
		if ok {
			return ctxDialer.DialContext(ctx, network, target)
		}
		return d.Dial(network, target)
	}, nil
}
