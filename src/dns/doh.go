package dns

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const DoHContentType = "application/dns-message"

var ErrDoHMethodNotAllowed = errors.New("doh method not allowed")

// MarkedDoHClient builds the legacy marked DoH client. Adaptive DNS should
// prefer MarkedDoHClientWithBootstrap for hostname endpoints so DNS recovery
// never recursively depends on the system resolver it is trying to replace.
func MarkedDoHClient(mark int, timeout time.Duration) *http.Client {
	return MarkedDoHClientWithBootstrap(mark, timeout, "", nil)
}

// MarkedDoHClientWithBootstrap pins connections for serverName to the
// supplied bootstrap IPs while preserving the URL hostname for TLS SNI and
// certificate verification. Redirects are not followed: a redirect could
// silently escape the reviewed/bootstrap-pinned endpoint.
func MarkedDoHClientWithBootstrap(mark int, timeout time.Duration, serverName string, bootstrap []net.IP) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
	}
	var control func(string, string, syscall.RawConn) error
	if mark != 0 {
		control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if cerr := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
			}); cerr != nil {
				return cerr
			}
			return serr
		}
	}
	d := &net.Dialer{Timeout: timeout, Control: control}
	d.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			bd := &net.Dialer{Timeout: timeout, Control: control}
			return bd.DialContext(ctx, network, address)
		},
	}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err == nil && serverName != "" && strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(serverName, ".")) && len(bootstrap) > 0 {
			var lastErr error
			for _, ip := range bootstrap {
				if ip == nil {
					continue
				}
				conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			if lastErr != nil {
				return nil, lastErr
			}
		}
		return d.DialContext(ctx, network, address)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func ResolveDoH(ctx context.Context, client *http.Client, serverURL string, query []byte) ([]byte, error) {
	body, err := dohPOST(ctx, client, serverURL, query)
	if errors.Is(err, ErrDoHMethodNotAllowed) {
		body, err = dohGET(ctx, client, serverURL, query)
	}
	return body, err
}

func dohPOST(ctx context.Context, client *http.Client, serverURL string, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", DoHContentType)
	req.Header.Set("Content-Type", DoHContentType)
	return dohDo(client, req)
}

func dohGET(ctx context.Context, client *http.Client, serverURL string, query []byte) ([]byte, error) {
	enc := base64.RawURLEncoding.EncodeToString(query)
	sep := "?"
	if strings.ContainsRune(serverURL, '?') {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+sep+"dns="+enc, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", DoHContentType)
	return dohDo(client, req)
}

func dohDo(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		io.Copy(io.Discard, resp.Body)
		return nil, ErrDoHMethodNotAllowed
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65536))
}
