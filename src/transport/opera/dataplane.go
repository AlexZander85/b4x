// SurfEasy data plane (design §1.3, stage OP2): TCP -> TLS (ClientHello
// without SNI or with a fake-SNI override) -> manual VerifyConnection against
// the REAL node name with the root pool -> HTTP/1.1 CONNECT with
// Proxy-Authorization Basic -> after 200 OK a raw bidirectional TCP relay.
//
// Wire format and the prefixConn replay trick are mirrored from the canonical
// reference (opera-proxy2 dialer/upstream.go): bufio buffering must never eat
// tunnel bytes that arrived in the same segment as the CONNECT response.
package opera

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

const connectRespBufSize = 4 * 1024

// BasicAuthHeader renders "Basic base64(login:password)" for both the
// Proxy-Authorization header and tests (reference parity).
func BasicAuthHeader(login, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(login+":"+password))
}

// NodeDialer dials arbitrary TCP targets THROUGH one Opera proxy node.
// Credentials are resolved per dial so JWT rotation (4h cadence) is picked up
// without rebuilding the dialer. The zero next-dialer falls back to a plain
// net.Dialer; carrier chains plug in here at OP4.
type NodeDialer struct {
	// Address of the node, "host:port" (SEIPEntry.NetAddr).
	Address string
	// TLSServerName is the real node name for certificate verification
	// (SEIPEntry.TLSServerName). Empty is rejected: the data plane is
	// always TLS — there is no plain-HTTP node mode in scope.
	TLSServerName string
	// FakeSNI replaces the ClientHello SNI when non-empty (design §1.3/§1.4);
	// empty suppresses SNI entirely (upstream default behavior).
	FakeSNI string
	// Auth returns the Proxy-Authorization header value per dial.
	Auth func() (string, error)
	// RootPool verifies the node certificate chain. Nil resolves the system
	// pool lazily (Mozilla/NSS roots on Linux); resolution failure fails
	// closed instead of skipping verification.
	RootPool *x509.CertPool
	// Next dials raw TCP to Address. Nil => net.Dialer{Timeout: 15s}.
	Next func(ctx context.Context, network, addr string) (net.Conn, error)

	poolOnce sync.Once
	pool     *x509.CertPool
	poolErr  error
}

// resolveRoot returns the verification pool, resolving the system store on
// first use when no explicit pool was configured (fail-closed on error).
func (d *NodeDialer) resolveRoot() (*x509.CertPool, error) {
	if d.RootPool != nil {
		return d.RootPool, nil
	}
	d.poolOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil {
			d.poolErr = fmt.Errorf("system cert pool unavailable: %w", err)
			return
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		d.pool = pool
	})
	return d.pool, d.poolErr
}

func (d *NodeDialer) baseDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.Next != nil {
		return d.Next(ctx, network, addr)
	}
	dd := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return dd.DialContext(ctx, network, addr)
}

// DialContext connects to address THROUGH the node: TCP + TLS + CONNECT.
// On success the returned conn carries raw tunnel bytes (any response-header
// lookahead already buffered is replayed first via prefixConn).
func (d *NodeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("bad network for node dial: %q (tcp only)", network)
	}
	if strings.TrimSpace(d.Address) == "" {
		return nil, fmt.Errorf("node dialer: empty node address")
	}
	if strings.TrimSpace(d.TLSServerName) == "" {
		return nil, fmt.Errorf("node dialer: empty TLS server name")
	}
	if d.Auth == nil {
		return nil, fmt.Errorf("node dialer: auth provider required")
	}

	conn, err := d.baseDial(ctx, "tcp", d.Address)
	if err != nil {
		return nil, newFailure(ClassDataPlaneTLS, "dial node tcp", err)
	}

	pool, err := d.resolveRoot()
	if err != nil {
		_ = conn.Close()
		return nil, newFailure(ClassDataPlaneTLS, "resolve root pool", err)
	}

	// Reference strategy: SNI carries the fake value (or is suppressed);
	// the peer certificate is verified manually against the REAL name with
	// the explicit root pool — intermediates come from the presented chain.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         d.FakeSNI,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       d.TLSServerName,
				Intermediates: x509.NewCertPool(),
				Roots:         pool,
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, newFailure(ClassDataPlaneTLS, "node handshake", err)
	}
	conn = tlsConn

	auth, err := d.Auth()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("auth provider: %w", err)
	}

	req := &http.Request{
		Method:     "CONNECT",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RequestURI: address,
		Host:       address,
		Header: http.Header{
			"Host":                 []string{address},
			"Proxy-Authorization": []string{auth},
		},
	}
	rawreq, err := httputil.DumpRequest(req, false)
	if err != nil {
		_ = conn.Close()
		return nil, newFailure(ClassDataPlaneProtocol, "render connect", err)
	}
	if _, err := conn.Write(rawreq); err != nil {
		_ = conn.Close()
		return nil, newFailure(ClassDataPlaneProtocol, "send connect", err)
	}

	resp, wrapped, err := readConnectResponse(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		status := resp.Status
		if status == "" {
			status = fmt.Sprintf("%d", resp.StatusCode)
		}
		_ = conn.Close()
		return nil, newFailure(ClassDataPlaneConnectRefused,
			fmt.Sprintf("connect through %s to %s: %s", d.Address, address, status), nil)
	}
	return wrapped, nil
}

// readConnectResponse parses the CONNECT reply without over-consuming the
// tunnel stream: bufio may pre-fetch tunnel bytes that arrived in the same
// segment; they are replayed through prefixConn (reference parity).
func readConnectResponse(conn net.Conn) (*http.Response, net.Conn, error) {
	br := bufio.NewReaderSize(conn, connectRespBufSize)
	fakeReq := &http.Request{Method: "CONNECT"}
	resp, err := http.ReadResponse(br, fakeReq)
	if err != nil {
		return nil, nil, newFailure(ClassDataPlaneProtocol, "read connect reply", err)
	}
	if br.Buffered() > 0 {
		peeked, _ := br.Peek(br.Buffered())
		_, _ = br.Discard(br.Buffered())
		wrapped := &prefixConn{
			Reader: io.MultiReader(bytes.NewReader(peeked), conn),
			Conn:   conn,
		}
		resp.Body = io.NopCloser(wrapped)
		return resp, wrapped, nil
	}
	return resp, conn, nil
}

// prefixConn serves buffered bytes before the underlying connection
// (reference upstream.go parity).
type prefixConn struct {
	io.Reader
	net.Conn
}

func (pc *prefixConn) Read(b []byte) (int, error) { return pc.Reader.Read(b) }

// Relay pipes two established connections into each other until both
// directions finish, then closes both. A clean EOF on either side counts as
// normal tunnel completion (the opposite direction is unblocked by Close and
// its forced-error is swallowed); a genuine transport error wins otherwise.
func Relay(a, b io.ReadWriteCloser) error {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		clean    bool
	)
	copyDir := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		mu.Lock()
		if err == nil {
			clean = true
		} else if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
		// Unblock the opposite direction promptly.
		_ = dst.Close()
		_ = src.Close()
	}
	wg.Add(2)
	go copyDir(a, b)
	go copyDir(b, a)
	wg.Wait()
	if clean {
		return nil
	}
	return firstErr
}

// ProxyAuthHeader renders the current data-plane credentials as a ready
// Proxy-Authorization value (fresh per call — survives JWT rotation).
func (c *Client) ProxyAuthHeader() (string, error) {
	login, pass := c.ProxyCredentials()
	if login == "" || pass == "" {
		return "", fmt.Errorf("%w: no data-plane credentials", ErrIdentityInvalid)
	}
	return BasicAuthHeader(login, pass), nil
}

// NodeDialer wires a dialer for the given discovered entry using live client
// credentials (per-dial resolution) and the default system root pool.
// fakeSNI follows design §1.3: empty => suppressed SNI.
func (c *Client) NodeDialer(entry SEIPEntry, fakeSNI string) (*NodeDialer, error) {
	addr := entry.NetAddr()
	name := entry.TLSServerName()
	if strings.TrimSpace(addr) == "" || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("node entry incomplete: addr=%q name=%q", addr, name)
	}
	return &NodeDialer{
		Address:       addr,
		TLSServerName: name,
		FakeSNI:       fakeSNI,
		Auth:          c.ProxyAuthHeader,
	}, nil
}
