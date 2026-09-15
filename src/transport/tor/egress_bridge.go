package tor

// Egress bridge (design §3.1, patch-plan §4.2): a loopback SOCKS5 server
// that tor's `Socks5Proxy user:pass@127.0.0.1:port` directive points at —
// the composition point where ALL of tor's vanilla relay/bridge/dir TCP
// legs converge (the PT legs converge in the in-process PT proxy instead;
// both share the same Dialer). Credentials are random per start (sing-box
// proxybridge canon): not a secret, a defense against OTHER local
// processes wanting a free egress — RFC 1929 auth is mandatory and a wrong
// pair is refused.
//
// The handshake is a minimal local copy of the src/socks5 wire handling
// (plan-sanctioned: the public socks5.Server API is config-coupled and
// must not change); CONNECT is the only command. Class attribution: a
// target matching the active vanilla bridge set is ClassBridgeVanilla,
// everything else is ClassRelayDir (relays + directory authorities).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/log"
)

// Egress bridge limits (design §8.4 — FD discipline).
const (
	egressBridgeMaxConns = 512
	egressBridgeTimeout  = 30 * time.Second
)

// BridgeTargets supplies the active vanilla-bridge endpoint set for class
// attribution (nil → everything is ClassRelayDir).
type BridgeTargets func() []string

// EgressBridge is the loopback SOCKS5 egress bridge.
type EgressBridge struct {
	dialer   *Dialer
	targets  BridgeTargets
	listener net.Listener

	username string
	password string

	ctx       context.Context
	cancel    context.CancelFunc
	conns     sync.WaitGroup
	connCount atomic.Int64
}

// NewEgressBridge binds 127.0.0.1:0 and generates the per-start random
// credentials. Start launches the accept loop; Addr/Username/Password feed
// the torrc Socks5Proxy line.
func NewEgressBridge(dialer *Dialer, targets BridgeTargets) (*EgressBridge, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("tor egress bridge listen: %w", err)
	}
	user, err := randomHex(16)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	pass, err := randomHex(16)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	b := &EgressBridge{
		dialer:   dialer,
		targets:  targets,
		listener: ln,
		username: user,
		password: pass,
	}
	b.ctx, b.cancel = context.WithCancel(context.Background())
	go b.acceptLoop()
	return b, nil
}

// Addr is the loopback listener address (host:port).
func (b *EgressBridge) Addr() string { return b.listener.Addr().String() }

// Username is the per-start random SOCKS5 user (torrc Socks5Proxy user).
func (b *EgressBridge) Username() string { return b.username }

// Password is the per-start random SOCKS5 pass.
func (b *EgressBridge) Password() string { return b.password }

// Creds renders "user:pass" for the torrc directive.
func (b *EgressBridge) Creds() string { return b.username + ":" + b.password }

// LoopAddr reports the listener for the dialer's self-loop guard.
func (b *EgressBridge) LoopAddr() string { return b.Addr() }

// Stop closes the listener and drains the live pipes.
func (b *EgressBridge) Stop() {
	if b.cancel != nil {
		b.cancel()
	}
	if b.listener != nil {
		_ = b.listener.Close()
	}
	b.conns.Wait()
}

func (b *EgressBridge) acceptLoop() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			select {
			case <-b.ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if b.connCount.Load() >= egressBridgeMaxConns {
			_ = conn.Close() // bounded, honest refusal
			continue
		}
		b.connCount.Add(1)
		b.conns.Add(1)
		go func() {
			defer b.conns.Done()
			defer b.connCount.Add(-1)
			b.handleConn(conn)
		}()
	}
}

func (b *EgressBridge) handleConn(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(egressBridgeTimeout)); err != nil {
		return
	}
	if err := b.authenticate(conn); err != nil {
		log.Tracef("[tor] egress bridge auth failed: %v", err)
		return
	}
	if err := b.handleConnect(conn); err != nil {
		log.Tracef("[tor] egress bridge connect failed: %v", err)
	}
}

// authenticate runs the RFC 1928 method negotiation REQUIRING RFC 1929
// user/pass (method 0x02); anything else is refused with 0xFF.
func (b *EgressBridge) authenticate(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("methods: %w", err)
	}
	offersUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			offersUserPass = true
			break
		}
	}
	if !offersUserPass {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return errors.New("client refuses RFC 1929 auth")
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		return fmt.Errorf("method select: %w", err)
	}
	return b.checkUserPass(conn)
}

func (b *EgressBridge) checkUserPass(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("auth header: %w", err)
	}
	if hdr[0] != 0x01 {
		return fmt.Errorf("auth sub-version %d", hdr[0])
	}
	uname := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return fmt.Errorf("username: %w", err)
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return fmt.Errorf("password length: %w", err)
	}
	passwd := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return fmt.Errorf("password: %w", err)
	}
	ok := string(uname) == b.username && string(passwd) == b.password
	status := byte(0x00)
	if !ok {
		status = 0x01
	}
	if _, err := conn.Write([]byte{0x01, status}); err != nil {
		return fmt.Errorf("auth result: %w", err)
	}
	if !ok {
		return errors.New("invalid credentials (foreign local process?)")
	}
	return nil
}

func (b *EgressBridge) handleConnect(conn net.Conn) error {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if hdr[0] != 0x05 {
		b.reply(conn, 0x01)
		return fmt.Errorf("request version %d", hdr[0])
	}
	if hdr[1] != 0x01 {
		b.reply(conn, 0x07)
		return fmt.Errorf("command 0x%02x unsupported (CONNECT only)", hdr[1])
	}
	host, port, err := readBridgeAddress(conn, hdr[3])
	if err != nil {
		b.reply(conn, 0x08)
		return fmt.Errorf("address: %w", err)
	}
	// handshake done — clear the deadline, the pipe runs unbounded
	_ = conn.SetDeadline(time.Time{})

	class := b.classFor(host, port)
	ctx, cancel := context.WithTimeout(b.ctx, EgressDirectTimeout*4)
	defer cancel()
	remote, err := b.dialer.Dial(ctx, class, host, port)
	if err != nil {
		b.reply(conn, 0x01)
		return fmt.Errorf("dial %s:%d: %w", host, port, err)
	}
	defer remote.Close()
	if err := b.reply(conn, 0x00); err != nil {
		return err
	}
	pipeHalfClose(conn, remote)
	return nil
}

// classFor attributes the connection: vanilla bridge endpoints (from the
// active set) are bridge-vanilla, everything else relay-dir.
func (b *EgressBridge) classFor(host string, port uint16) ConnClass {
	if b.targets != nil {
		want := net.JoinHostPort(host, strconv.Itoa(int(port)))
		for _, t := range b.targets() {
			if t == want {
				return ClassBridgeVanilla
			}
			if norm, err := normalizeEndpoint(t); err == nil && norm == want {
				return ClassBridgeVanilla
			}
		}
	}
	return ClassRelayDir
}

func normalizeEndpoint(t string) (string, error) {
	// splitBridgeHostPort also understands bare-IPv6-with-port endpoints
	// (the bridge-line canonical form before normalization).
	host, port, err := splitBridgeHostPort(t)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	return t, nil
}

func (b *EgressBridge) reply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// readBridgeAddress reads the SOCKS5 address payload (ATYP already read).
func readBridgeAddress(r io.Reader, atyp byte) (string, uint16, error) {
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		return net.IP(buf[:4]).String(), binary.BigEndian.Uint16(buf[4:]), nil
	case 0x04: // IPv6
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		return net.IP(buf[:16]).String(), binary.BigEndian.Uint16(buf[16:]), nil
	case 0x03: // domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		return string(buf[:len(buf)-2]), binary.BigEndian.Uint16(buf[len(buf)-2:]), nil
	default:
		return "", 0, fmt.Errorf("address type 0x%02x", atyp)
	}
}

// pipeHalfClose relays both directions with TCP half-close propagation
// (the Nova pipe canon: a finished direction closes only ITS write side so
// protocols that rely on EOF semantics keep working).
func pipeHalfClose(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		copyAndHalfClose(b, a)
		done <- struct{}{}
	}()
	copyAndHalfClose(a, b)
	<-done
}

func copyAndHalfClose(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	} else if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// randomHex renders n random bytes as hex (2n chars).
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
