package tor

// In-process PT proxy (patch-plan §6.1, the Nova tor_obfs4.go port):
// ONE loopback SOCKS5 listener that tor's `ClientTransportPlugin <t>
// socks5 127.0.0.1:<pt-port>` lines all point at (design §7.4 — one port,
// four transports). The flow per connection:
//
//	greet [no-auth, user/pass] → select 0x02 → RFC 1929 subnegotiation
//	(login ‖ password = the pt-spec serialized bridge arguments, trailing
//	NULs stripped, '\' un-escaped) → CONNECT to the bridge endpoint →
//	ACL: the target must be an ACTIVE bridge endpoint; its Transport
//	field selects the factory → factory.ParseArgs → endpoint.Dial(
//	protectedDial) → reply → half-close pipe.
//
// Reply codes follow the PT contract: ACL refusal → 0x02 (connection not
// allowed by ruleset), dial/transport failure → 0x04 (host unreachable) —
// tor distinguishes "bridge dead" from "proxy confused". The connection
// limit is 256 (design §8.4 FD discipline). The protected dial goes
// through the egress dialer with ClassBridgePT — every PT socket marked
// and composable.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/meeklite"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/webtunnel"

	"github.com/daniellavrushin/b4/log"
)

// PT proxy limits (design §8.4).
const (
	PTProxyMaxConns    = 256
	PTProxyHandshakeTO = 30 * time.Second
)

// PTEndpoint is one parsed bridge endpoint: Dial connects to the bridge
// through the provided protected dialer (the CONNECT target is passed for
// transports that dial it — webtunnel/snowflake resolve their own path).
type PTEndpoint interface {
	// Dial opens the tunnel. address is the bridge endpoint from the tor
	// CONNECT request (obfs4/vanilla dial it; webtunnel's is a decoration
	// and snowflake rendezvouses instead). dial is the protected dialer.
	Dial(address string, dial func(addr string) (net.Conn, error)) (net.Conn, error)
}

// TransportFactory parses one transport's bridge arguments into an
// endpoint (the PTRegistry contract — lyrebird factories and the snowflake
// adapter both implement it).
type TransportFactory interface {
	Name() string
	ParseArgs(args map[string]string) (PTEndpoint, error)
}

// PTRegistry maps transport names to factories.
type PTRegistry struct {
	factories map[string]TransportFactory
}

// NewPTRegistry builds the registry with the lyrebird trio + snowflake.
func NewPTRegistry(snowflake TransportFactory) *PTRegistry {
	r := &PTRegistry{factories: map[string]TransportFactory{}}
	r.Register(&lyrebirdFactory{name: "obfs4", transport: &obfs4.Transport{}})
	r.Register(&lyrebirdFactory{name: "webtunnel", transport: webtunnel.Transport})
	r.Register(&lyrebirdFactory{name: "meek_lite", transport: &meeklite.Transport{}})
	if snowflake != nil {
		r.Register(snowflake)
	}
	return r
}

// Register adds/replaces one factory.
func (r *PTRegistry) Register(f TransportFactory) {
	if r == nil || f == nil {
		return
	}
	r.factories[f.Name()] = f
}

// Get resolves a transport name.
func (r *PTRegistry) Get(name string) (TransportFactory, bool) {
	if r == nil {
		return nil, false
	}
	f, ok := r.factories[name]
	return f, ok
}

// Transports lists the registered names.
func (r *PTRegistry) Transports() []string {
	out := make([]string, 0, len(r.factories))
	for k := range r.factories {
		out = append(out, k)
	}
	return out
}

// lyrebirdFactory adapts a lyrebird base.Transport onto TransportFactory.
type lyrebirdFactory struct {
	name      string
	transport base.Transport
}

// ParseArgs implements TransportFactory through the lyrebird factory.
func (l *lyrebirdFactory) ParseArgs(args map[string]string) (PTEndpoint, error) {
	f, err := l.transport.ClientFactory("")
	if err != nil {
		return nil, fmt.Errorf("%s client factory: %w", l.name, err)
	}
	parsed, err := f.ParseArgs(ptArgsFrom(args))
	if err != nil {
		return nil, fmt.Errorf("%s parse args: %w", l.name, err)
	}
	return &lyrebirdEndpoint{factory: f, parsed: parsed}, nil
}

func (l *lyrebirdFactory) Name() string { return l.name }

// ptArgsFrom converts a plain map into goptlib Args.
func ptArgsFrom(args map[string]string) *pt.Args {
	out := pt.Args{}
	for k, v := range args {
		out.Add(k, v)
	}
	return &out
}

// lyrebirdEndpoint dials through the lyrebird factory.
type lyrebirdEndpoint struct {
	factory base.ClientFactory
	parsed  interface{}
}

func (e *lyrebirdEndpoint) Dial(address string, dial func(addr string) (net.Conn, error)) (net.Conn, error) {
	// The bridge address MUST reach the factory: obfs4 dials exactly this
	// target (a "" address yields "missing port in address" and every
	// handshake fails — b4x obfs4/vanilla entry bug).
	return e.factory.Dial("tcp", address, func(network, addr string) (net.Conn, error) {
		return dial(addr)
	}, e.parsed)
}

// PTProxy is the loopback SOCKS5 server serving every transport.
type PTProxy struct {
	registry *PTRegistry
	bridges  func() []Bridge // active set (ACL + transport resolution)
	dial     EgressDialFunc  // protected dial (ClassBridgePT)

	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	conns    sync.WaitGroup
	count    atomic.Int64
	live     *liveConnSet
	stopOnce sync.Once
}

// NewPTProxy binds 127.0.0.1:0 and starts accepting.
func NewPTProxy(registry *PTRegistry, bridges func() []Bridge, dial EgressDialFunc) (*PTProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("tor pt proxy listen: %w", err)
	}
	p := &PTProxy{
		registry: registry,
		bridges:  bridges,
		dial:     dial,
		listener: ln,
		live:     newLiveConnSet(),
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	go p.acceptLoop()
	return p, nil
}

// Addr is the listener address (for the torrc ClientTransportPlugin lines).
func (p *PTProxy) Addr() string { return p.listener.Addr().String() }

// LoopAddr reports the listener for the egress dialer self-loop guard.
func (p *PTProxy) LoopAddr() string { return p.Addr() }

// Stop closes the listener and drains live pipes. Bounded (b4x-62dl):
// in-flight conns are force-closed first so a stuck PT stream cannot hold
// daemon shutdown hostage.
func (p *PTProxy) Stop() {
	p.stopOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		if p.listener != nil {
			_ = p.listener.Close()
		}
		if p.live != nil {
			p.live.closeAll()
		}
		if !drainBounded(&p.conns, bridgeStopGrace) {
			log.Tracef("[tor] pt proxy drain timed out after %s; abandoning stuck pipes", bridgeStopGrace)
		}
	})
}

func (p *PTProxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if p.count.Load() >= PTProxyMaxConns {
			_ = conn.Close() // bounded, honest refusal
			continue
		}
		p.count.Add(1)
		p.conns.Add(1)
		go func() {
			defer p.conns.Done()
			defer p.count.Add(-1)
			p.handleConn(conn)
		}()
	}
}

func (p *PTProxy) handleConn(conn net.Conn) {
	defer conn.Close()
	if p.live != nil {
		p.live.add(conn)
		defer p.live.remove(conn)
	}
	if err := conn.SetDeadline(time.Now().Add(PTProxyHandshakeTO)); err != nil {
		return
	}
	args, err := p.handshake(conn)
	if err != nil {
		log.Tracef("[tor] pt proxy handshake: %v", err)
		return
	}
	if err := p.handleConnect(conn, args); err != nil {
		log.Tracef("[tor] pt proxy connect: %v", err)
	}
}

// handshake negotiates SOCKS5 with MANDATORY RFC 1929 (the pt-spec
// convention: the fields carry the serialized bridge arguments, not
// credentials — there is nothing to authenticate on a loopback PT port,
// the ACL is the credential) and returns the decoded argument map.
func (p *PTProxy) handshake(conn net.Conn) (map[string]string, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("greeting: %w", err)
	}
	if hdr[0] != 0x05 {
		return nil, fmt.Errorf("version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, fmt.Errorf("methods: %w", err)
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
		return nil, errors.New("client refuses RFC 1929 (pt-spec argument channel)")
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		return nil, fmt.Errorf("method select: %w", err)
	}
	// RFC 1929 subnegotiation
	ahdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, ahdr); err != nil {
		return nil, fmt.Errorf("auth header: %w", err)
	}
	if ahdr[0] != 0x01 {
		return nil, fmt.Errorf("auth sub-version %d", ahdr[0])
	}
	uname := make([]byte, ahdr[1])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return nil, fmt.Errorf("username (args part 1): %w", err)
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return nil, fmt.Errorf("password length: %w", err)
	}
	passwd := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return nil, fmt.Errorf("password (args part 2): %w", err)
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("auth result: %w", err)
	}
	// reassemble the argument stream: EACH field's trailing NUL padding
	// stripped before concatenation (a padded login would otherwise plant
	// NULs mid-stream), then the pt-spec un-escaping in parsePTArgs.
	login := strings.TrimRight(string(uname), "\x00")
	pass := strings.TrimRight(string(passwd), "\x00")
	return parsePTArgs(login + pass), nil
}

// parsePTArgs splits the pt-spec k=v;k=v stream (with '\' escapes).
func parsePTArgs(stream string) map[string]string {
	out := map[string]string{}
	if stream == "" {
		return out
	}
	for _, tok := range splitUnescaped(stream, ';') {
		tok = strings.TrimRight(tok, "\x00")
		if tok == "" {
			continue
		}
		eq := indexUnescaped(tok, '=')
		if eq <= 0 {
			continue // malformed token: skip, the factory validates the rest
		}
		k := unescapePT(tok[:eq])
		v := unescapePT(tok[eq+1:])
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

func splitUnescaped(s string, sep byte) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == sep {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	parts = append(parts, cur.String())
	return parts
}

func indexUnescaped(s string, target byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == target {
			return i
		}
	}
	return -1
}

func unescapePT(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// handleConnect reads the CONNECT request, resolves the transport through
// the ACL, parses the endpoint and dials.
func (p *PTProxy) handleConnect(conn net.Conn, args map[string]string) error {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if hdr[0] != 0x05 {
		ptReply(conn, 0x01)
		return fmt.Errorf("request version %d", hdr[0])
	}
	if hdr[1] != 0x01 {
		ptReply(conn, 0x07)
		return fmt.Errorf("command 0x%02x unsupported", hdr[1])
	}
	host, port, err := readBridgeAddress(conn, hdr[3])
	if err != nil {
		ptReply(conn, 0x08)
		return fmt.Errorf("address: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	// ACL: the target must be an active bridge endpoint — the matching
	// bridge's transport selects the factory (scenario 21: a foreign
	// target is refused with 0x02 and NOTHING leaves the process).
	bridge, ok := p.resolveBridge(host, port)
	if !ok {
		ptReply(conn, 0x02)
		return fmt.Errorf("acl: %s:%d is not an active bridge endpoint", host, port)
	}
	factory, ok := p.registry.Get(bridge.Transport)
	if !ok {
		ptReply(conn, 0x02)
		return fmt.Errorf("acl: transport %q has no factory", bridge.Transport)
	}
	endpoint, err := factory.ParseArgs(args)
	if err != nil {
		ptReply(conn, 0x01)
		return fmt.Errorf("parse args: %w", err)
	}

	remote, err := endpoint.Dial(bridge.AddrPort, func(addr string) (net.Conn, error) {
		return p.protectedDial(addr)
	})
	if err != nil {
		ptReply(conn, 0x04) // dial failure: tor reads "bridge dead"
		return fmt.Errorf("endpoint dial: %w", err)
	}
	defer remote.Close()
	if p.live != nil {
		p.live.add(remote)
		defer p.live.remove(remote)
	}
	if err := ptReply(conn, 0x00); err != nil {
		return err
	}
	pipeHalfClose(conn, remote)
	return nil
}

// resolveBridge finds the active bridge whose endpoint matches the
// CONNECT target (IPv6 forms normalized).
func (p *PTProxy) resolveBridge(host string, port uint16) (Bridge, bool) {
	if p.bridges == nil {
		return Bridge{}, false
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	for _, b := range p.bridges() {
		if norm, err := normalizeEndpoint(b.AddrPort); err == nil && norm == target {
			return b, true
		}
	}
	return Bridge{}, false
}

// protectedDial routes a PT transport's raw dial through the egress
// dialer (ClassBridgePT — marked, composable, anti-SSRF-guarded).
func (p *PTProxy) protectedDial(addr string) (net.Conn, error) {
	if p.dial == nil {
		return nil, errors.New("pt proxy: egress dialer not wired")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("pt dial addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("pt dial port %q invalid", portStr)
	}
	ctx, cancel := context.WithTimeout(p.ctx, EgressDirectTimeout*4)
	defer cancel()
	return p.dial(ctx, ClassBridgePT, host, uint16(port))
}

func ptReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// encodePTStream serializes a bridge's args into the pt-spec stream (the
// parser already guarantees no '\' — escaping is the identity here, kept
// for correctness when composing streams programmatically in tests).
func encodePTStream(args map[string]string) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, escapePT(k)+"="+escapePT(args[k]))
	}
	return strings.Join(parts, ";")
}

func escapePT(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', ';', '=':
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
