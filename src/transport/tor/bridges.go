package tor

// Bridge-line parsing (Nova TorBridge canon, research-nova-tor §D; design
// §1.5/§7.3): the line is the unit of exchange, stored whole. The parser is
// the single admission gate for EVERYTHING that can reach a torrc Bridge
// statement — owner lines, collector mirrors, Moat, builtin sets — so it is
// paranoid by construction:
//
//   - ASCII-only, no ISO control chars (a newline inside a line is a torrc
//     injection, G174), no `\`, `#`, `"`;
//   - first token = transport name (vanilla lines may start with addr:port
//     and get the implicit "vanilla" transport);
//   - fingerprint: 40 hex, possibly split across whitespace tokens
//     (tor glues them back — so do we);
//   - k=v tokens after the fingerprint slot;
//   - argument budget ≤ 510 bytes (SOCKS5 RFC 1929 login+password are 255
//     bytes each — truncated args look like "bridge dead" and are
//     impossible to diagnose, Nova);
//   - sqsqueue/sqscreds are REJECTED (log.Fatalln inside snowflake =
//     process death; our fork also drops the code path, the parser drops
//     the line first);
//   - snowflake max= clamps into 1..8 with a notice (scenario #5); obfs4
//     iat-mode ∈ 0..2;
//   - decoration addresses (RFC 5737/3849 docs ranges, 0.0.0.0, ::) are
//     recognized so the dialer never dials them.
//
// Transports we KNOW but deliberately do not support answer with an honest
// ErrTransportUnsupported ("a count you cannot act on is the wrong count").

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SupportedTransports is the PT registry the pipeline can actually dial.
var SupportedTransports = []string{"obfs4", "webtunnel", "snowflake", "meek_lite", "vanilla"}

// KnownUnsupported lists transports we recognize but refuse: there is no
// live line source for them (Nova canon: honest refusal, not a silent
// dead entry in the set).
var KnownUnsupported = map[string]string{
	"obfs3":        "obfs3 is deprecated upstream; no live bridge source",
	"scramblesuit": "scramblesuit is superseded by obfs4; no live bridge source",
	"meek":         "meek (non-lite) requires a hosted frontend with secrets; meek_lite covers the client case",
	"conjure":      "conjure has no published bridge distribution",
	"dnstt":        "dnstt requires a DNS-over-TXT infrastructure; no live source",
}

// Bridge-line sentinel errors (patch-plan §0.3).
var (
	ErrBridgeLineInvalid    = errors.New("bridge line invalid")
	ErrTransportUnsupported = errors.New("transport unsupported")
)

// MaxSocksArgsBytes is the RFC 1929 budget: login + password fields are
// 255 bytes each (510 total).
const MaxSocksArgsBytes = 510

// Bridge is one parsed bridge line (the Line stays the unit of exchange —
// everything downstream renders it verbatim into torrc).
type Bridge struct {
	// Transport is one of SupportedTransports.
	Transport string
	// Line is the original normalized line (single-spaced, trimmed).
	Line string
	// AddrPort is the dial endpoint; PT transports may carry a decoration
	// placeholder (webtunnel/snowflake) — check DecorationAddr before any
	// dial.
	AddrPort string
	// Fingerprint is 40 hex uppercase, "" when absent (allowed).
	Fingerprint string
	// Args are the k=v bridge arguments (cert, url, fronts, ice, max, ...).
	Args map[string]string
	// Notices carries non-fatal normalizations (e.g. snowflake max=9
	// clamped to 8) so the store/API can surface them honestly.
	Notices []string
}

// Explain renders a human-readable reason for a refusal (API + logs).
func Explain(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ParseBridgeLine parses and validates one bridge line per the design §1.5
// rules. vanilla lines may omit the transport token and start with the
// address; every other line must start with a known transport token.
func ParseBridgeLine(raw string) (Bridge, error) {
	line := strings.Join(strings.Fields(raw), " ")
	if line == "" {
		return Bridge{}, fmt.Errorf("%w: empty line", ErrBridgeLineInvalid)
	}
	if !isASCII(line) {
		return Bridge{}, fmt.Errorf("%w: non-ASCII or control characters in line", ErrBridgeLineInvalid)
	}
	for _, bad := range []byte{'\\', '#', '"'} {
		if strings.IndexByte(line, bad) >= 0 {
			return Bridge{}, fmt.Errorf("%w: forbidden character %q in line", ErrBridgeLineInvalid, string(bad))
		}
	}

	tokens := strings.Split(line, " ")
	transport := ""
	rest := tokens
	if isBridgeTransport(tokens[0]) {
		transport = tokens[0]
		rest = tokens[1:]
	} else if reason, known := KnownUnsupported[strings.ToLower(tokens[0])]; known {
		return Bridge{}, fmt.Errorf("%w: transport %q known but unsupported: %s",
			ErrTransportUnsupported, tokens[0], reason)
	} else if looksLikeAddrPort(tokens[0]) {
		transport = "vanilla"
	} else {
		return Bridge{}, fmt.Errorf("%w: unknown transport token %q", ErrBridgeLineInvalid, tokens[0])
	}
	if len(rest) == 0 {
		return Bridge{}, fmt.Errorf("%w: missing endpoint", ErrBridgeLineInvalid)
	}

	// Endpoint token.
	addrPart := rest[0]
	host, portStr, err := splitBridgeHostPort(rest[0])
	if err != nil {
		return Bridge{}, fmt.Errorf("%w: endpoint %q is not host:port", ErrBridgeLineInvalid, rest[0])
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Bridge{}, fmt.Errorf("%w: port %q outside [1,65535]", ErrBridgeLineInvalid, portStr)
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(addrPart, "[") && net.ParseIP(host) != nil {
		addrPart = net.JoinHostPort(host, portStr) // normalize bare IPv6
	}

	// Fingerprint slot: consecutive hex tokens gluing to exactly 40 chars
	// (tor glues split fingerprints back together — so do we). Absent is
	// legal (go straight to k=v tokens).
	fingerprint := ""
	i := 1
	var fp strings.Builder
	for i < len(rest) {
		tok := strings.TrimPrefix(rest[i], "$")
		if tok == "" || !isHexToken(tok) {
			break
		}
		fp.WriteString(tok)
		i++
		if fp.Len() == 40 {
			fingerprint = strings.ToUpper(fp.String())
			break
		}
		if fp.Len() > 40 {
			return Bridge{}, fmt.Errorf("%w: fingerprint pieces exceed 40 hex chars", ErrBridgeLineInvalid)
		}
	}
	if fingerprint == "" && fp.Len() > 0 && fp.Len() != 40 {
		return Bridge{}, fmt.Errorf("%w: fingerprint pieces total %d hex chars, want 40", ErrBridgeLineInvalid, fp.Len())
	}

	// k=v tokens.
	kv := map[string]string{}
	for j := i; j < len(rest); j++ {
		tok := rest[j]
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			return Bridge{}, fmt.Errorf("%w: token %q is neither k=v nor a fingerprint", ErrBridgeLineInvalid, tok)
		}
		k := tok[:eq]
		v := tok[eq+1:]
		if k == "" || v == "" {
			return Bridge{}, fmt.Errorf("%w: empty key or value in %q", ErrBridgeLineInvalid, tok)
		}
		if _, dup := kv[k]; dup {
			return Bridge{}, fmt.Errorf("%w: duplicate argument %q", ErrBridgeLineInvalid, k)
		}
		kv[k] = v
	}

	// sqs rejection BEFORE anything else touches the args (fail-loud; the
	// parser is the first gate, the fork is the second).
	for _, banned := range []string{"sqsqueue", "sqscreds"} {
		if _, ok := kv[banned]; ok {
			return Bridge{}, fmt.Errorf("%w: argument %s rejected (sqs-rejected: process-killer upstream)",
				ErrBridgeLineInvalid, banned)
		}
	}

	b := Bridge{
		Transport:   transport,
		Line:        line,
		AddrPort:    addrPart,
		Fingerprint: fingerprint,
		Args:        kv,
	}

	// Transport-specific argument policy.
	switch transport {
	case "snowflake":
		if m, ok := kv["max"]; ok {
			n, err := strconv.Atoi(m)
			if err != nil {
				return Bridge{}, fmt.Errorf("%w: snowflake max=%q is not a number", ErrBridgeLineInvalid, m)
			}
			if n < 1 || n > 8 {
				clamped := 8
				if n < 1 {
					clamped = 1
				}
				b.Args["max"] = strconv.Itoa(clamped)
				b.Line = replaceToken(b.Line, "max="+m, "max="+strconv.Itoa(clamped))
				b.Notices = append(b.Notices,
					fmt.Sprintf("snowflake max=%d clamped to %d", n, clamped))
			}
		}
	case "obfs4":
		if m, ok := kv["iat-mode"]; ok {
			n, err := strconv.Atoi(m)
			if err != nil || n < 0 || n > 2 {
				return Bridge{}, fmt.Errorf("%w: obfs4 iat-mode=%q outside [0,2]", ErrBridgeLineInvalid, m)
			}
		}
	}

	// RFC 1929 budget over the SERIALIZED args (the PT proxy packs them
	// into login/password — see SocksArgs).
	if _, _, err := b.SocksArgs(); err != nil {
		return Bridge{}, err
	}
	return b, nil
}

// DecorationAddr reports whether the endpoint is a documentation/placeholder
// address (design §1.5): webtunnel/snowflake lines carry identifiers, not
// dial targets. Such bridges never get a TCP probe.
func (b Bridge) DecorationAddr() bool {
	host, _, err := net.SplitHostPort(b.AddrPort)
	if err != nil {
		return true // unparsable = not dialable
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsLoopback() {
			return true
		}
	}
	for _, doc := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
		if strings.HasPrefix(host, doc) {
			return true
		}
	}
	if strings.HasPrefix(host, "2001:db8:") {
		return true
	}
	return false
}

// SocksArgs renders the bridge arguments for the PT proxy's SOCKS5
// RFC 1929 exchange (Nova parseBridgeArgs canon): arguments are joined
// k=v;k=v (alphabetical order for stability) into login, the password
// carries the overflow past 255 bytes, each field ≤ 255. pt-spec
// backslash-escaping is impossible here — the parser rejects `\` — which
// is exactly why that rejection exists.
func (b Bridge) SocksArgs() (login, password string, err error) {
	if len(b.Args) == 0 {
		return "", "", nil
	}
	keys := make([]string, 0, len(b.Args))
	for k := range b.Args {
		keys = append(keys, k)
	}
	// stable order: alphabetical
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+b.Args[k])
	}
	joined := strings.Join(parts, ";")
	if len(joined) > MaxSocksArgsBytes {
		return "", "", fmt.Errorf("%w: serialized args %d bytes exceed the 510-byte SOCKS5 budget (trim the line)",
			ErrBridgeLineInvalid, len(joined))
	}
	if len(joined) > 255 {
		// pt-spec stream split: the serialized argument stream crosses the
		// login/password boundary at a BYTE offset (Nova parseBridgeArgs
		// canon); the PT proxy concatenates login+password to recover it.
		return joined[:255], joined[255:], nil
	}
	return joined, "", nil
}

// KnownTransport reports whether the transport can be dialed today.
func KnownTransport(name string) bool { return isBridgeTransport(name) }

func isBridgeTransport(tok string) bool {
	switch tok {
	case "obfs4", "webtunnel", "snowflake", "meek_lite", "vanilla":
		return true
	}
	return false
}

func looksLikeAddrPort(tok string) bool {
	_, _, err := splitBridgeHostPort(tok)
	return err == nil
}

// splitBridgeHostPort accepts the bracketed IPv6 form, the IPv4:port form
// and the bare-IPv6-with-port form (last colon splits; the whole-token
// interpretation loses because a trailing port is the published convention
// for bridge endpoints).
func splitBridgeHostPort(tok string) (string, string, error) {
	host, port, err := net.SplitHostPort(tok)
	if err == nil {
		return host, port, nil
	}
	if strings.HasPrefix(tok, "[") {
		return "", "", err // malformed bracket form: no guesswork
	}
	if i := strings.LastIndexByte(tok, ':'); i > 0 {
		prefix, suffix := tok[:i], tok[i+1:]
		if net.ParseIP(prefix) != nil {
			if p, perr := strconv.Atoi(suffix); perr == nil && p >= 1 && p <= 65535 {
				return prefix, suffix, nil
			}
		}
	}
	return "", "", err
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func isHexToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func replaceToken(line, old, new string) string {
	tokens := strings.Split(line, " ")
	for i, t := range tokens {
		if t == old {
			tokens[i] = new
		}
	}
	return strings.Join(tokens, " ")
}
