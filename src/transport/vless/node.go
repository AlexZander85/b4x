// Package vless is the dependency-free VLESS(+REALITY) engine of the b4x
// reserve family (design .ag/research/vless-tunnel-design.md §5/§8).
//
// b4x does NOT implement the VLESS protocol itself: it renders the config of
// an EXTERNAL helper (xray-core / sing-box), dials the helper's local SOCKS5
// inbound and owns node selection. This package is the engine side only:
//   - node.go:          the Node model + vless:// and sing-box parsers + rules
//   - render.go:        helper-agnostic config rendering with a capability matrix
//   - subscription.go:  subscription fetch/decode/parse/dedup with defensive caps
//   - sources.go:       the curated bundled aggregator list
//
// It imports nothing from config so the config package can validate node
// syntax by calling into here (dependency direction: config -> transport/vless,
// the same shape config -> transport/tor already uses).
package vless

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Security is the transport security of a node.
type Security string

const (
	SecurityNone    Security = "none"
	SecurityTLS     Security = "tls"
	SecurityReality Security = "reality"
)

// Canonical transport names. "raw" (Xray) and "tcp" are the same transport;
// a parsed node always carries the canonical "tcp".
const (
	TransportTCP         = "tcp" // raw/tcp
	TransportWS          = "ws"
	TransportGRPC        = "grpc"
	TransportXHTTP       = "xhttp" // Xray-only (xhttp/splithttp)
	TransportHTTPUpgrade = "httpupgrade"
	TransportKCP         = "kcp"  // Xray-only
	TransportQUIC        = "quic" // sing-box-only
	TransportHTTP        = "http" // sing-box-only (HTTP/2)
)

// FlowVision is the only XTLS flow the corpus uses (design §8).
const FlowVision = "xtls-rprx-vision"

// Node is one VLESS endpoint in a helper-agnostic shape. Zero values resolve
// to the protocol defaults at Validate time (security none, transport tcp).
type Node struct {
	// Name is the human label (URI fragment / sing-box tag). Not part of the
	// identity, so two differently-named copies of the same endpoint dedup.
	Name string `json:"name,omitempty"`
	// UUID is the VLESS user id (required).
	UUID string `json:"uuid"`
	// Host is the server hostname or IP (required).
	Host string `json:"host"`
	// Port is the server port (required, 1..65535).
	Port uint16 `json:"port"`
	// Security is none|tls|reality (default none).
	Security Security `json:"security,omitempty"`
	// SNI is the TLS server name (REALITY: the borrowed site; required).
	SNI string `json:"sni,omitempty"`
	// Fingerprint is the uTLS client fingerprint ("" = helper default).
	Fingerprint string `json:"fp,omitempty"`
	// ALPN is the offered ALPN list.
	ALPN []string `json:"alpn,omitempty"`
	// PublicKey is the REALITY x25519 public key (required for reality).
	PublicKey string `json:"pbk,omitempty"`
	// ShortID is the REALITY short id (optional).
	ShortID string `json:"sid,omitempty"`
	// SpiderX is the REALITY spider path (optional).
	SpiderX string `json:"spx,omitempty"`
	// Flow is the XTLS flow (only xtls-rprx-vision, only with TLS/REALITY).
	Flow string `json:"flow,omitempty"`
	// Transport is the canonical transport name (default tcp).
	Transport string `json:"network,omitempty"`
	// Path is the WS/HTTPUpgrade/XHTTP path.
	Path string `json:"path,omitempty"`
	// HostHeader is the WS/HTTPUpgrade/XHTTP Host header.
	HostHeader string `json:"host_header,omitempty"`
	// ServiceName is the gRPC service name.
	ServiceName string `json:"serviceName,omitempty"`
	// Mode is the KCP/QUIC mode (e.g. "gun", "none").
	Mode string `json:"mode,omitempty"`
	// HeaderType is the KCP header type (e.g. "none", "srtp").
	HeaderType string `json:"headerType,omitempty"`
}

// Stats reports a parse pass (collector-parity accounting, design §8).
type Stats struct {
	Total     int `json:"total"`
	VLESS     int `json:"vless"`
	Other     int `json:"other"`     // vmess/ss/trojan/... — not our protocol
	Bad       int `json:"bad"`       // looked like ours but failed to parse
	Duplicate int `json:"duplicate"` // identity already seen
	Truncated int `json:"truncated"` // a fragment without a scheme
}

// Identity is the normalized dedup key: two endpoints are the same node when
// every field that affects the wire behavior matches (name excluded).
func (n Node) Identity() string {
	parts := []string{
		strings.ToLower(n.UUID),
		strings.ToLower(n.Host) + ":" + strconv.Itoa(int(n.Port)),
		string(n.Security),
		strings.ToLower(n.SNI),
		strings.ToLower(n.Fingerprint),
		strings.Join(lowerAll(n.ALPN), ","),
		strings.ToLower(n.PublicKey),
		strings.ToLower(n.ShortID),
		n.SpiderX,
		strings.ToLower(n.Flow),
		strings.ToLower(n.Transport),
		n.Path,
		strings.ToLower(n.HostHeader),
		n.ServiceName,
		strings.ToLower(n.Mode),
		strings.ToLower(n.HeaderType),
	}
	return strings.Join(parts, "|")
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}

// utlsFingerprints is the closed set the helpers accept. An unknown fp is a
// dropped node (design §8: "неизвестный fp — отбросить").
var utlsFingerprints = map[string]bool{
	"chrome": true, "firefox": true, "safari": true, "ios": true,
	"android": true, "edge": true, "360": true, "qq": true,
	"random": true, "randomized": true,
}

// sniBlocklist entries are never plausible camouflage names (design §3.2).
var sniBlocklist = map[string]bool{
	"localhost": true, "example.com": true, "example.org": true,
	"example.net": true, "test": true, "invalid": true, "local": true,
}

// PlausibleSNI reports whether s is a believable camouflage server name:
// non-empty, not a bare IP, has a dot, RFC-1123 labels, not a placeholder.
func PlausibleSNI(s string) bool {
	v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if v == "" || len(v) > 253 || net.ParseIP(v) != nil {
		return false
	}
	if sniBlocklist[v] {
		return false
	}
	if !strings.Contains(v, ".") {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// Validate applies the protocol rules of design §8. It fills protocol
// defaults in place (security none, transport tcp) and returns the first
// violation. A node failing Validate MUST be dropped, never rendered.
func (n *Node) Validate() error {
	n.UUID = strings.TrimSpace(n.UUID)
	n.Host = strings.TrimSpace(n.Host)
	if n.UUID == "" {
		return fmt.Errorf("vless: node %q: empty uuid", label(n))
	}
	if n.Host == "" {
		return fmt.Errorf("vless: node %q: empty host", label(n))
	}
	if n.Port == 0 {
		return fmt.Errorf("vless: node %q: missing port", label(n))
	}
	if n.Security == "" {
		n.Security = SecurityNone
	}
	switch n.Security {
	case SecurityNone, SecurityTLS, SecurityReality:
	default:
		return fmt.Errorf("vless: node %q: security %q invalid (none|tls|reality)", label(n), n.Security)
	}
	if n.Transport == "" || n.Transport == "raw" {
		n.Transport = TransportTCP
	}
	switch n.Transport {
	case TransportTCP, TransportWS, TransportGRPC, TransportXHTTP,
		TransportHTTPUpgrade, TransportKCP, TransportQUIC, TransportHTTP:
	default:
		return fmt.Errorf("vless: node %q: transport %q unsupported", label(n), n.Transport)
	}
	if n.Fingerprint != "" && !utlsFingerprints[strings.ToLower(n.Fingerprint)] {
		return fmt.Errorf("vless: node %q: unknown fingerprint %q", label(n), n.Fingerprint)
	}
	if n.Flow != "" && n.Flow != FlowVision {
		return fmt.Errorf("vless: node %q: flow %q invalid (only %s)", label(n), n.Flow, FlowVision)
	}
	if n.Flow != "" && n.Security == SecurityNone {
		return fmt.Errorf("vless: node %q: flow %s requires tls or reality", label(n), n.Flow)
	}
	if n.Security == SecurityReality {
		switch n.Transport {
		case TransportTCP, TransportXHTTP, TransportGRPC:
		default:
			return fmt.Errorf("vless: node %q: reality requires tcp|xhttp|grpc (got %s)", label(n), n.Transport)
		}
		if n.PublicKey == "" {
			return fmt.Errorf("vless: node %q: reality requires pbk", label(n))
		}
		if !PlausibleSNI(n.SNI) {
			return fmt.Errorf("vless: node %q: reality sni %q not plausible", label(n), n.SNI)
		}
	}
	if n.Security == SecurityTLS && n.SNI != "" && !PlausibleSNI(n.SNI) {
		return fmt.Errorf("vless: node %q: tls sni %q not plausible", label(n), n.SNI)
	}
	for _, a := range n.ALPN {
		if strings.TrimSpace(a) == "" {
			return fmt.Errorf("vless: node %q: empty alpn entry", label(n))
		}
	}
	return nil
}

func label(n *Node) string {
	if n.Name != "" {
		return n.Name
	}
	if n.Host != "" {
		return n.Host
	}
	return "<unnamed>"
}

// ParseURI parses one `vless://` link. The returned node is NOT validated —
// callers run ParseMany (which validates and accounts) or call Validate.
func ParseURI(raw string) (Node, error) {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(s), "vless://") {
		return Node{}, fmt.Errorf("vless: not a vless:// uri")
	}
	u, err := url.Parse(s)
	if err != nil {
		return Node{}, fmt.Errorf("vless: parse uri: %w", err)
	}
	n := Node{Name: u.Fragment}
	if u.User != nil {
		n.UUID = u.User.Username()
	}
	host := u.Hostname()
	if host == "" {
		return Node{}, fmt.Errorf("vless: uri missing host")
	}
	n.Host = host
	if p := u.Port(); p != "" {
		v, err := strconv.Atoi(p)
		if err != nil || v < 1 || v > 65535 {
			return Node{}, fmt.Errorf("vless: uri port %q invalid", p)
		}
		n.Port = uint16(v)
	}
	q := u.Query()
	n.Security = Security(strings.ToLower(strings.TrimSpace(q.Get("security"))))
	n.SNI = q.Get("sni")
	n.Fingerprint = strings.ToLower(strings.TrimSpace(q.Get("fp")))
	if alpn := q.Get("alpn"); alpn != "" {
		n.ALPN = splitCSV(alpn)
	}
	n.PublicKey = q.Get("pbk")
	n.ShortID = q.Get("sid")
	n.SpiderX = q.Get("spx")
	n.Flow = strings.TrimSpace(q.Get("flow"))
	n.Transport = strings.ToLower(strings.TrimSpace(q.Get("type")))
	n.Path = q.Get("path")
	n.HostHeader = q.Get("host")
	n.ServiceName = q.Get("serviceName")
	n.Mode = q.Get("mode")
	n.HeaderType = q.Get("headerType")
	return n, nil
}

func splitCSV(in string) []string {
	out := []string{}
	for _, p := range strings.Split(in, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// singboxOutbound is the subset of a sing-box outbound we understand.
type singboxOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
	UUID       string `json:"uuid"`
	Flow       string `json:"flow"`
	TLS        *struct {
		Enabled    bool     `json:"enabled"`
		ServerName string   `json:"server_name"`
		ALPN       []string `json:"alpn"`
		UTLS       *struct {
			Enabled     bool   `json:"enabled"`
			Fingerprint string `json:"fingerprint"`
		} `json:"utls"`
		Reality *struct {
			Enabled   bool   `json:"enabled"`
			PublicKey string `json:"public_key"`
			ShortID   string `json:"short_id"`
		} `json:"reality"`
	} `json:"tls"`
	Transport *struct {
		Type        string         `json:"type"`
		Path        string         `json:"path"`
		Host        string         `json:"host"`
		ServiceName string         `json:"service_name"`
		Headers     map[string]any `json:"headers"`
	} `json:"transport"`
}

// ParseSingbox parses one sing-box outbound object or a whole sing-box config
// document containing an "outbounds" array. It returns every VLESS outbound
// found (non-vless outbounds are skipped, not an error).
func ParseSingbox(raw string) ([]Node, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, fmt.Errorf("vless: not json")
	}
	var outs []singboxOutbound
	if trimmed[0] == '[' {
		if err := json.Unmarshal([]byte(trimmed), &outs); err != nil {
			return nil, fmt.Errorf("vless: singbox json: %w", err)
		}
	} else {
		var doc struct {
			Outbounds []singboxOutbound `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
			return nil, fmt.Errorf("vless: singbox json: %w", err)
		}
		outs = doc.Outbounds
		if len(outs) == 0 {
			var single singboxOutbound
			if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
				return nil, fmt.Errorf("vless: singbox json: %w", err)
			}
			if single.Type != "" {
				outs = []singboxOutbound{single}
			}
		}
	}
	nodes := make([]Node, 0, len(outs))
	for _, o := range outs {
		if strings.ToLower(o.Type) != "vless" {
			continue
		}
		n := Node{
			Name:     o.Tag,
			UUID:     o.UUID,
			Host:     o.Server,
			Port:     o.ServerPort,
			Flow:     o.Flow,
			Security: SecurityNone,
		}
		if o.TLS != nil && o.TLS.Enabled {
			n.SNI = o.TLS.ServerName
			n.ALPN = o.TLS.ALPN
			n.Security = SecurityTLS
			if o.TLS.UTLS != nil && o.TLS.UTLS.Enabled {
				n.Fingerprint = strings.ToLower(o.TLS.UTLS.Fingerprint)
			}
			if o.TLS.Reality != nil && o.TLS.Reality.Enabled {
				n.Security = SecurityReality
				n.PublicKey = o.TLS.Reality.PublicKey
				n.ShortID = o.TLS.Reality.ShortID
			}
		}
		if o.Transport != nil {
			n.Transport = strings.ToLower(o.Transport.Type)
			n.Path = o.Transport.Path
			n.ServiceName = o.Transport.ServiceName
			if o.Transport.Host != "" {
				n.HostHeader = o.Transport.Host
			} else if o.Transport.Headers != nil {
				if h, ok := o.Transport.Headers["Host"].(string); ok {
					n.HostHeader = h
				}
			}
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("vless: no vless outbound in json")
	}
	return nodes, nil
}

// ParseMany parses a whole body (one node/URI per line) with defensive
// accounting: a broken line is dropped, the import never fails wholesale.
// Duplicates (by Identity) are counted and skipped.
func ParseMany(lines []string) ([]Node, Stats) {
	nodes := make([]Node, 0, len(lines))
	seen := make(map[string]bool, len(lines))
	var st Stats
	for _, raw := range lines {
		line := strings.TrimSpace(strings.Trim(raw, "\ufeff"))
		if line == "" {
			continue
		}
		st.Total++
		var parsed []Node
		switch {
		case strings.HasPrefix(strings.ToLower(line), "vless://"):
			n, err := ParseURI(line)
			if err != nil {
				st.Bad++
				continue
			}
			parsed = []Node{n}
		case line[0] == '{' || line[0] == '[':
			ns, err := ParseSingbox(line)
			if err != nil {
				st.Bad++
				continue
			}
			parsed = ns
		case strings.Contains(line, "://"):
			st.Other++
			continue
		default:
			st.Truncated++
			continue
		}
		for i := range parsed {
			n := parsed[i]
			if err := n.Validate(); err != nil {
				st.Bad++
				continue
			}
			id := n.Identity()
			if seen[id] {
				st.Duplicate++
				continue
			}
			seen[id] = true
			nodes = append(nodes, n)
			st.VLESS++
		}
	}
	return nodes, st
}

// ParseAny parses ONE config entry: a vless:// URI or a sing-box JSON object
// (config or outbound). The result is validated. Used by config validation.
func ParseAny(line string) ([]Node, error) {
	s := strings.TrimSpace(line)
	if s == "" {
		return nil, fmt.Errorf("vless: empty entry")
	}
	if strings.HasPrefix(strings.ToLower(s), "vless://") {
		n, err := ParseURI(s)
		if err != nil {
			return nil, err
		}
		if err := n.Validate(); err != nil {
			return nil, err
		}
		return []Node{n}, nil
	}
	if s[0] == '{' || s[0] == '[' {
		ns, err := ParseSingbox(s)
		if err != nil {
			return nil, err
		}
		for i := range ns {
			if err := ns[i].Validate(); err != nil {
				return nil, err
			}
		}
		return ns, nil
	}
	return nil, fmt.Errorf("vless: unrecognized node syntax (want vless:// or json)")
}

// SortByName returns nodes ordered by name then host for stable output.
func SortByName(nodes []Node) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Name != nodes[j].Name {
			return nodes[i].Name < nodes[j].Name
		}
		return nodes[i].Host < nodes[j].Host
	})
}
