package vless

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// HelperKind is the external helper that runs the VLESS client and exposes a
// local SOCKS5 inbound (design §3.1/§7). b4x never implements VLESS itself.
type HelperKind string

const (
	HelperXray     HelperKind = "xray"     // default: matches the public corpus
	HelperSingbox  HelperKind = "sing-box" // option: QUIC transport, urltest
	HelperExternal HelperKind = "external" // operator-managed; b4x only dials
)

// NormalizeHelper maps a config value onto a helper kind (empty -> xray).
func NormalizeHelper(s string) (HelperKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(HelperXray):
		return HelperXray, nil
	case string(HelperSingbox), "singbox":
		return HelperSingbox, nil
	case string(HelperExternal):
		return HelperExternal, nil
	default:
		return "", fmt.Errorf("vless: helper %q invalid (xray|sing-box|external)", s)
	}
}

// helperSupports is the capability matrix of design §3.1 point 3: xhttp/kcp
// exist only in Xray, the quic transport only in sing-box, and an unsupported
// combination is a config error — never a silent partial start.
func helperSupports(h HelperKind, transport string) bool {
	switch h {
	case HelperXray:
		switch transport {
		case TransportTCP, TransportWS, TransportGRPC, TransportXHTTP,
			TransportHTTPUpgrade, TransportKCP:
			return true
		}
	case HelperSingbox:
		switch transport {
		case TransportTCP, TransportWS, TransportGRPC,
			TransportHTTPUpgrade, TransportQUIC, TransportHTTP:
			return true
		}
	}
	return false
}

// Render produces the helper config (JSON) for one node with a local SOCKS5
// inbound at socksAddr. The node MUST have passed Validate. An unsupported
// helper/transport pair is an error.
// RenderOptions tunes the helper's local inbound.
type RenderOptions struct {
	// SocksAddr is the local inbound address (host:port).
	SocksAddr string
	// UDP enables UDP ASSOCIATE (Xray settings.udp; sing-box socks is UDP by
	// default, so it is a no-op there).
	UDP bool
	// Mixed uses a single-port SOCKS+HTTP inbound. Only sing-box has a native
	// "mixed" inbound (Xray has separate socks/http protocols, docs
	// xtls.github.io/en/config/inbounds), so mixed is refused for Xray.
	Mixed bool
}

func Render(h HelperKind, n Node, socksAddr string) ([]byte, error) {
	return RenderWith(h, n, RenderOptions{SocksAddr: socksAddr})
}

// RenderWithUDP is Render with the UDP ASSOCIATE toggle (V3).
func RenderWithUDP(h HelperKind, n Node, socksAddr string, udp bool) ([]byte, error) {
	return RenderWith(h, n, RenderOptions{SocksAddr: socksAddr, UDP: udp})
}

// RenderWith renders the helper config for one node.
func RenderWith(h HelperKind, n Node, opts RenderOptions) ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	if h == HelperExternal {
		return nil, fmt.Errorf("vless: helper=external has no rendered config (operator-managed)")
	}
	if !helperSupports(h, n.Transport) {
		return nil, fmt.Errorf("vless: helper %s does not support transport %q", h, n.Transport)
	}
	if opts.Mixed && h != HelperSingbox {
		return nil, fmt.Errorf("vless: mixed inbound requires helper=sing-box (xray has no mixed protocol)")
	}
	listen, port, err := splitSocksAddr(opts.SocksAddr)
	if err != nil {
		return nil, err
	}
	switch h {
	case HelperXray:
		return renderXray(n, listen, port, opts.UDP)
	case HelperSingbox:
		return renderSingbox(n, listen, port, opts.Mixed)
	default:
		return nil, fmt.Errorf("vless: helper %q not renderable", h)
	}
}

func splitSocksAddr(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", 0, fmt.Errorf("vless: socks_addr %q invalid (want host:port)", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("vless: socks_addr port %q invalid", portStr)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host, port, nil
}

func renderXray(n Node, listen string, port int, udp bool) ([]byte, error) {
	ss := map[string]any{
		"network":  xrayNetwork(n.Transport),
		"security": string(n.Security),
	}
	switch n.Security {
	case SecurityReality:
		r := map[string]any{
			"serverName":  n.SNI,
			"publicKey":   n.PublicKey,
			"shortId":     n.ShortID,
			"fingerprint": n.Fingerprint,
			"spiderX":     n.SpiderX,
			"show":        false,
		}
		ss["realitySettings"] = r
	case SecurityTLS:
		t := map[string]any{"serverName": n.SNI}
		if len(n.ALPN) > 0 {
			t["alpn"] = n.ALPN
		}
		if n.Fingerprint != "" {
			t["fingerprint"] = n.Fingerprint
		}
		ss["tlsSettings"] = t
	}
	switch n.Transport {
	case TransportWS:
		w := map[string]any{"path": defPath(n.Path, "/")}
		if n.HostHeader != "" {
			w["headers"] = map[string]any{"Host": n.HostHeader}
		}
		ss["wsSettings"] = w
	case TransportGRPC:
		ss["grpcSettings"] = map[string]any{"serviceName": n.ServiceName}
	case TransportXHTTP:
		x := map[string]any{"path": defPath(n.Path, "/")}
		if n.HostHeader != "" {
			x["host"] = n.HostHeader
		}
		ss["xhttpSettings"] = x
	case TransportHTTPUpgrade:
		hu := map[string]any{"path": defPath(n.Path, "/")}
		if n.HostHeader != "" {
			hu["host"] = n.HostHeader
		}
		ss["httpupgradeSettings"] = hu
	case TransportKCP:
		ss["kcpSettings"] = map[string]any{
			"mtu":    1350,
			"tti":    50,
			"header": map[string]any{"type": defStr(n.HeaderType, "none")},
		}
	}
	user := map[string]any{"id": n.UUID, "encryption": "none"}
	if n.Flow != "" {
		user["flow"] = n.Flow
	}
	doc := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": listen, "port": port, "protocol": "socks",
			"settings": map[string]any{"udp": udp},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": n.Host, "port": int(n.Port), "users": []any{user},
			}}},
			"streamSettings": ss,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func renderSingbox(n Node, listen string, port int, mixed bool) ([]byte, error) {
	out := map[string]any{
		"type":        "vless",
		"server":      n.Host,
		"server_port": int(n.Port),
		"uuid":        n.UUID,
	}
	if n.Flow != "" {
		out["flow"] = n.Flow
	}
	if n.Security != SecurityNone {
		tls := map[string]any{"enabled": true}
		if n.SNI != "" {
			tls["server_name"] = n.SNI
		}
		if len(n.ALPN) > 0 {
			tls["alpn"] = n.ALPN
		}
		if n.Fingerprint != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": n.Fingerprint}
		}
		if n.Security == SecurityReality {
			reality := map[string]any{"enabled": true, "public_key": n.PublicKey}
			if n.ShortID != "" {
				reality["short_id"] = n.ShortID
			}
			tls["reality"] = reality
		}
		out["tls"] = tls
	}
	switch n.Transport {
	case TransportWS:
		w := map[string]any{"type": "ws", "path": defPath(n.Path, "/")}
		if n.HostHeader != "" {
			w["headers"] = map[string]any{"Host": n.HostHeader}
		}
		out["transport"] = w
	case TransportGRPC:
		out["transport"] = map[string]any{"type": "grpc", "service_name": n.ServiceName}
	case TransportHTTPUpgrade:
		hu := map[string]any{"type": "httpupgrade", "path": defPath(n.Path, "/")}
		if n.HostHeader != "" {
			hu["host"] = n.HostHeader
		}
		out["transport"] = hu
	case TransportQUIC:
		out["transport"] = map[string]any{"type": "quic"}
	case TransportHTTP:
		h := map[string]any{"type": "http", "path": defPath(n.Path, "/")}
		if n.HostHeader != "" {
			h["host"] = n.HostHeader
		}
		out["transport"] = h
	}
	inboundType := "socks"
	if mixed {
		inboundType = "mixed" // SOCKS + HTTP CONNECT on one port
	}
	doc := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": inboundType, "listen": listen, "listen_port": port,
		}},
		"outbounds": []any{out},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// xrayNetwork maps the canonical transport onto the Xray streamSettings
// network name. "tcp" is the long-standing spelling every public corpus
// config uses (newer Xray accepts "raw" as an alias too).
func xrayNetwork(t string) string {
	return t
}

func defPath(p, d string) string {
	if strings.TrimSpace(p) == "" {
		return d
	}
	return p
}

func defStr(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
