package torsnowflake

// Snowflake adapter (patch-plan §6.2, the Nova tor_snowflake.go port):
// bridges the PT-proxy factory contract onto the snowflake/v2 client/lib
// library (the b4x fork at tools/snowflake). Bridge-line arguments map
// onto snowflake_client.ClientConfig; clients are cached by their RAW
// serialized argument string (≤16 — the Nova cache canon); the fork's
// socket hooks (NetWrapper / BrokerDialContext) are installed once and
// route everything through the egress dialer:
//
//   - broker/front HTTP  → tor.ClassRendezvous (direct-with-carrier-fallback,
//     never through tor — the anti-loop invariant);
//   - pion TCP (STUN/DTLS/WebRTC data) → ClassBridgePT (honors Through);
//   - pion UDP sockets   → direct, SO_MARK MarkTorEgress (the TCP-only
//     egress policy cannot carry UDP; the mark keeps the engine from
//     capturing its own tunnel's STUN traffic).
//
// sqsqueue/sqscreds never reach this adapter: the parser rejects those
// lines before a client is built (and the fork stubs the path anyway).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/pion/transport/v4"
	sflib "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"

	"github.com/daniellavrushin/b4/transport/tor"
)

// Snowflake adapter constants (Nova tor_snowflake.go canon).
const (
	snowflakeMaxClients = 16
	snowflakeDefaultMax = 1 // library default when the line carries no max=
)

// SnowflakeAdapter is the snowflake TransportFactory for the PT registry.
type SnowflakeAdapter struct {
	dial tor.EgressDialFunc
	prot *protectedPionNet

	mu      sync.Mutex
	clients map[string]*sflib.Transport
	keys    []string // insertion order for the bounded cache
}

// NewSnowflakeAdapter wires the seam and installs the fork hooks. The
// hooks are process-global (that is the fork's contract) — exactly one
// adapter owns them per process.
func NewSnowflakeAdapter(dial tor.EgressDialFunc, markCtl tor.MarkControlFunc) *SnowflakeAdapter {
	a := &SnowflakeAdapter{
		dial:    dial,
		clients: map[string]*sflib.Transport{},
	}
	a.prot = &protectedPionNet{dial: dial, markCtl: markCtl}
	sflib.NetWrapper = func(inner transport.Net) transport.Net { return a.prot.wrap(inner) }
	sflib.BrokerDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return a.prot.dialAddr(ctx, tor.ClassRendezvous, network, addr)
	}
	return a
}

// Name implements TransportFactory.
func (a *SnowflakeAdapter) Name() string { return "snowflake" }

// ParseArgs implements TransportFactory: the bridge k=v set becomes a
// snowflake ClientConfig; the endpoint dials through a cached client.
func (a *SnowflakeAdapter) ParseArgs(args map[string]string) (tor.PTEndpoint, error) {
	cfg, key, err := snowflakeConfigFromArgs(args)
	if err != nil {
		return nil, err
	}
	return &snowflakeEndpoint{adapter: a, key: key, cfg: cfg}, nil
}

// client returns the cached transport for a raw-args key, creating it on
// first use (the Nova canon: one client per argument shape, bounded 16).
func (a *SnowflakeAdapter) client(key string, build func() (*sflib.Transport, error)) (*sflib.Transport, error) {
	a.mu.Lock()
	if t, ok := a.clients[key]; ok {
		a.mu.Unlock()
		return t, nil
	}
	if len(a.keys) >= snowflakeMaxClients {
		oldest := a.keys[0]
		a.keys = a.keys[1:]
		delete(a.clients, oldest)
	}
	a.mu.Unlock()

	t, err := build()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if _, exists := a.clients[key]; !exists { // racy builders: first one wins
		a.clients[key] = t
		a.keys = append(a.keys, key)
	}
	a.mu.Unlock()
	return a.clients[key], nil
}

// ClientCacheLen reports the cache occupancy (status/tests).
func (a *SnowflakeAdapter) ClientCacheLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.clients)
}

// snowflakeConfigFromArgs maps the bridge-line k=v set onto the library
// config (the Nova tor_snowflake.go ParseArgs mapping). The returned key
// is the RAW serialized argument string (cache identity).
func snowflakeConfigFromArgs(args map[string]string) (sflib.ClientConfig, string, error) {
	cfg := sflib.ClientConfig{}
	if v, ok := args["url"]; ok {
		cfg.BrokerURL = v
	}
	if v, ok := args["ampcache"]; ok {
		cfg.AmpCacheURL = v
	}
	if v, ok := args["fronts"]; ok && v != "" {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				cfg.FrontDomains = append(cfg.FrontDomains, f)
			}
		}
	}
	if v, ok := args["front"]; ok && v != "" {
		cfg.FrontDomains = append(cfg.FrontDomains, v)
	}
	if v, ok := args["ice"]; ok && v != "" {
		for _, raw := range strings.Split(v, ",") {
			if u := strings.TrimSpace(raw); u != "" {
				cfg.ICEAddresses = append(cfg.ICEAddresses, u)
			}
		}
	}
	if v, ok := args["max"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 8 {
			return cfg, "", fmt.Errorf("snowflake max=%q outside [1,8]", v)
		}
		cfg.Max = n
	} else {
		cfg.Max = snowflakeDefaultMax
	}
	if v, ok := args["utls-imitate"]; ok {
		cfg.UTLSClientID = v
	}
	if v, ok := args["utls-nosni"]; ok && (v == "1" || strings.EqualFold(v, "true")) {
		cfg.UTLSRemoveSNI = true
	}
	if v, ok := args["fingerprint"]; ok {
		cfg.BridgeFingerprint = v
	}
	if v, ok := args["covertdtls-mode"]; ok {
		cfg.CovertDTLSConfig = v
	}
	// sqsqueue/sqscreds: the parser already rejects them; the adapter
	// double-checks so no future caller can smuggle them past (the fork
	// stubs the SQS path — this is the loud refusal).
	for _, banned := range []string{"sqsqueue", "sqscreds"} {
		if _, ok := args[banned]; ok {
			return cfg, "", fmt.Errorf("snowflake argument %s rejected (sqs-rejected)", banned)
		}
	}
	if cfg.BrokerURL == "" && cfg.AmpCacheURL == "" {
		return cfg, "", errors.New("snowflake line needs url= or ampcache= (rendezvous place)")
	}
	return cfg, serializeArgs(args), nil
}

// serializeArgs renders the cache key (stable, alphabetical).
func serializeArgs(args map[string]string) string {
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
		parts = append(parts, k+"="+args[k])
	}
	return strings.Join(parts, ";")
}

// snowflakeEndpoint is the tor.PTEndpoint over a cached snowflake client.
type snowflakeEndpoint struct {
	adapter *SnowflakeAdapter
	key     string
	cfg     sflib.ClientConfig
}

// Dial implements tor.PTEndpoint: the snowflake transport dials its own
// WebRTC path (the CONNECT target is a decoration identifier — the real
// path lives inside the transport).
func (e *snowflakeEndpoint) Dial(dial func(addr string) (net.Conn, error)) (net.Conn, error) {
	t, err := e.adapter.client(e.key, func() (*sflib.Transport, error) {
		return sflib.NewSnowflakeClient(e.cfg)
	})
	if err != nil {
		return nil, fmt.Errorf("snowflake client: %w", err)
	}
	return t.Dial()
}
