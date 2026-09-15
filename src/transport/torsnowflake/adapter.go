package torsnowflake

// Snowflake adapter (patch-plan §6.2): bridges the PT-proxy factory
// contract onto snowflake/v2 client/lib. The fork's socket hooks route
// active rendezvous and Pion sockets through the E-TOR policy.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/pion/transport/v4"
	sflib "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"

	"github.com/daniellavrushin/b4/transport/tor"
)

const (
	snowflakeMaxClients = 16
	snowflakeDefaultMax = 1
)

type SnowflakeAdapter struct {
	dial tor.EgressDialFunc
	prot *protectedPionNet

	mu      sync.Mutex
	clients map[string]*sflib.Transport
	keys    []string
}

// NewSnowflakeAdapter keeps the old constructor for tests/embedders. It is
// the direct/availability profile and therefore permits marked direct UDP.
func NewSnowflakeAdapter(dial tor.EgressDialFunc, markCtl tor.MarkControlFunc) *SnowflakeAdapter {
	return NewSnowflakeAdapterPolicy(dial, markCtl, true)
}

// NewSnowflakeAdapterPolicy selects whether Pion may create direct packet
// sockets. Production passes false for a named pinned carrier because the
// reserve.Carrier API is TCP-only; Snowflake then fails closed instead of
// leaking ICE/STUN/DTLS around the carrier.
func NewSnowflakeAdapterPolicy(dial tor.EgressDialFunc, markCtl tor.MarkControlFunc, allowDirectPacket bool) *SnowflakeAdapter {
	a := &SnowflakeAdapter{
		dial:    dial,
		clients: map[string]*sflib.Transport{},
	}
	a.prot = &protectedPionNet{dial: dial, markCtl: markCtl, allowDirectPacket: allowDirectPacket}
	sflib.NetWrapper = func(inner transport.Net) transport.Net { return a.prot.wrap(inner) }
	// Active Snowflake broker/front traffic is part of the selected PT, not
	// a bootstrap-source. ClassPTRendezvous therefore honors a pinned
	// through=<kind> policy instead of being forced into direct-first auto.
	sflib.BrokerDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return a.prot.dialAddr(ctx, tor.ClassPTRendezvous, network, addr)
	}
	return a
}

func (a *SnowflakeAdapter) Name() string { return "snowflake" }

func (a *SnowflakeAdapter) DirectPacketAllowed() bool {
	return a != nil && a.prot != nil && a.prot.allowDirectPacket
}

func (a *SnowflakeAdapter) ParseArgs(args map[string]string) (tor.PTEndpoint, error) {
	cfg, key, err := snowflakeConfigFromArgs(args)
	if err != nil {
		return nil, err
	}
	return &snowflakeEndpoint{adapter: a, key: key, cfg: cfg}, nil
}

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
	if existing, exists := a.clients[key]; exists {
		a.mu.Unlock()
		return existing, nil
	}
	a.clients[key] = t
	a.keys = append(a.keys, key)
	a.mu.Unlock()
	return t, nil
}

func (a *SnowflakeAdapter) ClientCacheLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.clients)
}

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

func serializeArgs(args map[string]string) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+args[k])
	}
	return strings.Join(parts, ";")
}

type snowflakeEndpoint struct {
	adapter *SnowflakeAdapter
	key     string
	cfg     sflib.ClientConfig
}

func (e *snowflakeEndpoint) Dial(dial func(addr string) (net.Conn, error)) (net.Conn, error) {
	t, err := e.adapter.client(e.key, func() (*sflib.Transport, error) {
		return sflib.NewSnowflakeClient(e.cfg)
	})
	if err != nil {
		return nil, fmt.Errorf("snowflake client: %w", err)
	}
	return t.Dial()
}
