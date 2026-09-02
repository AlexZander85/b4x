// Package operaservice assembles the dependency-free Opera/SurfEasy reserve
// engine (src/transport/opera: OP1 control channel + OP2 data plane + OP3
// health) from the main config — the deliberately-thin "last mile" mirroring
// warpservice.
//
// Integration contract (design §5, stage OP4):
//
//   - role kind "opera": a userspace Backend-B style TCP carrier; consumers
//     take Runtime.DialStream (the warp StreamDialer shape) and the scoped
//     router treats it like every other userspace carrier;
//
//   - anti-loop: sec-tunnel.com must always stay DIRECT at the route level
//     (zapret-gui chain lesson). In-code, DialStream refuses dialing the
//     transport's OWN node addresses through itself, and
//     SecTunnelBypassSuffixes is exported for the field layer to build its
//     DIRECT rules;
//
//   - bootstrap-through-carrier: when the direct egress cannot reach
//     api2.sec-tunnel.com, control-channel AND data-plane dials fall back to
//     the injected base-transport carrier (failover dialer);
//
//   - UDP fail-closed: the transport is TCP-only by protocol; non-tcp dials
//     fail closed at the dialer and SupportsUDP() reports false honestly.
package operaservice

import (
        "context"
        "errors"
        "fmt"
        "net"
        "net/netip"
        "strings"
        "sync"

        "github.com/daniellavrushin/b4/config"
        opera "github.com/daniellavrushin/b4/transport/opera"
)

// DialFunc is the base TCP dial shape shared with the warp engine.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// SecTunnelBypassSuffixes lists domains that must NEVER traverse any tunnel
// route (anti-loop, design §5). The field layer consumes this for its DIRECT
// rules; in-code the same invariant is enforced by refuseNodeSelfLoop.
var SecTunnelBypassSuffixes = []string{"sec-tunnel.com"}

// IsBypassDomain reports whether host is (a subdomain of) a bypass domain.
func IsBypassDomain(host string) bool {
        h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
        if h == "" {
                return false
        }
        for _, s := range SecTunnelBypassSuffixes {
                if h == s || strings.HasSuffix(h, "."+s) {
                        return true
                }
        }
        return false
}

// ErrOperaSelfLoop is returned when a consumer asks the opera tunnel to
// carry traffic addressed to the transport's own infrastructure.
var ErrOperaSelfLoop = errors.New("operaservice: refusing self-loop through opera tunnel")

// Options assembles the runtime; zero values are valid.
type Options struct {
        // Carrier is the active base-transport dial (MASQUE/WG). When set,
        // every opera dial tries DIRECT first and falls back to the carrier —
        // "the reserve that reaches out through the base tunnel" (design §5).
        Carrier DialFunc
        // Client overrides the constructed engine client (test injection).
        Client *opera.Client
        // Supervisor overrides the constructed health supervisor (tests).
        Supervisor func(c *opera.Client) (*opera.HealthSupervisor, error)
}

// Runtime owns one assembled Opera transport for a config generation.
type Runtime struct {
        cfg    config.OperaConfig
        client *opera.Client
        sup    *opera.HealthSupervisor

        mu      sync.Mutex
        started bool
        stopped bool
        cancel  context.CancelFunc
}

// Build validates the system.opera section and constructs the runtime
// WITHOUT starting anything. It succeeds even when Enabled=false so the
// daemon gates on config itself (warpservice parity).
func Build(cfg *config.Config, opts Options) (*Runtime, error) {
        oc := cfg.System.Opera
        if oc.IdentityPath == "" {
                oc.IdentityPath = config.DefaultOperaIdentityPath
        }
        if strings.TrimSpace(oc.Region) == "" {
                oc.Region = opera.RegionEU // zero-config assembly defaults to EU
        }
        region, err := opera.NormalizeRegion(oc.Region)
        if err != nil {
                return nil, fmt.Errorf("operaservice: system.opera.region: %w", err)
        }

        client := opts.Client
        if client == nil {
                dial := failoverDialer(nil, opts.Carrier)
                c, err := opera.New(opera.Options{
                        DialContext: dial,
                        Slot:        &opera.IdentityStore{Path: oc.IdentityPath},
                })
                if err != nil {
                        return nil, fmt.Errorf("operaservice: engine client: %w", err)
                }
                client = c
        }

        var sup *opera.HealthSupervisor
        if opts.Supervisor != nil {
                sup, err = opts.Supervisor(client)
        } else {
                hc := opera.DefaultHealthConfig(region)
                hc.ControlTarget = oc.ControlTarget
                sup, err = opera.NewHealthSupervisor(client, hc)
        }
        if err != nil {
                return nil, fmt.Errorf("operaservice: health supervisor: %w", err)
        }
        return &Runtime{cfg: oc, client: client, sup: sup}, nil
}

// failoverDialer composes direct-first / carrier-second egress.
func failoverDialer(direct, carrier DialFunc) DialFunc {
        if direct == nil {
                d := &net.Dialer{}
                direct = d.DialContext
        }
        if carrier == nil {
                return direct
        }
        return func(ctx context.Context, network, addr string) (net.Conn, error) {
                conn, err := direct(ctx, network, addr)
                if err == nil {
                        return conn, nil
                }
                cconn, cerr := carrier(ctx, network, addr)
                if cerr != nil {
                        return nil, fmt.Errorf("direct: %v; carrier: %w", err, cerr)
                }
                return cconn, nil
        }
}

// Start launches the health supervisor loop (daemon mode only). The config
// gate (system.opera.enabled) belongs to the caller, like warpservice.
func (r *Runtime) Start(ctx context.Context) error {
        r.mu.Lock()
        defer r.mu.Unlock()
        if r.stopped {
                return errors.New("operaservice: runtime already stopped")
        }
        if r.started {
                return nil
        }
        runCtx, cancel := context.WithCancel(ctx)
        r.cancel = cancel
        r.started = true
        go r.sup.Run(runCtx)
        return nil
}

// Stop tears the loop down (no-op before Start).
func (r *Runtime) Stop() {
        r.mu.Lock()
        defer r.mu.Unlock()
        if !r.started || r.stopped {
                return
        }
        r.stopped = true
        if r.cancel != nil {
                r.cancel()
        }
}

// SetRegion switches the desired megaregion keeping the device identity
// (design §5: region lives in discover, not in registration).
func (r *Runtime) SetRegion(region string) error { return r.sup.SetDesiredRegion(region) }

// Kick runs one supervision step immediately on its own goroutine (HTTP
// restart endpoint). Caps and cooldowns inside the health layer still apply;
// the call itself never blocks on the supervisor mutex.
func (r *Runtime) Kick(ctx context.Context) {
        go r.sup.Tick(r.sup.Now())
}

// SupportsUDP is a protocol constant: SurfEasy nodes speak CONNECT over
// TLS/TCP only. UDP-scope traffic must never be routed here (design §5,
// red line #5) — honest static answer for status consumers.
func (r *Runtime) SupportsUDP() bool { return false }

// Status combines health state with assembly-level facts.
type Status struct {
        opera.HealthStatus
        Enabled      bool   `json:"enabled"`
        Transport    string `json:"transport"`     // constant "tcp-only"
        FakeSNI      string `json:"fake_sni,omitempty"`
        IdentityPath string `json:"identity_path"`
}

// Status snapshots the runtime.
func (r *Runtime) Status() Status {
        return Status{
                HealthStatus: r.sup.Status(),
                Enabled:      r.cfg.Enabled,
                Transport:    "tcp-only",
                FakeSNI:      r.cfg.FakeSNI,
                IdentityPath: r.cfg.IdentityPath,
        }
}

// DialStream dials ONE TCP stream to addr THROUGH the currently selected
// node (the warp StreamDialer contract, Backend-B userspace carrier shape).
// Self-loop targets (the transport's own node IPs) are refused.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
        entry := r.sup.ActiveEntry()
        if entry.IP == "" {
                return nil, errors.New("operaservice: no active node (bootstrap pending)")
        }
        if refuseNodeSelfLoop(entry, addr.Addr()) {
                return nil, ErrOperaSelfLoop
        }
        nd, err := r.client.NodeDialer(entry, r.cfg.FakeSNI)
        if err != nil {
                return nil, err
        }
        return nd.DialContext(ctx, "tcp", addr.String())
}

// ActiveNodeAddr exposes the current node for diagnostics/status pages.
func (r *Runtime) ActiveNodeAddr() string { return r.sup.Status().ActiveNode }

// refuseNodeSelfLoop reports whether target equals one of the transport's
// own node addresses (dialing ourselves through ourselves = loop).
func refuseNodeSelfLoop(entry opera.SEIPEntry, target netip.Addr) bool {
        tip, err := netip.ParseAddr(entry.IP)
        if err != nil {
                return false
        }
        return tip == target.Unmap()
}
