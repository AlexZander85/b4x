// Command operatester is the isolated field CLI for the Opera/SurfEasy
// reserve transport (E-OPERA field prompt §4). It runs entirely in
// userspace: it never touches the live b4 binary, /opt/etc/b4/b4.json, the
// NFQUEUE rules or the router's routes (prompt §3 — anti-loop rules belong
// to the b4x-6da daemon-wiring ticket). The engine is src/transport/opera,
// the assembly src/operaservice, exactly like the daemon path.
//
//	operatester register [--config c.json]      # EnsureSession (adopt|fresh) + discover
//	operatester status   [--config c.json]      # slot + HealthStatus (running/listening/...)
//	operatester probe    [--deep] [--fake-sni d] [--http] [--config c.json]
//	operatester relay    --target host:port [--config c.json]
//	operatester watch    [--interval 60s] [--config c.json]
//	operatester region   EU|AS|AM [--config c.json]
//	operatester udp-probe [--config c.json]     # expected fail-closed refusal (TCP-only)
//
// The config file is optional; omitted sections fall back to
// config.DefaultConfig's System.Opera (region EU, identity slot
// /opt/etc/b4/opera/identity.json). Every network operation is bounded by a
// 30s context. Exit codes: 0 ok, 1 fail, 2 usage.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/operaservice"
	"github.com/daniellavrushin/b4/reserve"
	opera "github.com/daniellavrushin/b4/transport/opera"
)

const (
	// opTimeout bounds every one-shot network phase (prompt §4).
	opTimeout = 30 * time.Second
	// relayIdleWindow is how long relay waits for more tunnel bytes before it
	// considers the exchange finished (echo peers keep the socket open). The
	// SurfEasy uplink is slow in the field, so a large payload's tail can take
	// a while; too small a window truncates the checksum comparison.
	relayIdleWindow = 30 * time.Second

	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// errUsage marks a flag/argument error so run() can map it to exit code 2.
var errUsage = errors.New("usage error")

func usageErr(err error) error { return fmt.Errorf("%w: %v", errUsage, err) }

// deps carries the injectable seams. Unit tests replace newRuntime/signals;
// production uses the defaults.
type deps struct {
	stdout io.Writer
	stderr io.Writer
	stdin  io.Reader
	// newRuntime assembles the runtime from the loaded config. Tests inject a
	// runtime wired to a loopback-only lite stand.
	newRuntime func(cfg *config.Config) (*operaservice.Runtime, error)
	// signals returns the long-running watch context (SIGINT/SIGTERM).
	signals func() (context.Context, context.CancelFunc)
}

func defaultDeps() *deps {
	return &deps{
		stdout: os.Stdout,
		stderr: os.Stderr,
		stdin:  os.Stdin,
		newRuntime: func(cfg *config.Config) (*operaservice.Runtime, error) {
			return operaservice.Build(cfg, operaservice.Options{})
		},
		signals: func() (context.Context, context.CancelFunc) {
			return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		},
	}
}

func newFlagSet(name string, d *deps) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(d.stderr)
	return fs
}

func (d *deps) build(cfg *config.Config) (*operaservice.Runtime, error) {
	if d.newRuntime != nil {
		return d.newRuntime(cfg)
	}
	return operaservice.Build(cfg, operaservice.Options{})
}

func printJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// loadConfig returns the config with System.Opera defaults applied. An empty
// path means "defaults only" (config.DefaultConfig-derived) — the CLI must
// never write anything back.
func loadConfig(path string) (*config.Config, error) {
	c := config.NewConfig()
	if strings.TrimSpace(path) != "" {
		if _, err := c.LoadWithMigration(path); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(c.System.Opera.IdentityPath) == "" {
		c.System.Opera.IdentityPath = config.DefaultOperaIdentityPath
	}
	if strings.TrimSpace(c.System.Opera.Region) == "" {
		c.System.Opera.Region = opera.RegionEU
	}
	// Field default (RU): the TSPU filters on the real SurfEasy name —
	// measured 2026-09-20, a ClientHello with SNI=api2.sec-tunnel.com gets a
	// SYN blackhole, while a neutral name completes TLS (200/407). Unless the
	// operator names a different discipline in the config, default to a
	// neutral pool SNI so the control channel is reachable at all. The
	// shipping engine/daemon default stays the engine's own decision (b4x-6da).
	if strings.TrimSpace(c.System.Opera.Masquerade.SNIMode) == "" {
		c.System.Opera.Masquerade.SNIMode = "pool"
	}
	if len(c.System.Opera.Masquerade.SNIPool) == 0 {
		c.System.Opera.Masquerade.SNIPool = []string{"www.microsoft.com", "www.opera.com"}
	}
	return &c, nil
}

func controlTarget(cfg *config.Config) string {
	if t := strings.TrimSpace(cfg.System.Opera.ControlTarget); t != "" {
		return t
	}
	region := cfg.System.Opera.Region
	if region == "" {
		region = opera.RegionEU
	}
	return opera.DefaultHealthConfig(region).ControlTarget
}

// ---------------------------------------------------------------------------
// register / status
// ---------------------------------------------------------------------------

func cmdRegister(args []string, d *deps) error {
	fs := newFlagSet("register", d)
	path := fs.String("config", "", "path to config json (optional)")
	if err := fs.Parse(args); err != nil {
		return usageErr(err)
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	rt, err := d.build(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := rt.Bootstrap(ctx); err != nil {
		return err
	}
	id, err := loadIdentity(cfg.System.Opera.IdentityPath)
	if err != nil {
		return err
	}
	printJSON(d.stdout, map[string]any{
		"identity": id.Redacted(),
		"status":   rt.Status(),
	})
	return nil
}

func cmdStatus(args []string, d *deps) error {
	fs := newFlagSet("status", d)
	path := fs.String("config", "", "path to config json (optional)")
	if err := fs.Parse(args); err != nil {
		return usageErr(err)
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	rt, err := d.build(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	bootErr := rt.Bootstrap(ctx)
	slot, slotErr := slotSummary(cfg.System.Opera.IdentityPath)
	out := map[string]any{
		"slot":   slot,
		"status": rt.Status(),
	}
	if slotErr != nil {
		out["slot_error"] = slotErr.Error()
	}
	printJSON(d.stdout, out)
	// The control plane is what status reports: surface the bootstrap error
	// (if any) as the command's failure AFTER the snapshot is printed.
	return bootErr
}

// loadIdentity reads and validates the persisted slot (must exist after a
// successful Bootstrap).
func loadIdentity(path string) (*opera.Identity, error) {
	store := &opera.IdentityStore{Path: path}
	id, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("identity slot %s: %w", path, err)
	}
	return id, nil
}

// slotSummary is the offline (no-network) view of the identity slot used by
// status; it deliberately reports the mode so F1 can assert 0600.
func slotSummary(path string) (map[string]any, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return map[string]any{"path": path, "exists": false}, err
	}
	out := map[string]any{
		"path":   path,
		"exists": true,
		"mode":   fmt.Sprintf("%04o", fi.Mode().Perm()),
		"size":   fi.Size(),
	}
	id, lerr := loadIdentity(path)
	if lerr != nil {
		out["parse_error"] = lerr.Error()
		return out, nil
	}
	pins := map[string]int{}
	for host, fp := range id.Pins {
		pins[host] = len(fp)
	}
	out["format"] = id.Format
	out["created_at"] = id.CreatedAt
	out["updated_at"] = id.UpdatedAt
	out["pin_lengths"] = pins
	return out, nil
}

// ---------------------------------------------------------------------------
// probe / relay
// ---------------------------------------------------------------------------

func cmdProbe(args []string, d *deps) error {
	fs := newFlagSet("probe", d)
	path := fs.String("config", "", "path to config json (optional)")
	deep := fs.Bool("deep", false, "L2 probe: full CONNECT through the node")
	httpProbe := fs.Bool("http", false, "after CONNECT, send HEAD and await HTTP bytes (implies --deep)")
	fakeSNI := fs.String("fake-sni", "", "replace the node ClientHello SNI (empty = suppress, engine default)")
	if err := fs.Parse(args); err != nil {
		return usageErr(err)
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	rt, err := d.build(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := rt.Bootstrap(ctx); err != nil {
		return err
	}
	entry := rt.ActiveEntry()
	if entry.IP == "" {
		return errors.New("no active node (bootstrap pending)")
	}
	nd, err := rt.Client().NodeDialer(entry, *fakeSNI)
	if err != nil {
		return err
	}

	isDeep := *deep || *httpProbe
	target := controlTarget(cfg)
	level := "cheap"
	if isDeep {
		level = "deep"
	}
	start := time.Now()
	var conn net.Conn
	if isDeep {
		conn, err = nd.DialContext(ctx, "tcp", target)
	} else {
		conn, err = nd.DialNodeTLS(ctx)
	}
	rtt := time.Since(start)
	result := map[string]any{
		"level":    level,
		"node":     entry.NetAddr(),
		"tls_name": entry.TLSServerName(),
		"fake_sni": *fakeSNI,
		"rtt_ms":   rtt.Milliseconds(),
		"http":     *httpProbe,
		"target":   target,
		"ok":       err == nil,
	}
	if err != nil {
		result["class"] = failureClass(err)
		printJSON(d.stdout, result)
		return err
	}
	defer conn.Close()
	if *httpProbe {
		prefix, herr := httpHeadProbe(conn, target)
		if herr != nil {
			result["ok"] = false
			result["http_error"] = herr.Error()
			printJSON(d.stdout, result)
			return herr
		}
		result["http_response_prefix"] = prefix
	}
	printJSON(d.stdout, result)
	return nil
}

// httpHeadProbe writes a HEAD request into an established tunnel and returns
// the first response bytes (the F3 "relay alive in both directions" proof).
func httpHeadProbe(conn net.Conn, target string) (string, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: operatester/1.0\r\nConnection: close\r\n\r\n", host)
	if _, err := io.WriteString(conn, req); err != nil {
		return "", fmt.Errorf("send HEAD: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 1024)
	n, rerr := conn.Read(buf)
	if n == 0 {
		if rerr != nil {
			return "", fmt.Errorf("no HTTP bytes: %w", rerr)
		}
		return "", errors.New("no HTTP bytes")
	}
	return string(buf[:n]), nil
}

// cmdTrace fetches a URL THROUGH the active node (TLS over the CONNECT
// tunnel) and prints the response. It is the Phase C/D proof of non-RU egress:
// https://www.cloudflare.com/cdn-cgi/trace returns ip=/loc= of the SurfEasy
// exit. Verification is relaxed on purpose (diagnostic egress probe); the data
// plane's own trust is proven separately by probe/VerifyConnection.
func cmdTrace(args []string, d *deps) error {
	fs := newFlagSet("trace", d)
	path := fs.String("config", "", "path to config json (optional)")
	rawURL := fs.String("url", "https://www.cloudflare.com/cdn-cgi/trace", "URL to fetch through the tunnel")
	if err := fs.Parse(args); err != nil {
		return usageErr(err)
	}
	u, err := url.Parse(*rawURL)
	if err != nil || u.Host == "" {
		return usageErr(fmt.Errorf("bad --url %q", *rawURL))
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	rt, err := d.build(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := rt.Bootstrap(ctx); err != nil {
		return err
	}
	entry := rt.ActiveEntry()
	if entry.IP == "" {
		return errors.New("no active node (bootstrap pending)")
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	nd, err := rt.Client().NodeDialer(entry, "")
	if err != nil {
		return err
	}
	conn, err := nd.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	defer conn.Close()
	if u.Scheme == "https" {
		tconn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // diagnostic egress probe; see doc comment
		})
		if err := tconn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("tunnel TLS handshake: %w", err)
		}
		conn = tconn
	}
	pathQ := u.RequestURI()
	if pathQ == "" {
		pathQ = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: operatester/1.0\r\nConnection: close\r\n\r\n", pathQ, u.Host)
	if _, err := io.WriteString(conn, req); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	body, _ := io.ReadAll(io.LimitReader(conn, 8192))
	printJSON(d.stdout, map[string]any{
		"url":   *rawURL,
		"node":  entry.NetAddr(),
		"tls":   u.Scheme == "https",
		"bytes": len(body),
		"body":  string(body),
	})
	return nil
}

func cmdRelay(args []string, d *deps) error {
	fs := newFlagSet("relay", d)
	path := fs.String("config", "", "path to config json (optional)")
	target := fs.String("target", "", "echo target host:port (required)")
	if err := fs.Parse(args); err != nil {
		return usageErr(err)
	}
	if strings.TrimSpace(*target) == "" {
		return usageErr(errors.New("--target is required"))
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	rt, err := d.build(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := rt.Bootstrap(ctx); err != nil {
		return err
	}
	addr, err := resolveTarget(ctx, *target)
	if err != nil {
		return err
	}
	conn, err := rt.DialStream(ctx, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	go func() {
		_, _ = io.Copy(conn, d.stdin)
		// The returned conn is the full-duplex CONNECT tunnel to the proxy
		// node (TLS to the node), NOT a socket to the target: half-closing it
		// (CloseWrite/Close) sends close_notify to the NODE and tears the whole
		// tunnel down, losing the peer's tail. We therefore never half-close;
		// the reader loop below drains until the peer closes or goes idle.
	}()
	// Drain with an idle timeout: read as long as bytes keep arriving (a
	// 256KB echo takes time), stop after relayIdleWindow of silence.
	buf := make([]byte, 64*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(relayIdleWindow))
		n, rerr := conn.Read(buf)
		if n > 0 {
			if _, werr := d.stdout.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			if errors.Is(rerr, os.ErrDeadlineExceeded) || errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
}

// resolveTarget turns host:port into a netip.AddrPort (loopback-friendly:
// names resolve locally, numeric literals pass through).
func resolveTarget(ctx context.Context, target string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(target); err == nil {
		return ap, nil
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad --target %q: %w", target, err)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: no addresses", host)
	}
	addr, ok := netip.AddrFromSlice(ips[0].IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: unusable address %v", host, ips[0].IP)
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad port %q: %w", port, err)
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(p)), nil
}

// ---------------------------------------------------------------------------
// watch
// ---------------------------------------------------------------------------

func cmdWatch(args []string, d *deps) error {
	fs := newFlagSet("watch", d)
	path := fs.String("config", "", "path to config json (optional)")
	interval := fs.Duration("interval", 60*time.Second, "tick cadence (events stream to stdout)")
	if err := fs.Parse(args); err != nil {
		return usageErr(err)
	}
	if *interval <= 0 {
		return usageErr(errors.New("--interval must be positive"))
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	rt, err := d.build(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := d.signals()
	defer cancel()

	// The first tick is immediate (Run parity): bootstrap + the first probe
	// must not wait a full interval.
	rt.Kick(ctx)
	emitted := emitEvents(d.stdout, rt.Status().Events, 0)
	printStatus(d.stdout, rt.Status())

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			rt.Kick(ctx)
			st := rt.Status()
			emitted = emitEvents(d.stdout, st.Events, emitted)
			printStatus(d.stdout, st)
		}
	}
}

// emitEvents prints the event-ring entries newer than already-emitted and
// returns the new watermark. The ring trims at its cap; a shorter snapshot
// than the watermark means a wrap, so the tail is reprinted.
func emitEvents(w io.Writer, events []operaservice.Event, emitted int) int {
	if emitted > len(events) {
		emitted = 0
	}
	for _, ev := range events[emitted:] {
		printJSON(w, map[string]any{
			"event":  ev.Name,
			"detail": ev.Detail,
			"at":     ev.At,
		})
	}
	return len(events)
}

func printStatus(w io.Writer, st operaservice.Status) {
	printJSON(w, map[string]any{"status": st})
}

// ---------------------------------------------------------------------------
// region
// ---------------------------------------------------------------------------

func cmdRegion(args []string, d *deps) error {
	// The region is positional (prompt §4: `operatester region EU|AS|AM`), so
	// the flag package's stop-at-first-positional behavior is avoided by
	// extracting --config by hand — both `region AS --config c` and
	// `region --config c AS` work.
	var (
		configPath string
		positional []string
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config":
			if i+1 >= len(args) {
				return usageErr(errors.New("--config requires a value"))
			}
			configPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--config="):
			configPath = strings.TrimPrefix(a, "--config=")
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) != 1 {
		return usageErr(errors.New("exactly one region (EU|AS|AM) is required"))
	}
	region, err := opera.NormalizeRegion(positional[0])
	if err != nil {
		return usageErr(err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	rt, err := d.build(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := rt.Bootstrap(ctx); err != nil {
		return err
	}
	before, _ := slotCreatedAt(cfg.System.Opera.IdentityPath)
	from := rt.Status().DesiredRegion
	if err := rt.SetRegion(region); err != nil {
		return err
	}
	st := rt.Status()
	after, _ := slotCreatedAt(cfg.System.Opera.IdentityPath)
	printJSON(d.stdout, map[string]any{
		"from":               from,
		"to":                 st.DesiredRegion,
		"region":             st.Region,
		"active_node":        st.ActiveNode,
		"cached_nodes":       st.CachedNodes,
		"nodes_source":       st.NodesSource,
		"identity_created":   before,
		"identity_created2":  after,
		"identity_unchanged": !before.IsZero() && before.Equal(after),
	})
	return nil
}

func slotCreatedAt(path string) (time.Time, error) {
	id, err := loadIdentity(path)
	if err != nil {
		return time.Time{}, err
	}
	return id.CreatedAt, nil
}

// ---------------------------------------------------------------------------
// udp-probe
// ---------------------------------------------------------------------------

func cmdUDPProbe(args []string, d *deps) error {
	fs := newFlagSet("udp-probe", d)
	path := fs.String("config", "", "path to config json (optional)")
	if err := fs.Parse(args); err != nil {
		return usageErr(err)
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return err
	}
	rt, err := d.build(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	target := netip.MustParseAddrPort("1.1.1.1:443")
	conn, uerr := rt.DialUDP(ctx, target)
	if conn != nil {
		_ = conn.Close()
	}
	if uerr == nil {
		printJSON(d.stdout, map[string]any{"udp_supported": rt.SupportsUDP(), "refused": false})
		return errors.New("unexpected UDP success (TCP-only carrier must fail closed)")
	}
	result := map[string]any{
		"udp_supported": rt.SupportsUDP(),
		"refused":       true,
		"fail_closed":   errors.Is(uerr, reserve.ErrCarrierNoUDP),
		"class":         failureClass(uerr),
		"error":         uerr.Error(),
	}
	printJSON(d.stdout, result)
	// The refusal IS the designed outcome: the command succeeds when the
	// carrier fails closed (prompt §6 F3: PASS exactly on the refusal).
	return nil
}

// failureClass renders the structured opera class when present, else the
// reserve/plain error text (keeps the CLI honest without parsing statuses).
func failureClass(err error) string {
	var f *opera.Failure
	if errors.As(err, &f) {
		return string(f.Class)
	}
	if errors.Is(err, reserve.ErrCarrierNoUDP) {
		return "carrier-no-udp"
	}
	return "plain-error"
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

var commands = map[string]func([]string, *deps) error{
	"register":  cmdRegister,
	"status":    cmdStatus,
	"probe":     cmdProbe,
	"trace":     cmdTrace,
	"relay":     cmdRelay,
	"watch":     cmdWatch,
	"region":    cmdRegion,
	"udp-probe": cmdUDPProbe,
}

func run(args []string, d *deps) int {
	if len(args) == 0 {
		fmt.Fprint(d.stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(d.stdout, usage)
		return exitOK
	}
	fn, ok := commands[cmd]
	if !ok {
		fmt.Fprintf(d.stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
	if err := fn(rest, d); err != nil {
		fmt.Fprintf(d.stderr, "operatester %s: %v\n", cmd, err)
		if errors.Is(err, errUsage) {
			return exitUsage
		}
		return exitFail
	}
	return exitOK
}

func main() {
	os.Exit(run(os.Args[1:], defaultDeps()))
}

const usage = `operatester — isolated field CLI for the Opera/SurfEasy reserve transport (E-OPERA)

It runs as a separate userspace process and never touches the live b4 binary,
config, NFQUEUE rules or routes.

Usage:
  operatester register  [--config c.json]
        EnsureSession (adopt the persisted device or register one fresh) +
        discover, then print the Redacted identity and the health status.
  operatester status    [--config c.json]
        Slot summary (existence, mode, format, created_at, pin lengths) plus
        HealthStatus (running/listening/region/active node/restarts). Adopts
        the slot — it never re-registers an existing device.
  operatester probe     [--deep] [--fake-sni d] [--http] [--config c.json]
        Probe the active node. Default = L1 TCP+TLS handshake. --deep = full
        CONNECT to the control target. --http implies --deep and additionally
        sends a HEAD through the tunnel awaiting HTTP response bytes.
        --fake-sni replaces the ClientHello SNI (empty suppresses it).
  operatester trace     [--url https://www.cloudflare.com/cdn-cgi/trace] [--config c.json]
        Fetch a URL through the active node (TLS over CONNECT) and print the
        body — the loc=/ip= proof of non-RU egress for Fases C/D.
  operatester relay     --target host:port [--config c.json]
        Raw echo channel: stdin -> tunnel -> stdout (checksums). Drains until
        the peer closes or 8s idle; never half-closes the CONNECT tunnel.
  operatester watch     [--interval 60s] [--config c.json]
        Tick loop until SIGINT; lifecycle events and status stream to stdout.
  operatester region    EU|AS|AM [--config c.json]
        SetRegion + immediate discover keeping the device identity; prints the
        new active node.
  operatester udp-probe [--config c.json]
        Expected FAIL: prove the TCP-only carrier refuses UDP fail-closed
        (class carrier-no-udp). The command reports success when it refuses.

Config is optional; omitted sections use config.DefaultConfig System.Opera
(region EU, slot /opt/etc/b4/opera/identity.json). Network operations are
bounded by a 30s context. Exit codes: 0 ok, 1 fail, 2 usage.
`
