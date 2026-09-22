// src/main.go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/daniellavrushin/b4/adblock"
	"github.com/daniellavrushin/b4/ai"
	"github.com/daniellavrushin/b4/awgwarpservice"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/discovery"
	"github.com/daniellavrushin/b4/fxvpservice"
	"github.com/daniellavrushin/b4/geodat"
	b4http "github.com/daniellavrushin/b4/http"
	"github.com/daniellavrushin/b4/http/handler"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/monitoring"
	"github.com/daniellavrushin/b4/mtproto"
	"github.com/daniellavrushin/b4/nfq"
	"github.com/daniellavrushin/b4/nonruservice"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/operaservice"
	"github.com/daniellavrushin/b4/protonservice"
	"github.com/daniellavrushin/b4/quic"
	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/serviceprofile"
	"github.com/daniellavrushin/b4/socks5"
	"github.com/daniellavrushin/b4/tables"
	"github.com/daniellavrushin/b4/torservice"
	"github.com/daniellavrushin/b4/tproxy"
	fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
	b4tun "github.com/daniellavrushin/b4/tun"
	"github.com/daniellavrushin/b4/validation"
	"github.com/daniellavrushin/b4/vlessservice"
	"github.com/daniellavrushin/b4/warp"
	"github.com/daniellavrushin/b4/warpchainservice"
	"github.com/daniellavrushin/b4/warpservice"
	"github.com/daniellavrushin/b4/watchdog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	cfg             = config.NewConfig()
	cliOverrides    config.CLIOverrides
	verboseFlag     string
	showVersion     bool
	clearTables     bool
	Version         = "dev"
	Commit          = "none"
	Date            = "unknown"
	currentLogLevel = log.LevelInfo
)

// kindAlias re-exposes a reserve.Carrier under a second kind. The MASQUE
// carrier uses it to answer as kind=h3: the warpservice ladder is H3-first
// (QUIC/H3, H2 fallback), so tunnel=h3 and tunnel=masque ride the SAME carrier.
// This turns the previously-reserved "h3" registry kind into a real, routable
// alias instead of a dead placeholder.
type kindAlias struct {
	reserve.Carrier
	kind reserve.Kind
}

func (a kindAlias) Kind() reserve.Kind { return a.kind }

var rootCmd = &cobra.Command{
	Use:           "b4",
	Short:         "B4 network packet processor",
	Long:          `B4 is a netfilter queue based packet processor for DPI circumvention`,
	RunE:          runB4,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	// Bind all configuration flags
	cfg.BindFlags(rootCmd, &cliOverrides)

	// Add verbosity flags separately since they need special handling
	rootCmd.Flags().StringVar(&verboseFlag, "verbose", "info", "Set verbosity level (debug, trace, info, silent), default: info")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version and exit")
	rootCmd.Flags().BoolVar(&clearTables, "clear-tables", false, "Perform only iptables/nftables cleanup and exit")

	rootCmd.AddCommand(iv18Cmd)
}

// iv18Cmd runs the FB-28 IV-18 continuous-monitoring conformance suite
// (registry + executed coverage) without starting the daemon. It exits
// non-zero while coverage is incomplete (fail-closed), which makes it
// suitable for CI promotion gates.
var iv18Cmd = &cobra.Command{
	Use:   "iv18",
	Short: "Run the IV-18 continuous monitoring conformance suite (FB-28)",
	RunE: func(cmd *cobra.Command, args []string) error {
		result := validation.RunIV18Suite()
		iv18JSON, _ := cmd.Flags().GetBool("json")
		if iv18JSON {
			out, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(out))
		} else {
			fmt.Printf("IV-18 suite: registered=%d covered=%d missing=%d production_ready=%t verdict=%s\n",
				result.Registered, result.Covered, len(result.MissingCoverage), result.ProductionReady, result.Verdict)
			for _, id := range result.MissingCoverage {
				fmt.Printf("  missing coverage: %s\n", id)
			}
			for _, h := range result.LegacyMutatingHits {
				fmt.Printf("  legacy mutating path reachable: %s:%d\n", h.File, h.Line)
			}
		}
		if result.Verdict != validation.Pass {
			return fmt.Errorf("IV-18 suite not passing: verdict %s (missing coverage: %d, production_ready: %t)", result.Verdict, len(result.MissingCoverage), result.ProductionReady)
		}
		return nil
	},
}

func init() {
	iv18Cmd.Flags().Bool("json", false, "Emit the full suite result as JSON")
}

// warpCmd exposes identity lifecycle operations for the built-in WARP/MASQUE
// transport (warpservice). Enrollment accepts the Cloudflare ToS on behalf
// of the operator — field session phase B requires explicit owner consent
// recorded in the session report before this command runs.
var warpCmd = &cobra.Command{
	Use:   "warp",
	Short: "WARP/MASQUE transport operations (identity enroll/status)",
}

var warpEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Run one identity reconciliation pass against Cloudflare (idempotent)",
	Long: `Provision or revalidate the WARP/MASQUE device identity stored at
system.warp.identity_path. A valid existing identity produces ZERO
registration requests (idempotent); refused/throttled API verdicts are
reported structurally instead of retried. The first provisioning registers a
real device with Cloudflare and accepts the WARP Terms of Service on behalf
of the operator.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := warpConfigPath(cmd)
		if err != nil {
			return err
		}
		c := config.NewConfig()
		if _, err := c.LoadWithMigration(path); err != nil {
			return err
		}
		rt, err := warpservice.Build(&c, nil)
		if err != nil {
			return err
		}
		res, enrollErr := rt.EnrollOnce(cmd.Context())
		out, _ := json.MarshalIndent(warpservice.EnrollSummary(res, c.System.Warp.IdentityPath), "", "  ")
		fmt.Println(string(out))
		return enrollErr
	},
}

var warpStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Print the redacted identity summary (offline, no network)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := warpConfigPath(cmd)
		if err != nil {
			return err
		}
		c := config.NewConfig()
		if _, err := c.LoadWithMigration(path); err != nil {
			return err
		}
		out, _ := json.MarshalIndent(warpservice.OfflineSummary(c.System.Warp.IdentityPath), "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func warpConfigPath(cmd *cobra.Command) (string, error) {
	path, _ := cmd.Flags().GetString("config")
	if path == "" {
		return "", fmt.Errorf("--config is required (path to b4.json)")
	}
	return path, nil
}

// logWarpEvent renders one supervisor event for the structured router log.
// SupervisorEvent payloads are redacted-safe by engine contract; only
// non-zero fields are printed to keep lines greppable.
func logWarpEvent(ev warpservice.Event) {
	line := fmt.Sprintf("[warp] event=%s attempt=%d", ev.Name, ev.Attempt)
	if ev.FailureClass != "" {
		line += fmt.Sprintf(" class=%s", ev.FailureClass)
	}
	if ev.Status != 0 {
		line += fmt.Sprintf(" status=%d", ev.Status)
	}
	if ev.Colo != "" {
		line += fmt.Sprintf(" colo=%s", ev.Colo)
	}
	if ev.BackoffMS != 0 {
		line += fmt.Sprintf(" backoff_ms=%d", ev.BackoffMS)
	}
	if ev.DurationMS != 0 {
		line += fmt.Sprintf(" duration_ms=%d", ev.DurationMS)
	}
	if ev.Detail != "" {
		line += fmt.Sprintf(" detail=%q", ev.Detail)
	}
	log.Infof("%s", line)
}

var warpRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the WARP supervisor until connected and optionally test trace",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := warpConfigPath(cmd)
		if err != nil {
			return err
		}
		wait, _ := cmd.Flags().GetDuration("wait")
		trace, _ := cmd.Flags().GetBool("trace")
		urlFlag, _ := cmd.Flags().GetString("url")
		repeat, _ := cmd.Flags().GetInt("repeat")

		c := config.NewConfig()
		if _, err := c.LoadWithMigration(path); err != nil {
			return err
		}

		type eventRecord struct {
			Event  string `json:"event"`
			Class  string `json:"class,omitempty"`
			Status int    `json:"status,omitempty"`
			Colo   string `json:"colo,omitempty"`
			Detail string `json:"detail,omitempty"`
		}
		var mu sync.Mutex
		var events []eventRecord
		sink := func(ev warpservice.Event) {
			mu.Lock()
			rec := eventRecord{
				Event:  ev.Name,
				Class:  ev.FailureClass,
				Status: ev.Status,
				Colo:   ev.Colo,
				Detail: ev.Detail,
			}
			events = append(events, rec)
			mu.Unlock()
			fmt.Printf("{\"event\":%q,\"class\":%q,\"status\":%d,\"colo\":%q,\"detail\":%q}\n",
				ev.Name, ev.FailureClass, ev.Status, ev.Colo, ev.Detail)
		}

		rt, err := warpservice.Build(&c, sink)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()
		defer rt.Stop()
		if err := rt.Start(ctx); err != nil {
			return err
		}

		reached := false
		deadline := time.Now().Add(wait)
		for time.Now().Before(deadline) {
			st := rt.Status().Status
			if st.State == "connected" || st.State == "stopped" {
				reached = st.State == "connected"
				break
			}
			time.Sleep(250 * time.Millisecond)
		}

		traceBody := ""
		if reached && trace {
			if carrier, closer, aerr := rt.AttachNetstack(); aerr != nil {
				traceBody = "attach failed: " + aerr.Error()
			} else {
				defer closer()
				for i := 1; i <= repeat; i++ {
					tctx, tcancel := context.WithTimeout(ctx, 20*time.Second)
					req, _ := http.NewRequestWithContext(tctx, http.MethodGet, urlFlag, nil)
					resp, rerr := carrier.HTTPClient(15 * time.Second).Do(req)
					if rerr != nil {
						traceBody = fmt.Sprintf("fetch %d/%d failed: %v", i, repeat, rerr.Error())
						tcancel()
						break
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
					resp.Body.Close()
					tcancel()
					traceBody = string(body)
					fmt.Printf("--- fetch %d/%d %s -> status %d ---\n", i, repeat, urlFlag, resp.StatusCode)
				}
			}
			fmt.Println("--- cdn-cgi/trace through tunnel ---")
			fmt.Println(traceBody)
			fmt.Println("------------------------------------")
		}

		snap := rt.Status()
		mu.Lock()
		evSnap := append([]eventRecord(nil), events...)
		mu.Unlock()
		out, _ := json.MarshalIndent(map[string]any{
			"reached_connected": reached,
			"state":             string(snap.Status.State),
			"colo":              snap.Status.LastColo,
			"attempt":           snap.Status.Attempt,
			"last_failure":      snap.Status.LastFailureClass,
			"events":            evSnap,
		}, "", "  ")
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	for _, sub := range []*cobra.Command{warpEnrollCmd, warpStatusCmd} {
		sub.Flags().String("config", "", "Path to b4.json (required)")
		warpCmd.AddCommand(sub)
	}
	warpRunCmd.Flags().String("config", "", "Path to b4.json (required)")
	warpRunCmd.Flags().Duration("wait", 45*time.Second, "Max wait for connected state")
	warpRunCmd.Flags().Bool("trace", false, "After connect: mount netstack carrier and GET cdn-cgi/trace through tunnel")
	warpRunCmd.Flags().String("url", "https://1.1.1.1/cdn-cgi/trace", "Trace URL")
	warpRunCmd.Flags().Int("repeat", 1, "Sequential fetch count")
	warpCmd.AddCommand(warpRunCmd)

	rootCmd.AddCommand(warpCmd)
}

// @title B4 API
// @version 1.0
// @description B4 network packet processor REST API
// @BasePath /api
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Enter "Bearer {token}" to authorize
func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runB4(cmd *cobra.Command, args []string) error {
	handler.Version = Version
	handler.Commit = Commit
	handler.Date = Date

	if showVersion {
		fmt.Printf("B4 version: %s (%s) %s\n", Version, Commit, Date)
		return nil
	}

	releaseLock, err := ensureSingleInstance()
	if err != nil {
		return err
	}
	if releaseLock != nil {
		defer releaseLock()
	}

	initTimezone()

	needsSave, _ := cfg.LoadWithMigration(cfg.ConfigPath)
	if needsSave {
		cfg.SaveToFile(cfg.ConfigPath)
	}
	cfg.ApplyCLIOverrides(cmd, &cliOverrides)
	cfg.EnsureRuntimeGeneration()

	if cfg.System.Timezone != "" {
		config.ApplyTimezone(cfg.System.Timezone)
	}

	if limit, err := config.ApplyMemoryLimit(cfg.System.MemoryLimit); err != nil {
		fmt.Fprintf(os.Stderr, "[INIT] invalid system.memory_limit %q: %v\n", cfg.System.MemoryLimit, err)
	} else if limit > 0 {
		fmt.Fprintf(os.Stderr, "[INIT] Memory limit set to %d MB\n", limit/(1024*1024))
	}

	if cmd.Flags().Changed("verbose") {
		cfg.ApplyLogLevel(verboseFlag)
	}

	var cfgPtr atomic.Pointer[config.Config]
	cfgPtr.Store(&cfg)

	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	aiManager := ai.NewManager(cfg.System.AI, cfg.ConfigPath)
	handler.SetAIManager(aiManager)

	discoveryRT := discovery.NewRuntime()

	tproxyResolver := tproxy.NewLearnedIPResolver(nil)
	tproxyMgr := tproxy.NewManager(tproxyResolver)

	mtprotoBridge := mtproto.NewTransparentBridge(&cfg)
	tproxyMgr.SetMTProtoBridge(mtprotoBridge)
	handler.SetMTProtoBridge(mtprotoBridge)
	go func() {
		_ = mtproto.RefreshDCs(cfg.System.MTProto.DCFallbackEnabled, cfg.System.MTProto.DCFallbackURL)
	}()
	startCFRefresh := func(c *config.Config) {
		if c.System.MTProto.CFProxyEnabled {
			mtproto.StartCFProxyRefresh(appCtx, c.System.MTProto.CFProxyURL)
		}
	}
	startCFRefresh(&cfg)
	handler.SetMTProtoCFRefreshFunc(startCFRefresh)

	refreshTables := func() error {
		c := cfgPtr.Load()
		if c.System.Tables.SkipSetup {
			return nil
		}
		if c.Queue.Mode == "tun" {
			tproxyMgr.SyncConfig(c)
			tables.RoutingSyncConfig(c)
			return nil
		}
		if discoveryRT.IsActive() {
			log.Warnf("Tables refresh requested while discovery is active, waiting for discovery to finish...")
			deadline := time.After(5 * time.Minute)
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for discoveryRT.IsActive() {
				select {
				case <-deadline:
					return fmt.Errorf("tables refresh timed out: discovery did not finish within 5 minutes")
				case <-ticker.C:
				}
			}
		}
		if err := tables.ClearRules(c); err != nil {
			return err
		}
		if err := tables.AddRules(c); err != nil {
			return err
		}
		tproxyMgr.SyncConfig(c)
		tables.RoutingSyncConfig(c)
		handler.GetMetricsCollector().TablesStatus = tables.DetectBackend(c)
		return nil
	}
	handler.SetTablesRefreshFunc(refreshTables)
	handler.SetRoutingSyncFunc(func(c *config.Config) {
		tproxyMgr.SyncConfig(c)
		tables.RoutingSyncConfig(c)
	})
	handler.SetDiscoveryRuntime(discoveryRT)
	nfq.RoutingHandleDNSFunc = tables.RoutingHandleDNS
	nfq.RoutingLearnIPFunc = tables.RoutingLearnIP

	if err := initLogging(&cfg); err != nil {
		return fmt.Errorf("logging initialization failed: %w", err)
	}

	initAdaptiveDNS(&cfg)

	if clearTables {
		log.Infof("Clearing iptables rules as requested (--clear-iptables)")
		clearErr := tables.ClearRules(&cfg)
		b4tun.RestoreFromState()
		tables.RoutingClearAll()
		b4tun.ClearStaleArtifacts(&cfg)
		if clearErr != nil {
			return fmt.Errorf("failed to clear iptables/nftables rules: %w", clearErr)
		}
		log.Infof("IPTables rules cleared successfully")
		return nil
	}

	log.Infof("Starting B4 packet processor")

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return log.Errorf("invalid configuration: %w", err)
	}

	printConfigDefaults(cmd)

	// Initialize metrics collector early
	metrics := handler.GetMetricsCollector()
	metrics.RecordEvent("info", "B4 starting up")

	if cfg.System.WebServer.Port > 0 {
		metrics.RecordEvent("info", fmt.Sprintf("Web server started on port %d", cfg.System.WebServer.Port))
	}

	// Load domains
	_, totalDomains, totalIps, err := cfg.LoadTargets()
	if err != nil {
		metrics.RecordEvent("error", fmt.Sprintf("Failed to load domains: %v", err))
		return fmt.Errorf("failed to load domains: %w", err)
	}

	log.Infof("Loaded targets: %d domains, %d IPs across %d sets", totalDomains, totalIps, len(cfg.Sets))
	b4tun.RestoreFromState()
	tables.RoutingClearAll()

	isTUN := cfg.Queue.Mode == "tun"

	pool := nfq.NewPool(&cfg)

	// BLK-7 wiring: the IP-learn sublayer talks to the kernel through the
	// tables backend and reuses the production full-tables-refresh mechanism
	// for enable transitions (PPE coordination). Bound AFTER pool creation so
	// a boot-time-enabled ip_learn cannot trigger a refresh before the
	// NFQUEUE listeners are ready; boot-time rule order is guaranteed by the
	// AddRules tail integration instead.
	adblock.SetLearnApplier(tables.NewAdBlockLearnApplier(cfgPtr.Load))
	adblock.SetRefreshTablesFunc(func() {
		if err := refreshTables(); err != nil {
			log.Warnf("adblock: ip_learn enable refresh failed (SNI layer unaffected): %v", err)
		}
	})

	var tunEngine *b4tun.Engine
	var tablesMonitor *tables.Monitor

	if isTUN {
		log.Infof("Starting TUN engine (device: %s, out: %s, threads: %d)",
			cfg.Queue.TUN.DeviceName, cfg.Queue.TUN.OutInterface, cfg.Queue.Threads)

		if !cfg.System.Tables.SkipSetup {
			log.Tracef("Clearing any pre-existing NFQUEUE/tables rules before TUN setup")
			if err := tables.ClearRules(&cfg); err != nil {
				log.Warnf("TUN: failed to clear pre-existing tables rules (continuing): %v", err)
			}
			if err := tables.ApplyMasqueradeOnly(&cfg); err != nil {
				metrics.RecordEvent("error", fmt.Sprintf("Failed to apply masquerade: %v", err))
				return fmt.Errorf("failed to apply masquerade: %w", err)
			}
			tables.ApplyConntrackSysctls()
			if err := tables.ApplyMSSClampOnly(&cfg); err != nil {
				log.Errorf("Failed to apply MSS clamp in TUN mode: %v", err)
			}
		} else {
			log.Infof("Skipping masquerade and conntrack sysctls (--skip-tables); the TUN engine also skips its own firewall/sysctl rules and only sets up routing")
		}

		tunEngine = b4tun.NewEngine(&cfg, pool)
		if err := tunEngine.Start(); err != nil {
			if !cfg.System.Tables.SkipSetup {
				tables.ClearMasqueradeOnly(&cfg)
				tables.ClearMSSClampOnly(&cfg)
				tables.RevertConntrackSysctls()
			}
			pool.Stop()
			metrics.RecordEvent("error", fmt.Sprintf("TUN engine start failed: %v", err))
			metrics.NFQueueStatus = "error"
			return fmt.Errorf("TUN engine start failed: %w", err)
		}

		if cfg.System.Tables.SkipSetup {
			metrics.TablesStatus = "tun (skip-tables)"
		} else {
			metrics.TablesStatus = "tun"
		}
		metrics.NFQueueStatus = "active (tun)"
		metrics.RecordEvent("info", fmt.Sprintf("TUN engine started with %d threads", cfg.Queue.Threads))

		if !cfg.System.Tables.SkipSetup {
			tproxyMgr.SyncConfig(&cfg)
			tables.RoutingSyncConfig(&cfg)
		}
	} else {
		// Reconcile stale B4-owned rules before binding queues. queue-bypass keeps
		// any surviving vendor rule fail-open; no new rule is installed until all
		// listeners are bound.
		if !cfg.System.Tables.SkipSetup {
			log.Tracef("Reconciling pre-existing B4 firewall rules")
			tables.ClearRules(&cfg)
			b4tun.ClearStaleArtifacts(&cfg)
		}

		// Start listeners before installing queue targets. This removes the old
		// unbound-startup window where live rules could point at absent queues.
		log.Infof("Starting netfilter queue pool (queue: %d, threads: %d)", cfg.Queue.StartNum, cfg.Queue.Threads)
		if err := pool.Start(); err != nil {
			metrics.RecordEvent("error", fmt.Sprintf("NFQueue start failed: %v", err))
			metrics.NFQueueStatus = "error"
			return fmt.Errorf("netfilter queue start failed: %w", err)
		}

		if !cfg.System.Tables.SkipSetup {
			log.Tracef("Installing B4 rules after NFQUEUE listener readiness")
			if err := tables.AddRules(&cfg); err != nil {
				pool.Stop()
				metrics.RecordEvent("error", fmt.Sprintf("Failed to add tables rules: %v", err))
				return fmt.Errorf("failed to add tables rules: %w", err)
			}
			metrics.TablesStatus = tables.DetectBackend(&cfg)
			metrics.RecordEvent("info", "Tables rules configured after queue readiness")
			tproxyMgr.SyncConfig(&cfg)
			tables.RoutingSyncConfig(&cfg)
		} else {
			log.Infof("Skipping tables setup (--skip-tables)")
			metrics.TablesStatus = "skipped"
			log.Tracef("Skipping routing sync due to --skip-tables")
		}

		metrics.RecordEvent("info", fmt.Sprintf("NFQueue started with %d threads", cfg.Queue.Threads))
		metrics.NFQueueStatus = "active"

		// L5 field test (Часть 2.7): apply the PPE handshake window
		// directly (no policy change, no config persist).
		maybeStartL5PPE(&cfgPtr, appCtx)

		// Part 3 П.4: proactive GGC shard discovery — feed current
		// googlevideo shard IPs into the scoped hint store so a seek to
		// a fresh CDN IP classifies before any QUIC/DNS observation.
		nfq.StartGGCShardDiscovery(appCtx, &cfgPtr, pool)

		// Part 3 P.5: automatic QUIC liveness fact via Version-Negotiation
		// probes toward current googlevideo shard endpoints.
		nfq.StartVNBProbe(appCtx, &cfgPtr, pool)

		// Part 3 follow-up: hourly external-churn gauge over masked-QUIC
		// destination diversity (see nfq/storm.go).
		nfq.StartStormGauge(appCtx, pool)

		// Start tables monitor to handle rule restoration if system wipes them
		if !cfg.System.Tables.SkipSetup && cfg.System.Tables.MonitorInterval > 0 {
			tablesMonitor = tables.NewMonitor(&cfgPtr)
			tablesMonitor.Start()
		}
	}

	shutdownHandled := false
	defer func() {
		if shutdownHandled {
			return
		}
		c := cfgPtr.Load()
		if tunEngine != nil {
			tunEngine.Stop()
			if !c.System.Tables.SkipSetup {
				tables.ClearMasqueradeOnly(c)
				tables.ClearMSSClampOnly(c)
				tables.RevertConntrackSysctls()
			}
		} else if !c.System.Tables.SkipSetup {
			tables.ClearRules(c)
		}
		tables.RoutingClearAll()
	}()

	tproxyResolver.Set(pool.GetMatcher())

	handler.SetTUNEngine(tunEngine)

	if tunEngine != nil {
		tunEngine.SetRouteDecisions(pool.GetRouteDecisions())
	}

	// Start internal web server if configured
	httpServer, apiHandler, err := b4http.StartServer(&cfgPtr, pool)
	if err != nil {
		metrics.RecordEvent("error", fmt.Sprintf("Failed to start web server: %v", err))
		return log.Errorf("failed to start web server: %w", err)
	}

	// Start SOCKS5 server if configured.
	socks5Server := socks5.NewServer(&cfg)
	socks5Server.SetIPBlockCache(pool.GetIPBlockCache())
	socks5Server.SetRouteDecisions(pool.GetRouteDecisions())
	if err := socks5Server.Start(); err != nil {
		metrics.RecordEvent("error", fmt.Sprintf("Failed to start SOCKS5 server: %v", err))
		log.Errorf("SOCKS5 server did not start: %v (b4 continues without it; fix in Settings or config)", err)
	}
	handler.SetSocks5Server(socks5Server)

	// Start MTProto server if configured.
	mtprotoServer := mtproto.NewServer(&cfg)
	if err := mtprotoServer.Start(); err != nil {
		metrics.RecordEvent("error", fmt.Sprintf("Failed to start MTProto server: %v", err))
		log.Errorf("MTProto server did not start: %v (b4 continues without it; fix in Settings or config)", err)
	}
	handler.SetMTProtoServer(mtprotoServer)

	wd := watchdog.New(&cfgPtr, discoveryRT)
	wd.Start()
	handler.SetWatchdog(wd)

	// MON addendum v1.0 §59: legacy_watchdog_direct_apply=true re-enables the
	// removed legacy direct-apply semantics and MAY exist only in migration
	// test builds or explicit unsafe development mode. It emits a startup
	// warning and increments the zero-tolerance hard-gate counter
	// monitor_legacy_watchdog_direct_apply_total, which blocks production
	// readiness (FT-MON-A); the option is never exposed in the beginner UI.
	if cfgPtr.Load().System.Checker.Watchdog.LegacyWatchdogDirectApply {
		log.Warnf("[WATCHDOG] legacy_watchdog_direct_apply=true: legacy direct apply is UNSAFE (MON §59); allowed only in migration test builds / explicit unsafe development mode; production readiness is blocked (monitor_legacy_watchdog_direct_apply_total > 0)")
		observability.Default().Metrics.Inc(observability.MetricMONLegacyWatchdogDirectApply, nil, 1)
	}

	// MON addendum v1.0 §57.1: legacy_watchdog_api=false means the event-driven
	// cutover is active: every legacy mutating /api/watchdog/* endpoint answers
	// 410 Gone and GET /api/watchdog/status serves the Monitoring projection
	// (read-only alias). Warn on startup so operators relying on the legacy
	// surface notice the behaviour change immediately.
	if !cfgPtr.Load().System.Checker.Watchdog.LegacyWatchdogAPI {
		log.Warnf("[WATCHDOG] legacy_watchdog_api=false: cutover active (MON §57.1) — legacy mutating /api/watchdog/* endpoints return 410 Gone; GET /api/watchdog/status serves the Monitoring projection")
	}

	// MON -> ABD -> DDI production runtime (IV-18-MON-09 wiring): consumes
	// observations from the PPE capture-visibility gate and drives the
	// bounded diagnostic scheduler. Read-only by design — it never mutates
	// configuration.
	monitoringRT := monitoring.NewRuntime(monitoring.DefaultConfig())
	monitoringRT.Start()
	handler.SetMonitoringRuntime(monitoringRT)
	monitoringRT.SetConfigProvider(func() *config.Config { return cfgPtr.Load() })

	// WARP base-transport lifecycle controller (FB-02 WARP section): owns the
	// built-in WARP/MASQUE enrollment -> TUN -> routing lifecycle and the ten
	// §72 base-transport hard-gate producers. Mirrors the monitoring runtime:
	// Start/Stop bound its controller loop; the future WARP control plane
	// feeds it via Submit (bounded, non-blocking).
	warpRT := warp.NewRuntime(warp.DefaultConfig())
	warpRT.Start()
	handler.SetWarpRuntime(warpRT)

	// WARP/MASQUE data-plane engine (design v2; E0-E8 engine in
	// src/transport/warp, warpservice assembly). Zero goroutines unless
	// system.warp.enabled=true — the default config keeps the section off,
	// so daemon behavior matches the p35b baseline unless explicitly
	// switched (field session phases B/C). Supervisor events go to the
	// structured log with redacted-safe payload fields only.
	var warpEngine *warpservice.Runtime
	if cfgPtr.Load().System.Warp.Enabled {
		rt, err := warpservice.Build(cfgPtr.Load(), logWarpEvent)
		if err != nil {
			log.Errorf("[warp] engine disabled this run: %v", err)
		} else if err := rt.Start(appCtx); err != nil {
			log.Errorf("[warp] engine start failed: %v", err)
		} else {
			warpEngine = rt
			st := rt.Status().Status
			log.Infof("[warp] engine started state=%s attempt=%d colo=%s", st.State, st.Attempt, st.LastColo)
		}
	}
	handler.SetWarpServiceRuntime(warpEngine) // nil-safe: the handler answers the disabled shape
	// Tunnels pane seam (TUNNELS_PANEL_DESIGN): the MASQUE-WARP engine joins
	// the reserve registry (kind=masque, netstack-carrier adapter, IPv4/TCP
	// only) so routing.mode=tunnel sets can dial through it.
	var warpMasqueCarrier *warpservice.MasqueCarrier
	if warpEngine != nil {
		warpMasqueCarrier = warpservice.NewMasqueCarrier(warpEngine)
		reserve.Register(warpMasqueCarrier)
		log.Infof("[warp] carrier registered kind=masque priority=%d udp=false (netstack v1: IPv4/TCP only)",
			reserve.PriorityMasque)
		// The warpservice ladder is H3-FIRST, so the same carrier also answers
		// as kind=h3: a set routed via routing.tunnel=h3 rides this carrier and
		// negotiates H3 when the edge allows (H2 fallback otherwise). This makes
		// the reserved "h3" kind genuinely routable instead of a dead entry.
		reserve.Register(kindAlias{Carrier: warpMasqueCarrier, kind: reserve.KindH3})
		log.Infof("[warp] carrier registered kind=h3 priority=%d (alias of masque, H3-first ladder)",
			reserve.PriorityH3)
	}

	// AWG-WARP transport (tunnels panel stage 2; engine in transport/wg,
	// assembly in awgwarpservice, config system.warp.awg). Zero wire calls
	// unless system.warp.awg.enabled=true — the identity slot provisions
	// on first use, one registration per boot. The Runtime IS the carrier
	// (kind=warp, UDP full-scope through the session netstack) in NETSTACK
	// mode; in KERNEL mode (/dev/net/tun + the PBR field layer — design §7
	// "kernel-TUN PBR — основной путь роутера") there is no userspace
	// carrier: the session hooks own the kernel wiring and the reserve tree
	// never sees a dead dialer (honest absence, not a fail-closed facade).
	var awgWarpEngine *awgwarpservice.Runtime
	if cfgPtr.Load().System.Warp.AWG.Enabled {
		// Event sink (field observability, bd b4x-wh6/pt.2 + FIELD2 Фаза D/E):
		// without it the service's lifecycle events (session_started/lost,
		// seek_adopted, trace) never reach the router log.
		rt, err := awgwarpservice.Build(cfgPtr.Load(), awgwarpservice.Options{
			OnEvent: func(ev awgwarpservice.Event) {
				log.Infof("[awgwarp] %s %s", ev.Name, ev.Detail)
			},
		})
		if err != nil {
			log.Errorf("[awgwarp] engine disabled this run: %v", err)
		} else if err := rt.Start(appCtx); err != nil {
			log.Errorf("[awgwarp] engine start failed: %v", err)
		} else {
			awgWarpEngine = rt
			st := rt.Status()
			log.Infof("[awgwarp] engine started state=%s endpoint=%s mode=%s", st.State, st.Endpoint, st.Mode)
		}
	}
	handler.SetAWGWarpRuntime(awgWarpEngine) // nil-safe: the handler answers the disabled shape
	if awgWarpEngine != nil && !awgWarpEngine.SupportsUDP() {
		// Kernel mode: the PBR field plane serves routing; the carrier stays
		// OUT of the reserve tree (its dial legs refuse with ErrKernelMode).
		log.Infof("[awgwarp] kernel-TUN PBR mode: no userspace carrier registered (from_cidrs selectors own the routing)")
	} else if awgWarpEngine != nil {
		reserve.Register(awgWarpEngine) // Register AFTER Start (proton canon)
		log.Infof("[awgwarp] carrier registered kind=warp priority=%d udp=true",
			reserve.PriorityWarp)
	}

	// Nested chains (tunnels panel stage 2; engines in transport/nested and
	// transport/wg, assembly in warpchainservice, config system.warp.chains[]).
	// One runtime per chain entry; every layer owns a DISTINCT identity slot
	// (one CF device per layer — the nested red line #3). Chain kinds:
	// masque+awg (UDP full-scope inner), awg+masque (IPv4/TCP inner),
	// awg+awg — the W+W composition over transportwg.NestedWgRuntime (UDP
	// full-scope through the inner AWG netstack, two CF wg devices) — and
	// masque+masque — the M+M composition over nested.MasqueMasqueRuntime
	// (IPv4/TCP through the inner MASQUE netstack, two CF masque devices).
	var chainEngines []*warpchainservice.Runtime
	for _, chain := range cfgPtr.Load().System.Warp.Chains {
		if !chain.Enabled {
			continue
		}
		kind := chain.Kind
		rt, err := warpchainservice.Build(cfgPtr.Load(), chain, warpchainservice.Options{
			OnEvent: func(ev warpchainservice.Event) {
				log.Infof("[chain %s] %s %s", kind, ev.Name, ev.Detail)
			},
		})
		if err != nil {
			log.Errorf("[chain %s] engine disabled this run: %v", chain.Kind, err)
			continue
		}
		if err := rt.Start(appCtx); err != nil {
			log.Errorf("[chain %s] engine start failed: %v", chain.Kind, err)
			continue
		}
		chainEngines = append(chainEngines, rt)
		handler.SetChainRuntime(chain.Kind, rt) // nil-safe per kind
		reserve.Register(rt)                    // Register AFTER Start (proton canon)
		log.Infof("[chain %s] engine started carrier kind=%s priority=%d udp=%t",
			chain.Kind, chain.Kind, reserve.PriorityOf(reserve.Kind(chain.Kind)), rt.SupportsUDP())
	}

	// НЕ РФ experimental mode (tunnels panel stage 6; addendum §3.2 /
	// ADR-WARP-6, the E6/E7 daemon assembly in src/nonruservice): a nested
	// WARP session riding the verified BASE warp (warpservice plane), gated
	// by multi-provider geo attestation. Zero wire calls unless
	// system.warp.nonru.enabled=true AND the base warp is up — ADR-WARP-6:
	// base WARP not ACTIVE makes the nested mode ineligible (the runtime
	// parks in waiting-base until the base identity materializes).
	// Carrier registration is DYNAMIC: the gate's route hooks register
	// kind=nonru on a fresh PASS_NON_RU attestation and revoke it on every
	// §62.5 close reason (the reserve registry IS the route).
	var nonruEngine *nonruservice.Runtime
	// b4x (field 2026-09-22): the НЕ РФ checkbox now means the NON-RU MASTER
	// SWITCH for the base MASQUE carrier (system.warp.socks5 gated on
	// system.warp.nonru.enabled in warpservice), NOT the experimental nested
	// composition. The nested M+M engine is intentionally NOT started: it
	// composed over the SAME base warp plane and reset the base carrier's data
	// path (`connection reset by peer`) while its geo-gate never opened — a
	// silent half-dead data plane. The checkbox + proxy now lives entirely in
	// warpservice; the handler keeps answering the disabled shape.
	_ = warpEngine
	handler.SetNonRURuntime(nonruEngine) // nil-safe: the handler answers the disabled shape

	// E-PROTON reserve transport (design v2; control plane in
	// src/transport/proton, data plane reuses the transport/wg engine).
	// Zero goroutines and zero wire calls unless system.proton.enabled=true
	// — the default config keeps the section off. The carrier seam is
	// REGISTERED below (review P2 stage PT6b): DialStream/DialUDP + the
	// kind=proton entry in the reserve registry the scoped-router trees
	// consume (priority LOWEST — design §7: below WARP/MASQUE/H3, never
	// a silent substitute). The kernel-TUN PBR path stays a separate
	// stage (review P2 step в).
	var protonEngine *protonservice.Runtime
	if cfgPtr.Load().System.Proton.Enabled {
		rt, err := protonservice.Build(cfgPtr.Load(), protonservice.Options{})
		if err != nil {
			log.Errorf("[proton] engine disabled this run: %v", err)
		} else if err := rt.Start(appCtx); err != nil {
			log.Errorf("[proton] engine start failed: %v", err)
		} else {
			protonEngine = rt
			st := rt.Status()
			log.Infof("[proton] engine started state=%s listening=%t", st.State, st.Listening)
		}
	}
	handler.SetProtonRuntime(protonEngine) // nil-safe: the handler answers the disabled shape
	// Review P2 (PT6b step б): register kind=proton in the selection-tree
	// seam with its design priority. Unregistered on stop (below).
	if protonEngine != nil {
		reserve.Register(protonEngine)
		log.Infof("[proton] carrier registered kind=proton priority=%d udp=%t",
			reserve.PriorityProton, protonEngine.SupportsUDP())
	}

	// E-OPERA reserve transport (design v2; engine in src/transport/opera,
	// assembly in operaservice). Zero goroutines and zero wire calls unless
	// system.opera.enabled=true — the default config keeps the section off.
	// The carrier seam (bootstrap-through-carrier) is wired by the base
	// transport layer when the selection trees learn the opera kind; direct
	// egress is the standalone path until then (review C1: proton canon).
	var operaEngine *operaservice.Runtime
	if cfgPtr.Load().System.Opera.Enabled {
		// Bootstrap-through-carrier (design §2/§5): API and data-plane dials
		// reach the SurfEasy infrastructure through the active base transport
		// (MASQUE/WG) when a direct egress is blocked. The base carrier is
		// resolved at dial time, so engines that register after this point are
		// picked up without a restart.
		rt, err := operaservice.Build(cfgPtr.Load(), operaservice.Options{
			Carrier: operaservice.BaseCarrierDial(),
		})
		if err != nil {
			log.Errorf("[opera] engine disabled this run: %v", err)
		} else if err := rt.Start(appCtx); err != nil {
			log.Errorf("[opera] engine start failed: %v", err)
		} else {
			operaEngine = rt
			st := rt.Status()
			log.Infof("[opera] engine started running=%t listening=%t region=%s",
				st.Running, st.Listening, st.Region)
		}
	}
	handler.SetOperaRuntime(operaEngine) // nil-safe: the handler answers the disabled shape
	// Tunnels pane seam: opera joins the selection-tree registry (kind=opera,
	// TCP-only). Register AFTER Start, Unregister BEFORE Stop (proton canon).
	if operaEngine != nil {
		reserve.Register(operaEngine)
		log.Infof("[opera] carrier registered kind=opera priority=%d udp=false",
			reserve.PriorityOpera)
	}

	// E-FXVPN reserve transport (review fxvpn-reserve-review.md; engine in
	// src/transport/fxvpn, assembly in fxvpservice). Zero goroutines and
	// zero wire calls unless system.fxvpn.enabled=true — the default
	// config keeps the section off. Canon: the proton/opera blocks above.
	//
	// Carrier-nesting / bootstrap-through-carrier (design §7.5): when the
	// config asks for it, hand the runtime the highest base transport
	// (MASQUE/AWG-WARP/H3) resolved at DIAL time — a carrier registered
	// after this Build is still picked up. This is what makes fxvpn usable
	// on a network that prefix-blocks the fastly-masque edge (field
	// b4x-auj): the direct edge is blackholed, the nested path works.
	var fxvpnEngine *fxvpservice.Runtime
	if fxvpnCfg := cfgPtr.Load().System.FxVPN; fxvpnCfg.Enabled {
		var fxvpnOpts fxvpservice.Options
		if fxvpnCfg.BootstrapThroughCarrier || fxvpnCfg.Masquerade.NestOnPortBlock {
			// Identical underlying signatures: explicit conversion is the
			// whole seam (no new import, no wrapper).
			fxvpnOpts.Carrier = fxvpservice.DialFunc(operaservice.BaseCarrierDial())
		}
		// Observability parity with opera: pool/ladder events (including the
		// fxvpn_nested_activated announcement — nesting is never silent,
		// design §7.8.3) reach the daemon log.
		fxvpnOpts.ExtraEvents = func(ev fxvpn.PoolEvent) {
			log.Infof("[fxvpn] %s %s %s", ev.Type, ev.Label, ev.Detail)
		}
		rt, err := fxvpservice.Build(cfgPtr.Load(), fxvpnOpts)
		if err != nil {
			log.Errorf("[fxvpn] engine disabled this run: %v", err)
		} else if err := rt.Start(appCtx); err != nil {
			log.Errorf("[fxvpn] engine start failed: %v", err)
		} else {
			fxvpnEngine = rt
			st := rt.Status()
			log.Infof("[fxvpn] engine started running=%t listening=%t carrier=%s",
				st.Running, st.Listening, st.Carrier)
		}
	}
	handler.SetFxvpnRuntime(fxvpnEngine) // nil-safe: the handler answers the disabled shape
	// Tunnels pane seam: fxvpn joins the selection-tree registry (kind=fxvpn,
	// TCP-only). Register AFTER Start, Unregister BEFORE Stop (proton canon).
	if fxvpnEngine != nil {
		reserve.Register(fxvpnEngine)
		log.Infof("[fxvpn] carrier registered kind=fxvpn priority=%d udp=false",
			reserve.PriorityFxvpn)
	}

	// E-TOR reserve tunnel (design tor-reserve-design.md; control plane
	// in src/transport/tor, snowflake in src/transport/torsnowflake,
	// assembly in torservice). Disabled by default (ToS grey zone +
	// the slowest reserve — design §0 honest boundaries). Canon: the
	// proton wiring — reserve.Register AFTER Start, Unregister BEFORE
	// Stop in the shutdown chain.
	var torEngine *torservice.Runtime
	if cfgPtr.Load().System.Tor.Enabled {
		rt, err := torservice.Build(cfgPtr.Load(), torservice.Options{})
		if err != nil {
			log.Errorf("[tor] engine disabled this run: %v", err)
		} else if err := rt.Start(appCtx); err != nil {
			log.Errorf("[tor] engine start failed: %v", err)
		} else {
			torEngine = rt
			st := rt.Status()
			log.Infof("[tor] engine started state=%s entry=%s", st.State, st.Entry.Mode)
		}
	}
	handler.SetTorRuntime(torEngine) // nil-safe: the handler answers the disabled shape
	if torEngine != nil {
		reserve.Register(torEngine)
		log.Infof("[tor] carrier registered kind=tor priority=%d udp=false (TCP-only, carrier of last resort)",
			reserve.PriorityTor)
	}

	// VLESS(+REALITY) reserve transport (design .ag/research/vless-tunnel-design.md;
	// engine in src/transport/vless, assembly in vlessservice). Zero goroutines
	// and zero wire calls unless system.vless.enabled=true — the default config
	// keeps the section off. V1 is the TCP-only carrier: b4x dials the local
	// SOCKS5 inbound of an EXTERNAL helper (xray/sing-box); the helper lifecycle
	// (spawn/ready/restart) and seek/geo selection are V2. Canon: the opera
	// block above (Register AFTER Start, Unregister BEFORE Stop).
	var vlessEngine *vlessservice.Runtime
	if cfgPtr.Load().System.Vless.Enabled {
		// Bootstrap-through-carrier (design §4/§8): the in-process client dials
		// the node through the active base transport when a direct egress is
		// blocked. Resolved at dial time, so late-registered carriers count.
		rt, err := vlessservice.Build(cfgPtr.Load(), vlessservice.Options{
			Carrier: vlessservice.DialFunc(operaservice.BaseCarrierDial()),
		})
		if err != nil {
			log.Errorf("[vless] engine disabled this run: %v", err)
		} else if err := rt.Start(appCtx); err != nil {
			log.Errorf("[vless] engine start failed: %v", err)
		} else {
			vlessEngine = rt
			st := rt.Status()
			log.Infof("[vless] engine started helper=%s socks=%s nodes=%d",
				st.Helper, st.SocksAddr, st.NodeCount)
		}
	}
	handler.SetVlessRuntime(vlessEngine) // nil-safe: the handler answers the disabled shape
	if vlessEngine != nil {
		reserve.Register(vlessEngine)
		log.Infof("[vless] carrier registered kind=vless priority=%d udp=%t",
			reserve.PriorityVless, vlessEngine.SupportsUDP())
	}

	// Tunnels pane seam: the reserve carriers registered above may serve
	// routing.mode=tunnel sets that were fail-closed at boot (their engines
	// start later than the first tproxy sync). One re-sync now wires every
	// tunnel listener that became possible.
	tproxyMgr.SyncConfig(cfgPtr.Load())
	tables.RoutingSyncConfig(cfgPtr.Load())

	// Service-profile WARP-recommendation lifecycle controller (FB-02 sp
	// section §28A.11): owns the recommendation state machine
	// (compile -> begin-test -> validate -> enable/promote) and the fourteen
	// §28A.11 hard-gate producers. Mirrors the warp runtime: Start/Stop bound
	// its controller loop; the future service-profile control plane feeds it
	// via Submit (bounded, non-blocking).
	serviceprofileRT := serviceprofile.NewRuntime(serviceprofile.DefaultConfig())
	serviceprofileRT.Start()
	handler.SetServiceProfileRuntime(serviceprofileRT)

	var geoScheduler *geodat.Scheduler
	if apiHandler != nil {
		geoScheduler = geodat.NewScheduler(
			func() geodat.GeoDatConfig { return cfgPtr.Load().System.Geo },
			func(dest, siteURL, ipURL string) error {
				_, _, err := apiHandler.RefreshGeodat(dest, siteURL, ipURL)
				return err
			},
			func(ts string) {
				c := cfgPtr.Load().Clone()
				c.System.Geo.AutoUpdate.LastRun = ts
				if err := c.SaveToFile(c.ConfigPath); err != nil {
					log.Errorf("failed to persist geo last_run: %v", err)
					return
				}
				cfgPtr.Store(c)
			},
		)
		geoScheduler.Start()
	}

	log.Infof("B4 is running. Press Ctrl+C to stop")
	metrics.RecordEvent("info", "B4 is fully operational")

	// Wait for shutdown signal
	sig := <-sigChan

	log.Infof("Received signal: %v, shutting down gracefully", sig)
	metrics.RecordEvent("info", fmt.Sprintf("Shutdown initiated by signal: %v", sig))

	wd.Stop()
	monitoringRT.Stop()
	warpRT.Stop()
	// Child-first teardown discipline: the chains ride their own CF
	// devices but compose two transports each — they stop before the
	// single-transport engines; AWG-WARP follows the same canon. The nonru
	// assembly rides the BASE warp plane — it stops before warpEngine (its
	// Stop is gate → nested composition; the plane is never touched).
	for _, rt := range chainEngines {
		reserve.Unregister(rt.Kind()) // trees see the stop immediately
		rt.Stop()
	}
	if nonruEngine != nil {
		nonruEngine.Stop() // unregisters kind=nonru + tears the gate/composition down
	}
	if awgWarpEngine != nil {
		reserve.Unregister(reserve.KindWarp) // trees see the stop immediately
		awgWarpEngine.Stop()
	}
	if warpMasqueCarrier != nil {
		reserve.Unregister(reserve.KindMasque) // trees see the stop immediately
		warpMasqueCarrier.Detach()
	}
	if warpEngine != nil {
		warpEngine.Stop()
	}
	if protonEngine != nil {
		reserve.Unregister(reserve.KindProton) // trees see the stop immediately
		protonEngine.Stop()
	}
	if operaEngine != nil {
		reserve.Unregister(reserve.KindOpera) // trees see the stop immediately
		operaEngine.Stop()
	}
	if fxvpnEngine != nil {
		reserve.Unregister(reserve.KindFxvpn) // trees see the stop immediately
		fxvpnEngine.Stop()
	}
	if torEngine != nil {
		reserve.Unregister(reserve.KindTor) // trees see the stop immediately
		torEngine.Stop()                    // graded ladder, PT proxy after tor
	}
	if vlessEngine != nil {
		reserve.Unregister(reserve.KindVless) // trees see the stop immediately
		vlessEngine.Stop()
	}
	if geoScheduler != nil {
		geoScheduler.Stop()
	}
	if tablesMonitor != nil {
		tablesMonitor.Stop()
	}
	tproxyMgr.Stop()

	// Perform graceful shutdown with timeout
	shutdownHandled = true
	return gracefulShutdown(cfgPtr.Load(), pool, tunEngine, httpServer, socks5Server, mtprotoServer, metrics, discoveryRT)
}

func gracefulShutdown(cfg *config.Config, pool *nfq.Pool, tunEngine *b4tun.Engine, httpServer *http.Server, socks5Server *socks5.Server, mtprotoServer *mtproto.Server, metrics *handler.MetricsCollector, discoveryRT *discovery.Runtime) error {
	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create wait group for parallel shutdown
	var wg sync.WaitGroup
	shutdownErrors := make(chan error, 4)

	// Shutdown HTTP server
	if httpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Infof("Shutting down HTTP server...")
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				log.Errorf("HTTP server shutdown error: %v", err)
				shutdownErrors <- fmt.Errorf("HTTP shutdown: %w", err)
			} else {
				log.Infof("HTTP server stopped")
			}
		}()
	}

	// Shutdown SOCKS5 server
	if socks5Server != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := socks5Server.Stop(); err != nil {
				log.Errorf("SOCKS5 server shutdown error: %v", err)
				shutdownErrors <- fmt.Errorf("SOCKS5 shutdown: %w", err)
			} else {
				log.Infof("SOCKS5 server stopped")
			}
		}()
	}

	if mtprotoServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mtprotoServer.Stop(); err != nil {
				log.Errorf("MTProto server shutdown error: %v", err)
				shutdownErrors <- fmt.Errorf("MTProto shutdown: %w", err)
			} else {
				log.Infof("MTProto server stopped")
			}
		}()
	}

	// Shutdown WebSocket connections
	log.Infof("Shutting down WebSocket connections...")
	b4http.Shutdown()

	// BLK-7: stop the adblock refresher + IP-learn worker, persisting the
	// pending learn snapshot before kernel state goes away.
	adblock.StopRefresher()

	if discoveryRT != nil && discoveryRT.IsActive() {
		log.Infof("Stopping active discovery...")
		discoveryRT.Stop("")
	}

	// Stop NFQueue pool
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Infof("Stopping netfilter queue pool...")
		metrics.NFQueueStatus = "stopping"

		// Use a goroutine with timeout for engine stop
		stopDone := make(chan struct{})
		go func() {
			if tunEngine != nil {
				tunEngine.Stop()
			}
			pool.Stop()
			close(stopDone)
		}()

		select {
		case <-stopDone:
			log.Infof("Netfilter queue pool stopped")
		case <-shutdownCtx.Done():
			log.Errorf("Netfilter queue pool stop timed out")
			shutdownErrors <- fmt.Errorf("NFQueue stop timeout")
		}

		quic.Shutdown()
	}()

	// Clean up iptables/nftables rules
	if tunEngine != nil {
		if !cfg.System.Tables.SkipSetup {
			tables.ClearMasqueradeOnly(cfg)
			tables.ClearMSSClampOnly(cfg)
			tables.RevertConntrackSysctls()
		}
		metrics.TablesStatus = "inactive"
	} else if !cfg.System.Tables.SkipSetup {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Infof("Clearing iptables/nftables rules...")
			if err := tables.ClearRules(cfg); err != nil {
				log.Errorf("Failed to clear tables rules: %v", err)
				metrics.RecordEvent("error", fmt.Sprintf("Failed to clear tables rules: %v", err))
				shutdownErrors <- fmt.Errorf("tables cleanup: %w", err)
			} else {
				log.Infof("Tables rules cleared")
				metrics.TablesStatus = "inactive"
			}
		}()
	}

	tables.RoutingClearAll()

	// Wait for all shutdown tasks or timeout
	shutdownDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		// All tasks completed
		close(shutdownErrors)

		// Check for any errors
		var errs []error
		for err := range shutdownErrors {
			errs = append(errs, err)
		}

		if len(errs) > 0 {
			log.Errorf("Shutdown completed with %d errors", len(errs))
			for _, err := range errs {
				log.Errorf("  - %v", err)
			}
			metrics.RecordEvent("warning", fmt.Sprintf("B4 shutdown with %d errors", len(errs)))
		} else {
			log.Infof("B4 stopped successfully")
			metrics.RecordEvent("info", "B4 shutdown complete")
		}

	case <-shutdownCtx.Done():
		log.Errorf("Shutdown timeout reached, forcing exit")
		metrics.RecordEvent("error", "Forced shutdown due to timeout")

		log.Flush()
		time.Sleep(100 * time.Millisecond)

		os.Exit(1)
	}

	nfq.ShutdownDNSRouteRuntime()

	log.CloseErrorFile()
	log.Flush()
	return nil
}

func ensureSingleInstance() (func(), error) {
	candidates := []string{"/var/run/b4.pid", "/run/b4.pid"}
	var f *os.File
	var path string
	for _, p := range candidates {
		fp, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
		if err == nil {
			f = fp
			path = p
			break
		}
	}
	if f == nil {
		return nil, nil
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			fmt.Fprintf(os.Stderr, "[INIT] single-instance check skipped: flock(%s): %v\n", path, err)
			f.Close()
			return nil, nil
		}
		data, _ := io.ReadAll(f)
		pid := strings.TrimSpace(string(data))
		f.Close()
		if pid == "" {
			return nil, fmt.Errorf("another b4 instance is already running (lock: %s)", path)
		}
		return nil, fmt.Errorf("another b4 instance is already running (pid %s)", pid)
	}

	if err := writePidFile(f, os.Getpid()); err != nil {
		fmt.Fprintf(os.Stderr, "[INIT] could not update pidfile %s: %v\n", path, err)
	}

	cleanup := func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		os.Remove(path)
	}
	return cleanup, nil
}

func writePidFile(f *os.File, pid int) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%d\n", pid); err != nil {
		return err
	}
	return f.Sync()
}

func initTimezone() {
	// Apply TZ env var if set; otherwise keep Go's default (system timezone from /etc/localtime)
	if tzName := os.Getenv("TZ"); tzName != "" {
		config.ApplyTimezone(tzName)
	}
}

func initLogging(cfg *config.Config) error {

	fmt.Fprintf(os.Stderr, "[INIT] Logging initialized at level %d\n", cfg.System.Logging.Level)

	w := io.MultiWriter(log.OrigStderr(), b4http.LogWriter())
	log.Init(w, log.Level(cfg.System.Logging.Level), cfg.System.Logging.Instaflush)

	if mainLogPath := cfg.System.Logging.MainLogPath(); mainLogPath != "" {
		if err := log.SetMainLogFile(mainLogPath); err != nil {
			log.Errorf("Failed to open main log file: %v", err)
		} else {
			log.Infof("Main logging to file: %s", mainLogPath)
		}
	}

	if cfg.System.Logging.Syslog {
		if err := log.EnableSyslog("b4"); err != nil {
			log.Warnf("Syslog unavailable, continuing without it: %v", err)
			cfg.System.Logging.Syslog = false
		} else {
			log.Infof("Syslog enabled")
		}
	}

	if errFilePath := cfg.System.Logging.ErrorFilePath(); errFilePath != "" {
		if err := log.InitErrorFile(errFilePath); err != nil {
			log.Errorf("Failed to open error log file: %v", err)
		} else {
			log.Infof("Error logging to file: %s", errFilePath)
		}
	}

	currentLogLevel = log.Level(cfg.System.Logging.Level)
	return nil
}

func printConfigDefaults(cmd *cobra.Command) {
	var all []*pflag.Flag
	cmd.InheritedFlags().VisitAll(func(f *pflag.Flag) { all = append(all, f) })
	cmd.Flags().VisitAll(func(f *pflag.Flag) { all = append(all, f) })
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })

	log.Infof("Effective CLI flags:")
	line := ""
	for _, f := range all {
		if line == "" {
			line = fmt.Sprintf("--%s=%s", f.Name, f.Value.String())
		} else {
			line += " " + fmt.Sprintf("--%s=%s", f.Name, f.Value.String())
		}
	}
	log.Infof("  %s", line)
}
