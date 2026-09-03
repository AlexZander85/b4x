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
        "github.com/daniellavrushin/b4/config"
        "github.com/daniellavrushin/b4/discovery"
        "github.com/daniellavrushin/b4/geodat"
        b4http "github.com/daniellavrushin/b4/http"
        "github.com/daniellavrushin/b4/http/handler"
        "github.com/daniellavrushin/b4/fxvpservice"
        "github.com/daniellavrushin/b4/log"
        "github.com/daniellavrushin/b4/monitoring"
        "github.com/daniellavrushin/b4/mtproto"
        "github.com/daniellavrushin/b4/nfq"
        "github.com/daniellavrushin/b4/operaservice"
        "github.com/daniellavrushin/b4/observability"
        "github.com/daniellavrushin/b4/protonservice"
        "github.com/daniellavrushin/b4/quic"
        "github.com/daniellavrushin/b4/reserve"
        "github.com/daniellavrushin/b4/serviceprofile"
        "github.com/daniellavrushin/b4/socks5"
        "github.com/daniellavrushin/b4/tables"
        "github.com/daniellavrushin/b4/tproxy"
        b4tun "github.com/daniellavrushin/b4/tun"
        "github.com/daniellavrushin/b4/validation"
        "github.com/daniellavrushin/b4/warp"
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

func init() {
        for _, sub := range []*cobra.Command{warpEnrollCmd, warpStatusCmd} {
                sub.Flags().String("config", "", "Path to b4.json (required)")
                warpCmd.AddCommand(sub)
        }
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
                rt, err := operaservice.Build(cfgPtr.Load(), operaservice.Options{})
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

        // E-FXVPN reserve transport (review fxvpn-reserve-review.md; engine in
        // src/transport/fxvpn, assembly in fxvpservice). Zero goroutines and
        // zero wire calls unless system.fxvpn.enabled=true — the default
        // config keeps the section off. Canon: the proton/opera blocks above.
        // The bootstrap-through-carrier seam stays nil until the selection
        // trees learn the fxvpn kind (same posture as opera/proton); direct
        // egress is the standalone path until then.
        var fxvpnEngine *fxvpservice.Runtime
        if cfgPtr.Load().System.FxVPN.Enabled {
                rt, err := fxvpservice.Build(cfgPtr.Load(), fxvpservice.Options{})
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
        if warpEngine != nil {
                warpEngine.Stop()
        }
        if protonEngine != nil {
                reserve.Unregister(reserve.KindProton) // trees see the stop immediately
                protonEngine.Stop()
        }
        if fxvpnEngine != nil {
                fxvpnEngine.Stop()
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
