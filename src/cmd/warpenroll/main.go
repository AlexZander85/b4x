// Command warpenroll runs WARP identity lifecycle operations and one-shot
// supervisor sessions on ANY platform (field workaround: router-local
// api.cloudflareclient.com traffic dies on SNI filtering because b4's
// NFQUEUE capture covers LAN forwarding only — see field1-report.md).
//
//	warpenroll enroll --config cfg.json
//	warpenroll run    --config cfg.json --wait 45s
//	warpenroll status --config cfg.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	warp "github.com/daniellavrushin/b4/transport/warp"
	"github.com/daniellavrushin/b4/warpservice"
)

func loadConfig(path string) (*config.Config, error) {
	c := config.NewConfig()
	if _, err := c.LoadWithMigration(path); err != nil {
		return nil, err
	}
	return &c, nil
}

func configFlag(args []string) *string {
	fs := flag.NewFlagSet("warpenroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("config", "", "path to config json (required)")
	wait := fs.Duration("wait", 45*time.Second, "run mode: max wait for connected state")
	_ = wait // parsed for symmetry; only run mode consumes it via its own set
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		os.Exit(2)
	}
	return path
}

func printJSON(v any) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

func cmdEnroll(args []string) error {
	c, err := loadConfig(*configFlag(args))
	if err != nil {
		return err
	}
	rt, err := warpservice.Build(c, nil)
	if err != nil {
		return err
	}
	res, enrollErr := rt.EnrollOnce(context.Background())
	printJSON(warpservice.EnrollSummary(res, c.System.Warp.IdentityPath))
	return enrollErr
}

func cmdStatus(args []string) error {
	c, err := loadConfig(*configFlag(args))
	if err != nil {
		return err
	}
	printJSON(warpservice.OfflineSummary(c.System.Warp.IdentityPath))
	return nil
}

// eventCollector is the sink: the supervisor emits from its own goroutine,
// so access is mutex-guarded.
type eventCollector struct {
	mu sync.Mutex
	ev []warpservice.Event
}

func (c *eventCollector) add(ev warpservice.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ev = append(c.ev, ev)
	fmt.Printf("{\"event\":%q,\"class\":%q,\"status\":%d,\"colo\":%q,\"detail\":%q}\n",
		ev.Name, ev.FailureClass, ev.Status, ev.Colo, ev.Detail)
}

func (c *eventCollector) snapshot() []warpservice.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]warpservice.Event(nil), c.ev...)
}

// cmdRun starts the supervisor, waits for the connected state (engine trust
// gate passed: data-plane probe round trips over the live tunnel), dumps
// status + events and stops. This proves the H2-MASQUE data plane end-to-end.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := fs.String("config", "", "path to config json (required)")
	wait := fs.Duration("wait", 45*time.Second, "max wait for connected state")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *path == "" {
		return fmt.Errorf("--config is required")
	}
	c, err := loadConfig(*path)
	if err != nil {
		return err
	}
	col := &eventCollector{}
	rt, err := warpservice.Build(c, col.add)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer rt.Stop()
	if err := rt.Start(ctx); err != nil {
		return err
	}

	reached := false
	deadline := time.Now().Add(*wait)
	for time.Now().Before(deadline) {
		if rt.Status().Status.State == warp.StateConnected || rt.Status().Status.State == warp.StateStopped {
			reached = rt.Status().Status.State == warp.StateConnected
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	snap := rt.Status()
	printJSON(map[string]any{
		"reached_connected": reached,
		"state":             string(snap.Status.State),
		"colo":              snap.Status.LastColo,
		"attempt":           snap.Status.Attempt,
		"last_failure":      snap.Status.LastFailureClass,
		"events":            col.snapshot(),
	})
	return nil
}

const usage = `warpenroll — WARP identity lifecycle from outside the SNI-filtered network

Usage:
  warpenroll enroll --config <cfg.json>
  warpenroll run    --config <cfg.json> [--wait 45s]
  warpenroll status --config <cfg.json>

enroll: register a new WARP identity (api.cloudflareclient.com) and store it
        at System.Warp.IdentityPath.
run:    start the supervisor, wait for the connected state (engine trust gate
        passed: data-plane probe round trips over the live tunnel), dump
        status + the event stream, then stop.
status: offline summary of the stored identity; no network activity.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warpenroll %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}
