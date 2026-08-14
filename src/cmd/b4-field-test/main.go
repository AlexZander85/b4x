// Command b4-field-test is the local Field-Test Controller (FT v1.5 §5.1).
// It owns Windows/ADB/router sessions and never executes ADB on the router.
//
//	b4-field-test preflight
//	b4-field-test run --profile quick|standard [--app official|revanced]
//	b4-field-test compare candidate-a candidate-b
//	b4-field-test validate candidate-a --runs 5
//	b4-field-test canary candidate-a
//	b4-field-test rollback
//	b4-field-test export RUN_ID
//
// Verdict state is the canonical validation package. This CLI does not keep
// a second source of truth.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/fieldtest"
	"github.com/daniellavrushin/b4/validation"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `b4-field-test — local Field-Test Controller (FT v1.5)

Usage:
  b4-field-test preflight [--json]
  b4-field-test run --profile quick|standard [--app official|revanced] [--json]
  b4-field-test compare <candidate-a> <candidate-b> [--json]
  b4-field-test validate <candidate> --runs N [--json]
  b4-field-test canary <candidate> [--json]
  b4-field-test rollback [--json]
  b4-field-test export <RUN_ID>

Environment: B4_BASE_URL B4_API_TOKEN B4_CLIENT_ID B4_ROUTER_HOST
             ADB_SERIAL B4_RESULTS_DIR B4_REQUIRE_ZERO_UNRELATED_ACTIONS

Exit: 0 ready/PASS; 1 FAIL/BLOCKED; 2 usage.`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "preflight":
		return cmdPreflight(rest, stdout)
	case "run":
		return cmdRun(rest, stdout)
	case "compare":
		return cmdCompare(rest, stdout)
	case "validate":
		return cmdValidate(rest, stdout)
	case "canary":
		return cmdCanary(rest, stdout)
	case "rollback":
		return cmdRollback(rest, stdout)
	case "export":
		return cmdExport(rest, stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "b4-field-test: unknown command %q\n", cmd)
		usage(stderr)
		return 2
	}
}

func resultsDir() string {
	if d := os.Getenv("B4_RESULTS_DIR"); d != "" {
		return d
	}
	return filepath.Join("artifacts", "field-runs")
}

func cmdPreflight(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p := fieldtest.DiscoverEnv(ctx, os.Getenv("B4_BASE_URL"), resultsDir(), os.Getenv("B4_ROUTER_HOST"))
	if *jsonOut {
		fmt.Fprint(stdout, string(p.JSON()))
	} else {
		fmt.Fprintf(stdout, "docker=%t adb=%t ssh=%t router_http=%t router_ssh=%t host=%t ready=%t\n",
			p.Docker.OK, p.ADB.OK, p.SSH.OK, p.RouterHTTP.OK, p.RouterSSH.OK, p.HostPreflight.Ready(), p.Ready)
		for _, b := range p.Blocking {
			fmt.Fprintf(stdout, "  blocked: %s\n", b)
		}
		if p.AndroidSerial != "" {
			fmt.Fprintf(stdout, "android_serial=%s packages=%d\n", p.AndroidSerial, len(p.AndroidPackages))
		}
	}
	if p.Ready {
		return 0
	}
	return 1
}

func cmdRun(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	profile := fs.String("profile", "quick", "quick|standard")
	app := fs.String("app", "official", "official|revanced")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile != "quick" && *profile != "standard" {
		fmt.Fprintln(stdout, "usage: b4-field-test run --profile quick|standard [--app official|revanced]")
		return 2
	}
	dir := resultsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(stdout, "error:", err)
		return 1
	}
	ctrl, err := fieldtest.NewController(envOr("B4_BASE_URL", "http://127.0.0.1"), dir)
	if err != nil {
		fmt.Fprintln(stdout, "error:", err)
		return 1
	}
	runID := fmt.Sprintf("B4X-FT-%s-%s", time.Now().UTC().Format("20060102T150405"), *profile)
	gen := uint64(1)
	req := fieldtest.SessionRequest{
		ClientID:         envOr("B4_CLIENT_ID", "field-client"),
		TargetAppID:      "youtube",
		TargetVariant:    *app,
		TargetPackage:    packageForApp(*app),
		ConfigGeneration: gen,
		DurationLimitSec: 180,
		ControlApps:      []string{"gmail", "google_app"},
	}
	sess, _, err := ctrl.Create(runID, req, gen, runID)
	if err != nil {
		fmt.Fprintln(stdout, "error:", err)
		return 1
	}
	valProfile := validation.ProfileDetectorQuick
	if *profile == "standard" {
		valProfile = validation.ProfileFullB4X
	}
	if *app == "revanced" && os.Getenv("ANDROID_PACKAGE_REVANCED") == "" {
		// ReVanced absence is a target block, not a harness pass.
	}
	run, err := validation.ExecuteProfile(valProfile, validation.RunOptions{
		RunID:           runID,
		EvidenceDir:     dir,
		RouterReachable: os.Getenv("B4_BASE_URL") != "",
		AndroidPresent:  os.Getenv("ADB_SERIAL") != "",
	})
	if err != nil {
		fmt.Fprintln(stdout, "error:", err)
		return 1
	}
	_ = ctrl.Stop(runID)
	rep, _ := ctrl.Report(runID)
	outDoc := map[string]any{
		"run_id":     runID,
		"session":    sess,
		"profile":    *profile,
		"app":        *app,
		"validation": run,
		"report":     rep,
		"verdict":    run.Verdict(),
	}
	writeJSON(filepath.Join(dir, runID+"-summary.json"), outDoc)
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(outDoc)
	} else {
		fmt.Fprintf(stdout, "run_id=%s session=%s verdict=%s\n", runID, sess.SessionID, run.Verdict())
	}
	if run.Verdict() == validation.Pass {
		return 0
	}
	return 1
}

func cmdCompare(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(stdout, "usage: b4-field-test compare <candidate-a> <candidate-b>")
		return 2
	}
	doc := map[string]any{
		"candidate_a": rest[0],
		"candidate_b": rest[1],
		"verdict":     validation.Blocked,
		"reason":      "no paired field evidence for both candidates; compare is fail-closed",
	}
	return emit(stdout, *jsonOut, doc, 1)
}

func cmdValidate(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	runs := fs.Int("runs", 5, "repeat count (contract: validate=5)")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	flags, rest := splitFlags(args)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(rest) != 1 {
		fmt.Fprintln(stdout, "usage: b4-field-test validate <candidate> --runs N")
		return 2
	}
	if *runs < 1 {
		fmt.Fprintln(stdout, "runs must be >= 1")
		return 2
	}
	doc := map[string]any{
		"candidate": rest[0],
		"runs":      *runs,
		"verdict":   validation.Blocked,
		"reason":    "validate requires " + fmt.Sprint(*runs) + " recorded field runs; none present",
	}
	return emit(stdout, *jsonOut, doc, 1)
}

func cmdCanary(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("canary", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stdout, "usage: b4-field-test canary <candidate>")
		return 2
	}
	req := fieldtest.CanaryRequest{
		CandidateID: rest[0], ClientIDs: []string{envOr("B4_CLIENT_ID", "field-client")},
		FlowPercent: 10, DurationSec: 60, AutomaticRollback: true, Mode: fieldtest.CanaryAuto,
	}
	if err := fieldtest.ValidateCanary(req); err != nil {
		fmt.Fprintln(stdout, "error:", err)
		return 2
	}
	// Production promotion is forbidden for this controller.
	doc := map[string]any{
		"candidate": rest[0],
		"eligible":  false,
		"verdict":   validation.Blocked,
		"reason":    "canary requires a PASS hard-gate window and deployed RC; strategy:promote is disabled",
	}
	return emit(stdout, *jsonOut, doc, 1)
}

func cmdRollback(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	doc := map[string]any{
		"action":  "rollback",
		"verdict": validation.Blocked,
		"reason":  "no armed rollback session; POST /api/v1/runtime/rollback was not invoked",
	}
	if os.Getenv("B4_BASE_URL") == "" {
		doc["reason"] = "B4_BASE_URL not set; rollback not attempted"
	}
	return emit(stdout, *jsonOut, doc, 1)
}

func cmdExport(args []string, stdout io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stdout, "usage: b4-field-test export <RUN_ID>")
		return 2
	}
	runID := args[0]
	src := filepath.Join(resultsDir(), runID+"-summary.json")
	if _, err := os.Stat(src); err != nil {
		fmt.Fprintf(stdout, "run %s not found at %s\n", runID, src)
		return 1
	}
	fmt.Fprintln(stdout, src)
	return 0
}

func emit(w io.Writer, jsonOut bool, doc map[string]any, code int) int {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(doc)
		return code
	}
	fmt.Fprintf(w, "verdict=%v\n", doc["verdict"])
	if r, ok := doc["reason"]; ok {
		fmt.Fprintf(w, "reason=%v\n", r)
	}
	return code
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, append(b, '\n'), 0o644)
}

// splitFlags lets contract-style `cmd positional --flag value` work with
// the stdlib flag parser (which otherwise stops at the first operand).
func splitFlags(args []string) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				name := strings.TrimLeft(a, "-")
				if name != "json" && name != "h" && name != "help" {
					flags = append(flags, args[i+1])
					i++
				}
			}
			continue
		}
		positional = append(positional, a)
	}
	return flags, positional
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func packageForApp(app string) string {
	switch app {
	case "revanced":
		return os.Getenv("ANDROID_PACKAGE_REVANCED")
	default:
		if v := os.Getenv("ANDROID_PACKAGE_OFFICIAL"); v != "" {
			return v
		}
		return "com.google.android.youtube"
	}
}
