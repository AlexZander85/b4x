// Command b4-validate implements the FB-03 validation CLI (v2 §5.4):
//
//	b4-validate list                      print the canonical gate registry
//	b4-validate plan full                 print the full-scope gate plan with
//	                                      producer/consumer references
//	b4-validate full --profile release    evaluate the release gates against
//	                                      observed counters (fail-closed)
//	b4-validate requirement <ID>          print one canonical gate with its
//	                                      producer/consumer chain
//	b4-validate meta                      run the FB-03 meta-suite (registry
//	                                      integrity + API parity + mutation
//	                                      detection)
//	b4-validate registry                  print the FB-33 canonical source-stage
//	                                      registry totals (computed, by
//	                                      category) and run registry-integrity
//	                                      checks
//	b4-validate verdict <name>            resolve a principal verdict name to
//	                                      its canonical form (FB-34 alias
//	                                      mapping) and print the full record:
//	                                      kind, family, source, dependencies
//	                                      (ARCH graph closure), required gates,
//	                                      target evidence, blocked variants and
//	                                      expiry/invalidation rules
//	b4-validate matrix                    regenerate the gate producer/consumer
//	                                      matrix artifact (FB-03 criterion 6)
//	b4-validate preflight                 host registry + false-PASS mutant gate
//	b4-validate run --profile NAME        execute a named IV/field profile
//	b4-validate explain --verdict NAME    explain a principal verdict + claim policy
//	b4-validate list --capability NAME    list one capability and its gates
//
// Every command appends its output to artifacts/remediation/logs/
// (v2 §5.4); the matrix command writes
// artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.json.
//
// Exit codes: 0 = PASS / not applicable, 1 = FAIL / BLOCKED / STALE (any
// non-pass gate verdict), 2 = usage or lookup error.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/daniellavrushin/b4/validation"
)

const matrixDefaultName = "FB03_GATE_PRODUCER_CONSUMER_MATRIX.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `b4-validate — FB-03 hard-gate validation CLI (v2 §5.4)

Usage:
  b4-validate list [--json]
  b4-validate plan full [--json]
  b4-validate full --profile release [--counters-file FILE] [--baseline-file FILE] [--json]
  b4-validate requirement <ID> [--json]
  b4-validate meta [--json]
  b4-validate matrix [--out PATH]
  b4-validate registry [--json]
  b4-validate verdict <name> [--json]
  b4-validate preflight [--json]
  b4-validate run --profile <name> [--json] [--evidence-dir DIR]
  b4-validate explain --verdict <name> [--json]
  b4-validate list [--json] [--capability NAME]

Profiles: detector-quick, detector-deep, guided-search-ab,
          telegram-bridge-android, warp-causal-trace,
          warp-nested-nonru-trace, full-b4x

Exit codes: 0 PASS / not applicable; 1 non-pass verdict (FAIL/BLOCKED/STALE);
2 usage or lookup error. All commands log to artifacts/remediation/logs/.`)
}

// run is the testable command dispatcher. It returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "list":
		return cmdList(rest, stdout)
	case "plan":
		return cmdPlan(rest, stdout)
	case "full":
		return cmdFull(rest, stdout)
	case "requirement":
		return cmdRequirement(rest, stdout)
	case "meta":
		return cmdMeta(rest, stdout)
	case "matrix":
		return cmdMatrix(rest, stdout)
	case "registry":
		return cmdRegistry(rest, stdout)
	case "verdict":
		return cmdVerdict(rest, stdout)
	case "preflight":
		return cmdPreflight(rest, stdout)
	case "run":
		return cmdRun(rest, stdout)
	case "explain":
		return cmdExplain(rest, stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "b4-validate: unknown command %q\n", cmd)
		usage(stderr)
		return 2
	}
}

// tee wraps stdout with the per-command log file under
// artifacts/remediation/logs/ (v2 §5.4). Logging is skipped when the
// repository root cannot be located or the artifacts dir does not exist.
// The returned closer appends the exit summary and closes the log.
func tee(cmd string, stdout io.Writer, args []string) (io.Writer, func(int), error) {
	root, err := repoRoot()
	if err != nil {
		return stdout, func(int) {}, nil // never fail the command because of logging
	}
	logDir := filepath.Join(root, "artifacts", "remediation", "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return stdout, func(int) {}, nil
	}
	logPath := filepath.Join(logDir, fmt.Sprintf("b4-validate-%s-%s.log", cmd, time.Now().UTC().Format("20060102T150405")))
	f, err := os.Create(logPath)
	if err != nil {
		return stdout, func(int) {}, nil
	}
	header := fmt.Sprintf("# b4-validate %s %s\n# started %s UTC\n\n",
		cmd, strings.Join(args, " "), time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(f, header)
	return io.MultiWriter(stdout, f), func(code int) {
		fmt.Fprintf(f, "\n# exit %d (PASS=0, non-pass=1, usage=2)\n", code)
		_ = f.Close()
	}, nil
}

// repoRoot walks up from the working directory to the directory containing
// the artifacts/ tree (repository root). Returns an error when not found.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if fi, err := os.Stat(filepath.Join(dir, "artifacts")); err == nil && fi.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("repository root (artifacts/ dir) not found from %s", wd)
		}
		dir = parent
	}
}

// releaseScope is the --profile release scope: every subsystem enabled,
// service-profile capability present (SP gates applicable).
func releaseScope() (validation.ReleaseScope, validation.CapabilitySet) {
	return validation.ReleaseScope{
		WARPBase: true, WARPCamouflage: true, WARPNonRU: true, SPF: true,
		MON: true, ABD: true, DDITGB: true, SP: true, CSI: true,
		RSTGSO: true, PPE: true,
	}, validation.CapabilitySet{"service_profiles": true}
}

// producedByRegistry marks gates with a verified runtime producer as produced
// (registry evidence, not grep-based).
func producedByRegistry() map[string]bool {
	produced := make(map[string]bool)
	for _, g := range validation.AllHardGates() {
		if g.ProducerStatus == "verified" {
			produced[g.GateID] = true
		}
	}
	return produced
}

// readCountersMap loads a JSON object {metric: count} from path. An empty
// path yields nil (fail-closed: no observed evidence).
func readCountersMap(path string) (map[string]uint64, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m map[string]uint64
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s (expected {\"metric\": count}): %w", path, err)
	}
	return m, nil
}

// sha256Of returns the lowercase hex SHA-256 of a file.
func sha256Of(path string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data)), nil
}

// --- commands ---------------------------------------------------------------

func cmdList(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	capability := fs.String("capability", "", "Filter by capability id or alias (detector-v2, telegram-transparent-bridge, ...)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	w, closer, _ := tee("list", stdout, args)
	if *capability != "" {
		code := cmdListCapability(w, *capability, *jsonOut)
		closer(code)
		return code
	}
	defer closer(0)

	gates := validation.AllHardGates()
	sort.Slice(gates, func(i, j int) bool { return gates[i].GateID < gates[j].GateID })

	if *jsonOut {
		out, err := json.MarshalIndent(gates, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			return 1
		}
		fmt.Fprintln(w, string(out))
		return 0
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GATE\tFAMILY\tCLASS\tKIND\tSTATUS\tBLOCKER")
	for _, g := range gates {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%t\n",
			g.GateID, g.OwnerFamily, g.GlobalGateClass, g.Kind, g.ProducerStatus, g.PromotionBlocker)
	}
	_ = tw.Flush()

	fam := map[string][2]int{}
	for _, g := range gates {
		s := fam[g.OwnerFamily]
		if g.ProducerStatus == "verified" {
			s[0]++
		} else {
			s[1]++
		}
		fam[g.OwnerFamily] = s
	}
	fmt.Fprintf(w, "\nregistered=%d\n", len(gates))
	names := make([]string, 0, len(fam))
	for k := range fam {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		s := fam[k]
		fmt.Fprintf(w, "  %-8s verified=%d missing=%d\n", k, s[0], s[1])
	}
	return 0
}

func cmdPlan(args []string, stdout io.Writer) int {
	if len(args) == 0 || args[0] != "full" {
		fmt.Fprintln(stdout, "usage: b4-validate plan full [--json]")
		return 2
	}
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	w, closer, _ := tee("plan", stdout, args)
	defer closer(0)

	scope, caps := releaseScope()
	required, err := validation.RequiredHardGates(scope, caps, "", validation.GenerationSet{})
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return 1
	}
	gates := validation.AllHardGates()
	byName := make(map[string]validation.Gate, len(gates))
	for _, g := range gates {
		byName[g.GateID] = g
	}

	type planEntry struct {
		GateID    string                   `json:"gate_id"`
		Family    string                   `json:"family"`
		Class     string                   `json:"class"`
		Kind      string                   `json:"kind"`
		Status    string                   `json:"status"`
		Producer  validation.ProducerRef   `json:"producer,omitempty"`
		Consumers []validation.ConsumerRef `json:"consumers,omitempty"`
	}
	plan := make([]planEntry, 0, len(required))
	for _, gid := range required {
		g := byName[string(gid)]
		plan = append(plan, planEntry{
			GateID: g.GateID, Family: g.OwnerFamily, Class: g.GlobalGateClass,
			Kind: g.Kind, Status: g.ProducerStatus, Producer: g.RuntimeProducer,
			Consumers: g.VerdictConsumers,
		})
	}

	if *jsonOut {
		out, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			return 1
		}
		fmt.Fprintln(w, string(out))
		return 0
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GATE\tFAMILY\tSTATUS\tPRODUCER\tCONSUMERS")
	for _, e := range plan {
		prod := "—"
		if e.Producer.Symbol != "" {
			prod = fmt.Sprintf("%s@%s", e.Producer.Symbol, e.Producer.File)
		}
		consumers := make([]string, 0, len(e.Consumers))
		for _, c := range e.Consumers {
			consumers = append(consumers, fmt.Sprintf("%s:%s@%s", c.Kind, c.Symbol, c.File))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.GateID, e.Family, e.Status, prod, strings.Join(consumers, ", "))
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\napplicable=%d (full release scope)\n", len(plan))
	verified := 0
	for _, e := range plan {
		if e.Status == "verified" {
			verified++
		}
	}
	fmt.Fprintf(w, "verified=%d missing=%d\n", verified, len(plan)-verified)
	return 0
}

func cmdFull(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("full", flag.ContinueOnError)
	profile := fs.String("profile", "", "validation profile (release)")
	countersFile := fs.String("counters-file", "", `JSON {"metric": count} of observed counters; without it the CLI is fail-closed (no observed evidence)`)
	baselineFile := fs.String("baseline-file", "", "JSON baseline snapshot for the validation window (optional)")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	cfgGen := fs.Uint64("config-generation", 0, "config generation bound")
	evGen := fs.Uint64("evidence-generation", 0, "evidence generation bound")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile != "release" {
		fmt.Fprintln(stdout, "usage: b4-validate full --profile release [--counters-file FILE] [--baseline-file FILE] [--json]")
		return 2
	}
	w, closer, _ := tee("full", stdout, args)

	counters, err := readCountersMap(*countersFile)
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		closer(2)
		return 2
	}
	baseline, err := readCountersMap(*baselineFile)
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		closer(2)
		return 2
	}
	scope, caps := releaseScope()
	produced := producedByRegistry()
	for name := range counters {
		produced[name] = true
	}
	eval := validation.EvaluateHardGatesWindow(scope, caps, "",
		validation.GenerationSet{ConfigGeneration: *cfgGen, EvidenceGeneration: *evGen},
		counters, baseline, produced)

	code := 1
	switch eval.Verdict {
	case validation.GatePass, validation.GateNotApplicable:
		code = 0
	}
	closer(code)

	if *jsonOut {
		out, err := json.MarshalIndent(eval, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			return 1
		}
		fmt.Fprintln(w, string(out))
		return code
	}
	fmt.Fprintf(w, "verdict=%s applicable=%d produced=%d scanned=%d window_baseline=%t\n",
		eval.Verdict, eval.Applicable, eval.Produced, eval.Scanned, eval.WindowBaseline)
	for _, v := range eval.Violations {
		fmt.Fprintf(w, "  violation: %s count=%d\n", v.GateID, v.Count)
	}
	for _, gid := range eval.Missing {
		fmt.Fprintf(w, "  missing: %s\n", gid)
	}
	for _, gid := range eval.CounterReset {
		fmt.Fprintf(w, "  counter_reset: %s\n", gid)
	}
	for _, t := range eval.Telemetry {
		fmt.Fprintf(w, "  telemetry: %s count=%d\n", t.GateID, t.Count)
	}
	return code
}

func cmdRequirement(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("requirement", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stdout, "usage: b4-validate requirement <ID> [--json]")
		return 2
	}
	id := rest[0]
	w, closer, _ := tee("requirement", stdout, args)
	g, ok := validation.HardGateByName(id)
	if !ok {
		fmt.Fprintf(w, "gate %q not found in the canonical registry\n", id)
		closer(2)
		return 2
	}
	closer(0)

	if *jsonOut {
		out, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			return 1
		}
		fmt.Fprintln(w, string(out))
		return 0
	}
	fmt.Fprintf(w, "gate_id:       %s\n", g.GateID)
	fmt.Fprintf(w, "family:        %s\n", g.OwnerFamily)
	fmt.Fprintf(w, "class:         %s\n", g.GlobalGateClass)
	fmt.Fprintf(w, "stage:         %s\n", g.OwnerStage)
	fmt.Fprintf(w, "kind:          %s\n", g.Kind)
	fmt.Fprintf(w, "status:        %s\n", g.ProducerStatus)
	fmt.Fprintf(w, "blocker:       %t\n", g.PromotionBlocker)
	fmt.Fprintf(w, "reset:         %s\n", g.ResetSemantics)
	fmt.Fprintf(w, "applicability: %s\n", g.Applicability)
	if g.RuntimeProducer.Symbol != "" {
		fmt.Fprintf(w, "producer:      %s @ %s:%d (%s, root %s, commit %s)\n",
			g.RuntimeProducer.Symbol, g.RuntimeProducer.File, g.RuntimeProducer.Line,
			g.RuntimeProducer.Mechanism, g.RuntimeProducer.ProductionRoot, g.VerifiedCommit)
	} else {
		fmt.Fprintf(w, "producer:      (none — expected at %s)\n", g.ExpectedProducerLocation)
	}
	for _, c := range g.VerdictConsumers {
		fmt.Fprintf(w, "consumer:      %s:%s @ %s:%d (binding %s)\n", c.Kind, c.Symbol, c.File, c.Line, c.Binding)
	}
	for _, t := range g.TestProducers {
		fmt.Fprintf(w, "test:          %s @ %s:%d (assertion %s)\n", t.Name, t.File, t.Line, t.Assertion)
	}
	for _, m := range g.MutationTests {
		fmt.Fprintf(w, "mutation:      %s (%s) @ %s\n", m.Name, m.Status, m.File)
	}
	for _, a := range g.EvidenceArtifacts {
		fmt.Fprintf(w, "evidence:      %s\n", a)
	}
	return 0
}

func cmdMeta(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("meta", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	w, closer, _ := tee("meta", stdout, args)

	root, err := repoRoot()
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		closer(1)
		return 1
	}
	artifacts := make([]validation.Artifact, 0, 2)
	for _, rel := range []string{
		filepath.Join("specs", "registries", "hard_gates.yaml"),
		filepath.Join("src", "validation", "hard_gates_registry.gen.go"),
	} {
		path := filepath.Join(root, rel)
		sum, size, err := sha256Of(path)
		if err != nil {
			fmt.Fprintf(w, "error: artifact %s: %v\n", rel, err)
			closer(1)
			return 1
		}
		artifacts = append(artifacts, validation.Artifact{
			Name: filepath.Base(rel), SHA256: sum, Kind: "sha256", Size: size, Redacted: true,
		})
	}
	res := validation.RunMetaSuite(artifacts)
	ready := res.Ready()
	if *jsonOut {
		out, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			closer(1)
			return 1
		}
		fmt.Fprintln(w, string(out))
	} else {
		fmt.Fprintf(w, "registry_complete=%t api_parity=%t verdict_mutation_detected=%t\n",
			res.RegistryComplete, res.APIParity, res.VerdictMutationDetected)
		fmt.Fprintf(w, "evidence_integrity=%t reproducible=%t infrastructure_safe=%t false_negative_detected=%t\n",
			res.EvidenceIntegrity, res.Reproducible, res.InfrastructureSafe, res.FalseNegativeDetected)
		fmt.Fprintf(w, "ready=%t artifacts=%d\n", ready, len(res.Artifacts))
		for _, a := range res.Artifacts {
			fmt.Fprintf(w, "  artifact: %s sha256=%s size=%d\n", a.Name, a.SHA256, a.Size)
		}
	}
	code := 1
	if ready {
		code = 0
	}
	closer(code)
	return code
}

func cmdMatrix(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	out := fs.String("out", "", "output path (default <repo>/artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	w, closer, _ := tee("matrix", stdout, args)

	root, err := repoRoot()
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		closer(1)
		return 1
	}
	path := *out
	if path == "" {
		path = filepath.Join(root, "artifacts", "remediation", matrixDefaultName)
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}

	gates := validation.AllHardGates()
	sort.Slice(gates, func(i, j int) bool { return gates[i].GateID < gates[j].GateID })
	verified, missing := 0, 0
	families := map[string][2]int{}
	for _, g := range gates {
		s := families[g.OwnerFamily]
		if g.ProducerStatus == "verified" {
			s[0]++
			verified++
		} else {
			s[1]++
			missing++
		}
		families[g.OwnerFamily] = s
	}
	type matrixGate struct {
		GateID           string                   `json:"gate_id"`
		Family           string                   `json:"family"`
		Class            string                   `json:"class"`
		Stage            string                   `json:"stage"`
		Kind             string                   `json:"kind"`
		Status           string                   `json:"status"`
		PromotionBlocker bool                     `json:"promotion_blocker"`
		Producer         validation.ProducerRef   `json:"producer,omitempty"`
		Consumers        []validation.ConsumerRef `json:"consumers,omitempty"`
		Tests            []validation.TestRef     `json:"tests,omitempty"`
		Mutations        []validation.MutationRef `json:"mutations,omitempty"`
		Evidence         []string                 `json:"evidence,omitempty"`
	}
	doc := struct {
		GeneratedAt string            `json:"generated_at"`
		Source      string            `json:"source"`
		Total       int               `json:"total"`
		Verified    int               `json:"verified"`
		Missing     int               `json:"missing"`
		Families    map[string][2]int `json:"families_verified_missing"`
		Gates       []matrixGate      `json:"gates"`
	}{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      "specs/registries/hard_gates.yaml (generated hard_gates_registry.gen.go)",
		Total:       len(gates), Verified: verified, Missing: missing, Families: families,
	}
	for _, g := range gates {
		doc.Gates = append(doc.Gates, matrixGate{
			GateID: g.GateID, Family: g.OwnerFamily, Class: g.GlobalGateClass,
			Stage: g.OwnerStage, Kind: g.Kind, Status: g.ProducerStatus,
			PromotionBlocker: g.PromotionBlocker, Producer: g.RuntimeProducer,
			Consumers: g.VerdictConsumers, Tests: g.TestProducers,
			Mutations: g.MutationTests, Evidence: g.EvidenceArtifacts,
		})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		closer(1)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(w, "error:", err)
		closer(1)
		return 1
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fmt.Fprintln(w, "error:", err)
		closer(1)
		return 1
	}
	fmt.Fprintf(w, "matrix written: %s (total=%d verified=%d missing=%d)\n", path, len(gates), verified, missing)
	closer(0)
	return 0
}

// cmdRegistry implements `b4-validate registry [--json]` (FB-33, b4x-yzt):
// prints the canonical source-stage registry totals — computed from the
// generated registry, never hard-coded — grouped by category, and runs the
// registry-integrity checks. Exit codes: 0 = registry consistent,
// 1 = integrity failure (duplicate/orphan/missing hash/stage/dependency/
// verdict, declared_total mismatch), 2 = usage error.
func cmdRegistry(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("registry", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	w, closer, _ := tee("registry", stdout, args)

	errs := validation.ValidateSourceStageRegistry()
	totals := validation.SourceStageTotalsByCategory()
	criteria := validation.CriteriaTotal()

	type catTotal struct {
		Category string `json:"category"`
		Total    int    `json:"total"`
	}
	cats := make([]catTotal, 0, len(totals))
	for _, c := range validation.SourceStageCategories() {
		cats = append(cats, catTotal{Category: c, Total: totals[c]})
	}
	doc := struct {
		DeclaredTotal int        `json:"declared_total"`
		CriteriaTotal int        `json:"criteria_total"`
		Consistent    bool       `json:"consistent"`
		Categories    []catTotal `json:"categories"`
		Errors        []string   `json:"errors,omitempty"`
	}{DeclaredTotal: validation.SourceStageDeclaredTotal, CriteriaTotal: criteria,
		Consistent: len(errs) == 0, Categories: cats, Errors: errs}

	code := 1
	if doc.Consistent {
		code = 0
	}

	if *jsonOut {
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			closer(1)
			return 1
		}
		fmt.Fprintln(w, string(out))
		closer(code)
		return code
	}
	fmt.Fprintf(w, "criteria_total=%d declared_total=%d consistent=%t\n",
		doc.CriteriaTotal, doc.DeclaredTotal, doc.Consistent)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CATEGORY\tTOTAL")
	for _, c := range cats {
		fmt.Fprintf(tw, "%s\t%d\n", c.Category, c.Total)
	}
	_ = tw.Flush()
	if len(errs) > 0 {
		fmt.Fprintf(w, "errors=%d\n", len(errs))
		for _, e := range errs {
			fmt.Fprintf(w, "  error: %s\n", e)
		}
	}
	closer(code)
	return code
}

// cmdVerdict implements `b4-validate verdict <name> [--json]` (FB-34,
// b4x-xgc): resolves a verdict spelling (canonical or alias) to its canonical
// name and prints the full registry record — kind, owner family, normative
// source, ARCH-graph dependency closure, required gates, required target
// evidence, blocked variants and expiry/invalidation rules.
// Exit codes: 0 = resolved, 2 = unknown verdict name or usage error.
func cmdVerdict(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("verdict", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stdout, "usage: b4-validate verdict <name> [--json]")
		return 2
	}
	name := rest[0]
	w, closer, _ := tee("verdict", stdout, args)

	canonical, ok := validation.CanonicalVerdictName(name)
	if !ok {
		fmt.Fprintf(w, "verdict %q not found in the canonical principal verdict registry\n", name)
		closer(2)
		return 2
	}
	v, _ := validation.PrincipalVerdictByCanonical(canonical)
	closure, err := validation.VerdictDependencyClosure(canonical)
	if err != nil {
		fmt.Fprintf(w, "error: %v\n", err)
		closer(1)
		return 1
	}

	type verdictOut struct {
		Canonical              string   `json:"canonical"`
		ResolvedFromAlias      string   `json:"resolved_from_alias,omitempty"`
		Aliases                []string `json:"aliases,omitempty"`
		Kind                   string   `json:"kind"`
		OwnerFamily            string   `json:"owner_family"`
		SourceStageCategory    string   `json:"source_stage_category,omitempty"`
		SourceDoc              string   `json:"source_doc"`
		SourceSection          string   `json:"source_section"`
		Dependencies           []string `json:"dependencies,omitempty"`
		DependencyClosure      []string `json:"dependency_closure"`
		DependencyExpression   string   `json:"dependency_expression"`
		RequiredGates          []string `json:"required_gates,omitempty"`
		RequiredTargetEvidence []string `json:"required_target_evidence,omitempty"`
		BlockedVariants        []string `json:"blocked_variants,omitempty"`
		Expiry                 []string `json:"expiry"`
	}
	doc := verdictOut{
		Canonical: canonical, Kind: v.Kind, OwnerFamily: v.OwnerFamily,
		SourceDoc: v.SourceDoc, SourceSection: v.SourceSection,
		Dependencies: v.Dependencies, DependencyClosure: closure,
		DependencyExpression: v.DependencyExpression, RequiredGates: v.RequiredGates,
		RequiredTargetEvidence: v.RequiredTargetEvidence, BlockedVariants: v.BlockedVariants,
		Expiry: v.Expiry,
	}
	if name != canonical {
		doc.ResolvedFromAlias = name
	}
	if len(v.Aliases) > 0 {
		doc.Aliases = v.Aliases
	}
	if v.SourceStageCategory != "" {
		doc.SourceStageCategory = v.SourceStageCategory
	}

	closer(0)
	if *jsonOut {
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			return 1
		}
		fmt.Fprintln(w, string(out))
		return 0
	}
	if doc.ResolvedFromAlias != "" {
		fmt.Fprintf(w, "resolved: %s -> %s (alias mapping)\n", doc.ResolvedFromAlias, canonical)
	}
	fmt.Fprintf(w, "canonical:        %s\n", canonical)
	fmt.Fprintf(w, "kind:             %s\n", v.Kind)
	fmt.Fprintf(w, "owner_family:     %s\n", v.OwnerFamily)
	if v.SourceStageCategory != "" {
		fmt.Fprintf(w, "source_stage_cat: %s\n", v.SourceStageCategory)
	}
	fmt.Fprintf(w, "source:           %s §%s\n", v.SourceDoc, v.SourceSection)
	if len(v.Aliases) > 0 {
		fmt.Fprintf(w, "aliases:          %s\n", strings.Join(v.Aliases, ", "))
	}
	if len(v.Dependencies) > 0 {
		fmt.Fprintf(w, "dependencies:     %s\n", strings.Join(v.Dependencies, ", "))
	}
	fmt.Fprintf(w, "dependency_closure (%d):\n", len(closure))
	for _, d := range closure {
		fmt.Fprintf(w, "  %s\n", d)
	}
	fmt.Fprintf(w, "dependency_expression: %s\n", v.DependencyExpression)
	if len(v.RequiredGates) > 0 {
		fmt.Fprintf(w, "required_gates:   %s\n", strings.Join(v.RequiredGates, ", "))
	}
	if len(v.RequiredTargetEvidence) > 0 {
		fmt.Fprintf(w, "target_evidence:  %s\n", strings.Join(v.RequiredTargetEvidence, ", "))
	}
	if len(v.BlockedVariants) > 0 {
		fmt.Fprintf(w, "blocked_variants: %s\n", strings.Join(v.BlockedVariants, ", "))
	}
	fmt.Fprintf(w, "expiry:           %s\n", strings.Join(v.Expiry, ", "))
	return 0
}
