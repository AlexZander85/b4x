package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/daniellavrushin/b4/validation"
)

func cmdPreflight(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	w, closer, _ := tee("preflight", stdout, args)
	p := validation.RunHostPreflight()
	code := 1
	if p.Ready() {
		code = 0
	}
	if *jsonOut {
		out, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			closer(1)
			return 1
		}
		fmt.Fprintln(w, string(out))
		closer(code)
		return code
	}
	fmt.Fprintf(w, "source_stage=%t principal_verdicts=%t capability_graph=%t\n",
		p.SourceStageConsistent, p.PrincipalVerdictsConsistent, p.CapabilityGraphConsistent)
	fmt.Fprintf(w, "meta_ready=%t false_pass_guard=%t artifacts=%d ready=%t\n",
		p.MetaReady, p.FalsePassGuard, p.ArtifactCount, p.Ready())
	for _, e := range p.Errors {
		fmt.Fprintf(w, "  error: %s\n", e)
	}
	closer(code)
	return code
}

func cmdRun(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	profile := fs.String("profile", "", "validation profile")
	jsonOut := fs.Bool("json", false, "Emit JSON")
	evidenceDir := fs.String("evidence-dir", os.Getenv("B4_RESULTS_DIR"), "directory of immutable field evidence")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile == "" {
		fmt.Fprintln(stdout, "usage: b4-validate run --profile <name> [--json] [--evidence-dir DIR]")
		fmt.Fprintf(stdout, "profiles: %s\n", strings.Join(validation.ProfileNames(), ", "))
		return 2
	}
	w, closer, _ := tee("run", stdout, args)
	opt := validation.RunOptions{
		EvidenceDir:     *evidenceDir,
		RouterReachable: os.Getenv("B4_BASE_URL") != "",
		AndroidPresent:  os.Getenv("ADB_SERIAL") != "",
	}
	run, err := validation.ExecuteProfile(*profile, opt)
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		closer(2)
		return 2
	}
	verdict := run.Verdict()
	code := 1
	if verdict == validation.Pass || verdict == validation.NotApplicable {
		code = 0
	}
	if *jsonOut {
		out, err := json.MarshalIndent(run, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			closer(1)
			return 1
		}
		fmt.Fprintln(w, string(out))
		closer(code)
		return code
	}
	fmt.Fprintf(w, "profile=%s run_id=%s verdict=%s stages=%d cleanup=%t warp_scope=%t\n",
		run.Profile, run.RunID, verdict, len(run.Results), run.CleanupComplete, run.DeclaredWARPScope)
	for _, st := range run.Results {
		fmt.Fprintf(w, "  stage %-28s %s", st.Stage, st.Verdict)
		if len(st.Limitations) > 0 {
			fmt.Fprintf(w, " (%s)", strings.Join(st.Limitations, "; "))
		}
		fmt.Fprintln(w)
	}
	closer(code)
	return code
}

func cmdExplain(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Emit JSON")
	nameFlag := fs.String("verdict", "", "principal verdict name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	name := *nameFlag
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	}
	if name == "" {
		fmt.Fprintln(stdout, "usage: b4-validate explain --verdict <name> [--json]")
		return 2
	}
	w, closer, _ := tee("explain", stdout, args)
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
	policy := claimPolicy(canonical)
	doc := map[string]any{
		"canonical":                canonical,
		"kind":                     v.Kind,
		"owner_family":             v.OwnerFamily,
		"source_doc":               v.SourceDoc,
		"source_section":           v.SourceSection,
		"dependency_closure":       closure,
		"required_gates":           v.RequiredGates,
		"required_target_evidence": v.RequiredTargetEvidence,
		"expiry":                   v.Expiry,
		"claim_policy":             policy,
		"current_status":           "BLOCKED_MISSING_ARTIFACT",
		"reason":                   "no immutable field evidence attached to this explain invocation",
	}
	if name != canonical {
		doc["resolved_from_alias"] = name
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
	fmt.Fprintf(w, "canonical:     %s\n", canonical)
	fmt.Fprintf(w, "kind:          %s\n", v.Kind)
	fmt.Fprintf(w, "source:        %s §%s\n", v.SourceDoc, v.SourceSection)
	fmt.Fprintf(w, "claim_policy:  %s\n", policy)
	fmt.Fprintf(w, "current:       BLOCKED_MISSING_ARTIFACT\n")
	fmt.Fprintf(w, "reason:        no immutable field evidence attached to this explain invocation\n")
	fmt.Fprintf(w, "dependencies:\n")
	for _, d := range closure {
		fmt.Fprintf(w, "  %s\n", d)
	}
	return 0
}

func claimPolicy(canonical string) string {
	switch canonical {
	case "ISSUE_277_RESOLVED":
		return "cannot be inferred from a larger timeout; requires delayed-first-byte Android/controlled reproduction, exact prefix-preserving handoff, and zero destructive zero-byte drop"
	case "ISSUE_278_RESOLVED":
		return "cannot be inferred from a new API field; requires measured detector-guided vs full Discovery A/B impact on a real BlockingProfile"
	case "WARP_CAUSAL_TRACE_READY":
		return "narrow causal-trace verdict; optional nested/non-RU/Android claims are separate and must not be mixed"
	case "MON_PRODUCTION_READY":
		return "requires real-router/Android field evidence; unit IV-18 coverage is not sufficient"
	default:
		return "PASS requires production reachability, active gate producers/consumers, Keenetic+Android evidence, isolation, cleanup closure, and validation-of-validation"
	}
}

func cmdListCapability(w io.Writer, name string, jsonOut bool) int {
	id, ok := validation.ResolveCapabilityAlias(name)
	if !ok {
		fmt.Fprintf(w, "capability %q not found\n", name)
		return 2
	}
	cap, _ := validation.CapabilityByID(id)
	fam := capabilityFamilies(id)
	var gates []validation.Gate
	for _, g := range validation.AllHardGates() {
		if fam[g.OwnerFamily] {
			gates = append(gates, g)
		}
	}
	if jsonOut {
		doc := map[string]any{
			"capability": cap,
			"resolved":   id,
			"alias":      name,
			"families":   keysOf(fam),
			"gates":      gates,
		}
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			fmt.Fprintln(w, "error:", err)
			return 1
		}
		fmt.Fprintln(w, string(out))
		return 0
	}
	fmt.Fprintf(w, "capability: %s (%s) layer=%d optional=%t parallel=%t\n",
		cap.ID, cap.Name, cap.Layer, cap.Optional, cap.Parallel)
	if len(cap.Requires) > 0 {
		fmt.Fprintf(w, "requires:   %s\n", strings.Join(cap.Requires, ", "))
	}
	fmt.Fprintf(w, "gates:      %d (families %s)\n", len(gates), strings.Join(keysOf(fam), ","))
	for _, g := range gates {
		fmt.Fprintf(w, "  %s\t%s\t%s\n", g.GateID, g.OwnerFamily, g.ProducerStatus)
	}
	return 0
}

func capabilityFamilies(id string) map[string]bool {
	switch id {
	case "abd":
		return map[string]bool{"abd": true}
	case "ddi":
		return map[string]bool{"ddi": true, "ddi_tgb": true}
	case "tgb":
		return map[string]bool{"ddi_tgb": true}
	case "warp":
		return map[string]bool{"warp": true}
	case "mon":
		return map[string]bool{"mon": true}
	case "visibility":
		return map[string]bool{"csi": true, "rst_gso": true, "ppe": true}
	case "progress":
		return map[string]bool{"spf": true}
	case "service_profile":
		return map[string]bool{"sp": true}
	case "classifier":
		return map[string]bool{"csi": true, "rst_gso": true}
	default:
		return map[string]bool{id: true}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
