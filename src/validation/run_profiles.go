package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

// Named validation profiles from IV v1.5 / field-validation CLI contract.
// Each profile selects a capability subset; execution order always follows
// the canonical capability graph (FB-36). Missing field evidence is never
// aggregated as PASS.
const (
	ProfileDetectorQuick         = "detector-quick"
	ProfileDetectorDeep          = "detector-deep"
	ProfileGuidedSearchAB        = "guided-search-ab"
	ProfileTelegramBridgeAndroid = "telegram-bridge-android"
	ProfileWARPCausalTrace       = "warp-causal-trace"
	ProfileWARPNestedNonRU       = "warp-nested-nonru-trace"
	ProfileFullB4X               = "full-b4x"
)

// Capability aliases accepted by `b4-validate list --capability`.
var CapabilityAliases = map[string]string{
	"detector-v2":                 "abd",
	"detector":                    "abd",
	"adaptive-blocking-detector":  "abd",
	"detector-guided-discovery":   "ddi",
	"guided-discovery":            "ddi",
	"telegram-transparent-bridge": "tgb",
	"telegram-bridge":             "tgb",
	"tgb":                         "tgb",
	"warp":                        "warp",
	"warp-masque":                 "warp",
	"service-profiles":            "service_profile",
	"service_profiles":            "service_profile",
	"monitoring":                  "mon",
	"classifier":                  "classifier",
	"visibility":                  "visibility",
	"progress":                    "progress",
	"canary":                      "canary",
	"mon":                         "mon",
	"abd":                         "abd",
	"ddi":                         "ddi",
}

// ProfileSpec is the executable definition of a named validation profile.
type ProfileSpec struct {
	Name              string
	Capabilities      []string
	RequiresField     bool
	RequiresAndroid   bool
	DeclaredWARPScope bool
	PrincipalVerdicts []string
}

// ProfileByName returns the named profile spec.
func ProfileByName(name string) (ProfileSpec, bool) {
	p, ok := profiles[name]
	return p, ok
}

// ProfileNames returns the sorted list of executable profile names.
func ProfileNames() []string {
	out := make([]string, 0, len(profiles))
	for k := range profiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var profiles = map[string]ProfileSpec{
	ProfileDetectorQuick: {
		Name: ProfileDetectorQuick, Capabilities: []string{"abd"},
		RequiresField: true, PrincipalVerdicts: []string{"ABD_PRODUCTION_READY"},
	},
	ProfileDetectorDeep: {
		Name: ProfileDetectorDeep, Capabilities: []string{"mon", "abd"},
		RequiresField:     true,
		PrincipalVerdicts: []string{"MON_PRODUCTION_READY", "ABD_PRODUCTION_READY"},
	},
	ProfileGuidedSearchAB: {
		Name: ProfileGuidedSearchAB, Capabilities: []string{"abd", "ddi"},
		RequiresField:     true,
		PrincipalVerdicts: []string{"ABD_PRODUCTION_READY", "DETECTOR_GUIDED_STRATEGY_SEARCH_READY", "ISSUE_278_RESOLVED"},
	},
	ProfileTelegramBridgeAndroid: {
		Name: ProfileTelegramBridgeAndroid, Capabilities: []string{"tgb"},
		RequiresField: true, RequiresAndroid: true,
		PrincipalVerdicts: []string{"TGB_PRODUCTION_READY", "ISSUE_277_RESOLVED"},
	},
	ProfileWARPCausalTrace: {
		Name: ProfileWARPCausalTrace, Capabilities: []string{"warp"},
		RequiresField: true, DeclaredWARPScope: true,
		PrincipalVerdicts: []string{"WARP_CAUSAL_TRACE_READY", "WARP_BASE_TRANSPORT_READY"},
	},
	ProfileWARPNestedNonRU: {
		Name: ProfileWARPNestedNonRU, Capabilities: []string{"warp"},
		RequiresField: true, DeclaredWARPScope: true,
		PrincipalVerdicts: []string{"WARP_NESTED_READY", "WARP_NON_RU_READY"},
	},
	ProfileFullB4X: {
		Name: ProfileFullB4X, Capabilities: nil, // filled from FullRunOrder
		RequiresField: true, RequiresAndroid: true, DeclaredWARPScope: true,
	},
}

// RunOptions controls ExecuteProfile. Field evidence is opt-in: without it
// every field stage is BLOCKED_TARGET_VALIDATION.
type RunOptions struct {
	RunID           string
	EvidenceDir     string
	RouterReachable bool
	AndroidPresent  bool
	CleanupLedger   bool
	Now             time.Time
}

// ExecuteProfile builds a FullRun from live host registries and, when
// present, field evidence. It never converts SKIPPED/missing into PASS.
func ExecuteProfile(name string, opt RunOptions) (FullRun, error) {
	spec, ok := ProfileByName(name)
	if !ok {
		return FullRun{}, fmt.Errorf("unknown profile %q", name)
	}
	if opt.RunID == "" {
		opt.RunID = fmt.Sprintf("B4X-VR-%s", time.Now().UTC().Format("20060102T150405"))
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now().UTC()
	}

	caps := spec.Capabilities
	if name == ProfileFullB4X {
		caps = append([]string(nil), FullRunOrder...)
	}
	schedule, err := CapabilityExecutionSchedule(caps)
	if err != nil {
		return FullRun{}, err
	}

	run := FullRun{
		Profile:           name,
		RunID:             opt.RunID,
		DeclaredWARPScope: spec.DeclaredWARPScope,
		CleanupComplete:   !spec.RequiresField || opt.CleanupLedger,
	}

	host, hostArts := hostRegistryStage(opt)
	run.Results = append(run.Results, host)
	run.BundleArtifacts = append(run.BundleArtifacts, hostArts...)

	if name == ProfileDetectorDeep || name == ProfileFullB4X {
		run.Results = append(run.Results, iv18HostStage(opt))
	}

	capVerdicts := map[string]Verdict{}
	for _, id := range schedule {
		hostStage := capabilityHostStage(id)
		run.Results = append(run.Results, hostStage)
		fieldStage := capabilityFieldStage(id, spec, opt)
		run.Results = append(run.Results, fieldStage)
		// Capability aggregation uses the stricter of host/field.
		v := hostStage.Verdict
		if fieldStage.Verdict != Pass && fieldStage.Verdict != PassWithLimitations && fieldStage.Verdict != NotApplicable {
			v = fieldStage.Verdict
		}
		if blocked := CapabilityUpstreamBlocked(id, capVerdicts); len(blocked) > 0 && v == Pass {
			v = Blocked
			fieldStage.Limitations = append(fieldStage.Limitations, "upstream blocked: "+joinComma(blocked))
		}
		capVerdicts[id] = v
	}

	if spec.DeclaredWARPScope {
		run.WARP = WARPVerdicts{
			Base:       fieldOrBlocked(opt, "WARP_BASE_TRANSPORT_READY"),
			Camouflage: fieldOrBlocked(opt, "WARP_CAMOUFLAGE_READY"),
			NonRU:      fieldOrBlocked(opt, "WARP_NON_RU_READY"),
			Causal:     fieldOrBlocked(opt, "WARP_CAUSAL_TRACE_READY"),
		}
		if name == ProfileWARPCausalTrace {
			// Nested/non-RU are optional for the base causal profile.
			run.WARP.Camouflage = NotApplicable
			run.WARP.NonRU = NotApplicable
		}
	}

	for _, art := range evidenceArtifactsFromDir(opt.EvidenceDir) {
		run.BundleArtifacts = append(run.BundleArtifacts, art)
	}
	return run, nil
}

func fieldOrBlocked(opt RunOptions, claim string) Verdict {
	if hasNamedEvidence(opt.EvidenceDir, claim) {
		return Pass
	}
	return Blocked
}

func hostRegistryStage(opt RunOptions) (StageResult, []Artifact) {
	arts := generatedRegistryArtifacts()
	reqs := []string{
		"source-stage-registry",
		"principal-verdicts",
		"capability-deps",
		"hard-gates",
		"false-pass-guard",
	}
	tests := []string{
		"ValidateSourceStageRegistry",
		"ValidatePrincipalVerdictRegistry",
		"ValidateCapabilityDependencyRegistry",
		"RunMetaSuite",
		"DetectFalsePass",
	}
	st := StageResult{
		Stage:        "host-registry",
		Requirements: reqs,
		Tests:        tests,
	}
	for _, a := range arts {
		st.Artifacts = append(st.Artifacts, a.Name+"="+a.SHA256)
	}

	var errs []string
	errs = append(errs, ValidateSourceStageRegistry()...)
	errs = append(errs, ValidatePrincipalVerdictRegistry()...)
	errs = append(errs, ValidateCapabilityDependencyRegistry()...)
	meta := RunMetaSuite(arts)
	if !meta.RegistryComplete || !meta.APIParity || !meta.VerdictMutationDetected || !meta.InfrastructureSafe {
		errs = append(errs, "meta-suite incomplete")
	}
	if !DetectFalsePass(StageResult{Stage: "mutant", Verdict: Pass}) {
		errs = append(errs, "DetectFalsePass failed to catch empty PASS")
	}
	if len(arts) == 0 {
		st.Verdict = BlockedMissingArtifact
		st.Limitations = []string{"generated registry artifacts unreadable"}
		return st, arts
	}
	if len(errs) > 0 {
		st.Verdict = Fail
		st.Limitations = errs
		return st, arts
	}
	st.Verdict = Pass
	return st, arts
}

func iv18HostStage(opt RunOptions) StageResult {
	res := RunIV18Suite()
	st := StageResult{
		Stage:        "iv-18",
		Requirements: []string{IV18SuiteID},
		Tests:        []string{"RunIV18Suite"},
		Artifacts:    []string{"iv18-suite"},
	}
	switch res.Verdict {
	case Pass, PassWithLimitations, Fail, Blocked, NotApplicable:
		st.Verdict = res.Verdict
	default:
		st.Verdict = Blocked
	}
	if len(res.MissingCoverage) > 0 {
		st.Limitations = append(st.Limitations, "missing coverage: "+joinComma(res.MissingCoverage))
	}
	if !opt.RouterReachable {
		st.Limitations = append(st.Limitations, "FT-MON-A..J field projections remain unit-mapped until Keenetic evidence exists")
	}
	return st
}

func capabilityHostStage(id string) StageResult {
	c, ok := CapabilityByID(id)
	arts := generatedRegistryArtifacts()
	st := StageResult{
		Stage:        id + "-host",
		Requirements: []string{id},
		Tests:        []string{"CapabilityByID", "CapabilityExecutionSchedule"},
		Dependencies: append([]string(nil), c.Requires...),
	}
	for _, a := range arts {
		if a.Name == "capability_deps.gen.go" || a.Name == "hard_gates_registry.gen.go" {
			st.Artifacts = append(st.Artifacts, a.Name+"="+a.SHA256)
		}
	}
	if !ok {
		st.Verdict = Fail
		st.Limitations = []string{"unknown capability"}
		return st
	}
	if len(st.Artifacts) == 0 {
		st.Verdict = BlockedMissingArtifact
		return st
	}
	st.Verdict = Pass
	return st
}

func capabilityFieldStage(id string, spec ProfileSpec, opt RunOptions) StageResult {
	st := StageResult{
		Stage:        id + "-field",
		Requirements: []string{id + "-keenetic-android"},
		Dependencies: []string{id + "-host"},
	}
	if hasNamedEvidence(opt.EvidenceDir, id) {
		st.Tests = []string{"field-evidence:" + id}
		st.Artifacts = []string{filepath.Join(opt.EvidenceDir, id)}
		st.Verdict = Pass
		return st
	}
	st.Tests = []string{"field-evidence-absent"}
	st.Verdict = Blocked
	st.Limitations = []string{"no immutable field evidence for capability " + id}
	if spec.RequiresAndroid && !opt.AndroidPresent {
		st.Limitations = append(st.Limitations, "ADB device not present")
	}
	if spec.RequiresField && !opt.RouterReachable {
		st.Limitations = append(st.Limitations, "router API not authenticated or RC not deployed")
	}
	return st
}

func hasNamedEvidence(dir, name string) bool {
	if dir == "" || name == "" {
		return false
	}
	candidates := []string{
		filepath.Join(dir, name),
		filepath.Join(dir, name+".json"),
		filepath.Join(dir, name+".PASS"),
		filepath.Join(dir, "VERDICTS.json"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			// VERDICTS.json is not proof of a named claim by itself.
			if filepath.Base(p) == "VERDICTS.json" {
				continue
			}
			return true
		}
	}
	return false
}

func evidenceArtifactsFromDir(dir string) []Artifact {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Artifact
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		sum, size, err := hashFile(path)
		if err != nil {
			continue
		}
		out = append(out, Artifact{Name: e.Name(), SHA256: sum, Kind: "field-evidence", Size: size, Redacted: true})
	}
	return out
}

func generatedRegistryArtifacts() []Artifact {
	dir := packageDir()
	names := []string{
		"hard_gates_registry.gen.go",
		"principal_verdicts.gen.go",
		"capability_deps.gen.go",
		"source_stage_registry.gen.go",
	}
	var out []Artifact
	for _, name := range names {
		sum, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		out = append(out, Artifact{Name: name, SHA256: sum, Kind: "sha256", Size: size, Redacted: true})
	}
	return out
}

func packageDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	dir := filepath.Dir(file)
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir
	}
	// Prebuilt binaries embed the build-time path (e.g. /src/src/validation),
	// which does not exist on the operator host. Fall back to locating the
	// validation package under the working directory (repo layout or cwd).
	if p, ok := findValidationDir(); ok {
		return p
	}
	return "."
}

// findValidationDir locates the validation package relative to cwd: it walks
// up to the repository root (src/validation) and also accepts a bare
// validation/ directory under cwd.
func findValidationDir() (string, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for d := cwd; ; d = filepath.Dir(d) {
		p := filepath.Join(d, "src", "validation")
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p, true
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
	}
	if st, err := os.Stat(filepath.Join(cwd, "validation")); err == nil && st.IsDir() {
		return filepath.Join(cwd, "validation"), true
	}
	return "", false
}

func hashFile(path string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data)), nil
}

func joinComma(in []string) string {
	if len(in) == 0 {
		return ""
	}
	out := in[0]
	for i := 1; i < len(in); i++ {
		out += "," + in[i]
	}
	return out
}

// ResolveCapabilityAlias maps a CLI capability spelling to a registry id.
func ResolveCapabilityAlias(name string) (string, bool) {
	if _, ok := CapabilityByID(name); ok {
		return name, true
	}
	if id, ok := CapabilityAliases[name]; ok {
		if _, exists := CapabilityByID(id); exists {
			return id, true
		}
	}
	return "", false
}

// HostPreflight is the L0/L1 static gate used by `b4-validate preflight`.
type HostPreflight struct {
	CheckedAt                   time.Time `json:"checked_at"`
	SourceStageConsistent       bool      `json:"source_stage_consistent"`
	PrincipalVerdictsConsistent bool      `json:"principal_verdicts_consistent"`
	CapabilityGraphConsistent   bool      `json:"capability_graph_consistent"`
	MetaReady                   bool      `json:"meta_ready"`
	FalsePassGuard              bool      `json:"false_pass_guard"`
	ArtifactCount               int       `json:"artifact_count"`
	Errors                      []string  `json:"errors,omitempty"`
}

func (p HostPreflight) Ready() bool {
	return p.SourceStageConsistent && p.PrincipalVerdictsConsistent &&
		p.CapabilityGraphConsistent && p.MetaReady && p.FalsePassGuard &&
		p.ArtifactCount > 0 && len(p.Errors) == 0
}

// RunHostPreflight executes registry integrity and the false-PASS mutant.
func RunHostPreflight() HostPreflight {
	arts := generatedRegistryArtifacts()
	p := HostPreflight{CheckedAt: time.Now().UTC(), ArtifactCount: len(arts)}
	srcErrs := ValidateSourceStageRegistry()
	pvErrs := ValidatePrincipalVerdictRegistry()
	capErrs := ValidateCapabilityDependencyRegistry()
	p.SourceStageConsistent = len(srcErrs) == 0
	p.PrincipalVerdictsConsistent = len(pvErrs) == 0
	p.CapabilityGraphConsistent = len(capErrs) == 0
	p.Errors = append(p.Errors, srcErrs...)
	p.Errors = append(p.Errors, pvErrs...)
	p.Errors = append(p.Errors, capErrs...)
	meta := RunMetaSuite(arts)
	p.MetaReady = meta.RegistryComplete && meta.APIParity && meta.VerdictMutationDetected && meta.InfrastructureSafe && meta.FalseNegativeDetected
	if !p.MetaReady {
		p.Errors = append(p.Errors, "meta-suite not ready")
	}
	p.FalsePassGuard = DetectFalsePass(StageResult{Stage: "mutant", Verdict: Pass})
	if !p.FalsePassGuard {
		p.Errors = append(p.Errors, "false-pass guard failed")
	}
	if p.ArtifactCount == 0 {
		p.Errors = append(p.Errors, "no generated registry artifacts")
	}
	return p
}
