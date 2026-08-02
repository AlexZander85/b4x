package validation

// FB-28 (b4x-pp4) IV-18-MON-09 / FT-MON-I: reverse reachability of the
// legacy Watchdog mutating path.
//
// MON_PRODUCTION_READY (gate mon_production_ready, family mon, stage
// cutover) must be impossible while the legacy mutating path
// (src/watchdog/applier.go -> applyBatchResults, invoked from
// watchdog_heal.go) is reachable from non-test production code. Passive
// observation must never be able to mutate configuration, so cutover can
// only be declared when that path is gone.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// ReachabilityHit is one production (non-test) call site of the legacy
// mutating symbol.
type ReachabilityHit struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// ReverseReachabilityResult is the static scan result for the legacy
// mutating path.
type ReverseReachabilityResult struct {
	LegacyMutatingPath string            `json:"legacy_mutating_path"`
	Hits               []ReachabilityHit `json:"hits,omitempty"`
	ProductionReady    bool              `json:"production_ready"`
	ScannedFiles       int               `json:"scanned_files"`
}

// legacyMutatingCall is the canonical mutating symbol of the legacy Watchdog
// applier (verified: src/watchdog/applier.go:18, caller watchdog_heal.go:111;
// removed by the FB-28 authoritative cutover 2026-08-02).
const legacyMutatingCall = "applyBatchResults"

// productionCallExists reports whether the named (package-qualified) symbol
// is invoked from any non-test Go file under the repository src/ tree
// (AST-based, same technique as IV18ReverseReachability). Qualifiers keep
// the probe honest: "monitor.NewObservationBus" must not match the unrelated
// ppe.NewObservationBus already present in production. Used as a real
// availability probe for production dependencies.
//
// The scan is cached: walking and parsing the tree once serves every
// dependency probe of the current process.
func productionCallExists(ref string) bool {
	hits := productionCalls()
	_, ok := hits[ref]
	return ok
}

var productionCallsOnce sync.Once
var productionCallHits map[string]bool

// productionCalls returns the set of package-qualified callable symbol names
// observed in non-test Go files under src/. The tree walk and parse happen
// exactly once per process; individual dependency probes then hit the
// in-memory set.
func productionCalls() map[string]bool {
	productionCallsOnce.Do(func() {
		hits := map[string]bool{}
		for _, path := range productionGoFiles() {
			parseAndCollectCalls(path, hits)
		}
		productionCallHits = hits
	})
	return productionCallHits
}

// productionGoFiles returns non-test Go file paths under src/ (bounded to
// guard against pathological recursion; the repository tree is far below the
// cap).
func productionGoFiles() []string {
	root := srcRoot()
	if root == "" {
		return nil
	}
	var files []string
	const maxFiles = 20000
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || len(files) >= maxFiles {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files
}

// parseAndCollectCalls parses each production file once and flattens every
// call expression into its symbol name: for qualified calls
// (pkg.Symbol or recv.Method) it records both the qualified and the bare
// name so probes can match either precisely. Used only by productionCalls
// (via productionGoFiles + parse), keeping a single AST pass per file.
func parseAndCollectCalls(path string, set map[string]bool) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fun.Sel == nil {
				return true
			}
			set[fun.Sel.Name] = true
			if x, isIdent := fun.X.(*ast.Ident); isIdent {
				set[x.Name+"."+fun.Sel.Name] = true
			}
		case *ast.Ident:
			set[fun.Name] = true
		}
		return true
	})
}

// monitorV1APIRegistered reports whether a /api/monitor/v1 route string
// exists in the production HTTP handler layer (src/http/handler). The
// handler registers routes by patterns like "/api/monitor/v1"; a missing
// registration means the migration API is not yet deployed. The scan is
// restricted to the http handler directory so probe strings in validation
// comments can never self-match.
func monitorV1APIRegistered() bool {
	root := filepath.Join(srcRoot(), "http", "handler")
	if _, err := os.Stat(root); err != nil {
		return false
	}
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || found {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(data), `"/api/monitor/v1"`) {
			found = true
		}
		return nil
	})
	return found
}

// srcRoot derives the repository src/ directory from this package's location
// (src/validation), independent of the working directory.
func srcRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Dir(filepath.Dir(file))
}

// IV18ReverseReachability scans all non-test Go files under root ("" uses
// the repository src/ tree) for production call sites of the legacy mutating
// path. The AST-based scan matches real call expressions
// (CallExpr/Ident == legacyMutatingCall) and deliberately ignores the
// function declaration and string literals (e.g. this package's own probe
// constant). ProductionReady is true only when zero call sites remain.
func IV18ReverseReachability(root string) ReverseReachabilityResult {
	res := ReverseReachabilityResult{LegacyMutatingPath: "src/watchdog/applier.go " + legacyMutatingCall + "()"}
	if root == "" {
		root = srcRoot()
	}
	if root == "" {
		return res
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		res.ScannedFiles++
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fun, ok := call.Fun.(*ast.Ident)
			if !ok || fun.Name != legacyMutatingCall {
				return true
			}
			res.Hits = append(res.Hits, ReachabilityHit{File: rel, Line: fset.Position(call.Pos()).Line})
			return true
		})
		return nil
	})
	sort.Slice(res.Hits, func(i, j int) bool {
		if res.Hits[i].File != res.Hits[j].File {
			return res.Hits[i].File < res.Hits[j].File
		}
		return res.Hits[i].Line < res.Hits[j].Line
	})
	res.ProductionReady = len(res.Hits) == 0
	return res
}

// MonProductionReady implements the mon_production_ready readiness gate
// (kind current_generation_readiness_input, promotion blocker). It is
// fail-closed by construction: PASS only when the legacy mutating path is
// unreachable AND every production dependency of the monitoring cutover is
// present. Removing the legacy path alone never flips the gate to PASS while
// the production monitoring chain or /api/monitor/v1 is missing — the gate
// remains BLOCKED_BY_DEPENDENCY (owner decision 2026-08-02).
func MonProductionReady() bool {
	return IV18ReverseReachability("").ProductionReady && len(IV18ProductionDependenciesBlocked()) == 0
}

// ProductionDependency is one named prerequisite of the full MON_PRODUCTION_READY
// semantics (owner decision: legacy removal alone must never false-PASS the
// gate while production dependencies are missing).
type ProductionDependency struct {
	ID      string `json:"id"`
	Ready   bool   `json:"ready"`
	Missing string `json:"missing,omitempty"`
}

// IV18ProductionDependencies enumerates the production prerequisites of the
// monitoring cutover. Each check is a real availability probe over the
// production tree (http handlers, main wiring); a dependency stays
// not-ready until its production component exists and is wired. This keeps
// the gate fail-closed: with the legacy path removed but the production
// monitoring chain not yet integrated, mon_production_ready must report
// BLOCKED_BY_DEPENDENCY, never a false PASS.
func IV18ProductionDependencies() []ProductionDependency {
	deps := []ProductionDependency{
		{
			ID:      "monitoring_runtime_observation_bus",
			Ready:   productionCallExists("monitor.NewObservationBus"),
			Missing: "production ObservationBus wiring absent (src/monitor not called from production)",
		},
		{
			ID:      "monitoring_scheduler_production",
			Ready:   productionCallExists("monitor.NewDiagnosticScheduler"),
			Missing: "production diagnostic scheduler absent (src/monitor not called from production)",
		},
		{
			ID:      "abd_ddi_chain_production",
			Ready:   productionCallExists("detector.CompileBlockingProfile") && productionCallExists("monitor.BuildGuidedDiscovery"),
			Missing: "MON -> ABD -> DDI -> Discovery production chain not wired",
		},
		{
			ID:      "api_monitor_v1",
			Ready:   monitorV1APIRegistered(),
			Missing: "GET /api/monitor/v1 endpoint not registered",
		},
	}
	for i := range deps {
		if deps[i].Ready {
			deps[i].Missing = ""
		}
	}
	return deps
}

// IV18ProductionDependenciesBlocked lists the not-ready production
// dependencies (empty when all are satisfied).
func IV18ProductionDependenciesBlocked() []ProductionDependency {
	var blocked []ProductionDependency
	for _, d := range IV18ProductionDependencies() {
		if !d.Ready {
			blocked = append(blocked, d)
		}
	}
	return blocked
}
