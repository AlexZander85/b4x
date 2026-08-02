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
// applier (verified: src/watchdog/applier.go:18, caller watchdog_heal.go:111).
const legacyMutatingCall = "applyBatchResults"

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
// (kind current_generation_readiness_input, promotion blocker): PASS only
// while the legacy mutating path is unreachable from production code.
func MonProductionReady() bool {
	return IV18ReverseReachability("").ProductionReady
}
