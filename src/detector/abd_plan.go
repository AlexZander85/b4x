package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type TargetRole string

const (
	RoleUserTarget         TargetRole = "user-target"
	RoleSameServiceControl TargetRole = "same-service-control"
	RoleUnrelatedControl   TargetRole = "unrelated-control"
	RoleCleanBaseline      TargetRole = "clean-baseline"
)

type UserTargetSelection struct {
	SelectionID      string
	ServiceProfileID string
	ComponentID      string
	Domains          []string
	URLs             []string
	MaxTargets       int
}

type PlannedTarget struct {
	ID, Host, URL, ComponentID string
	Role                       TargetRole
	Scope                      monitor.MonitorScopeKey
}
type DiagnosticBudget struct {
	QuickTargets, DeepTargets int
	MaxAttempts               int
	Deadline                  time.Duration
}

func DefaultDiagnosticBudget() DiagnosticBudget {
	return DiagnosticBudget{QuickTargets: 8, DeepTargets: 32, MaxAttempts: 3, Deadline: 2 * time.Minute}
}

type DiagnosticTargetPlan struct {
	PlanID           string
	Scope            monitor.MonitorScopeKey
	Targets          []PlannedTarget
	Controls         []PlannedTarget
	Budget           DiagnosticBudget
	CompiledAt       time.Time
	OverlayRequestID string
}

type TargetPlanCompileReport struct {
	Accepted          bool
	Plan              DiagnosticTargetPlan
	Rejections        []string
	PreservedControls int
}

func targetHash(scope monitor.MonitorScopeKey, value string) string {
	h := sha256.Sum256([]byte(scope.NetworkContextID + ":" + value))
	return hex.EncodeToString(h[:8])
}

func CompileDiagnosticTargetPlan(sel UserTargetSelection, req monitor.MonitorDiagnosticRequest, now time.Time) TargetPlanCompileReport {
	r := TargetPlanCompileReport{Plan: DiagnosticTargetPlan{Scope: req.Overlay.Scope, CompiledAt: now, OverlayRequestID: req.RequestID, Budget: DefaultDiagnosticBudget()}}
	if sel.ServiceProfileID == "" || sel.ComponentID == "" {
		r.Rejections = append(r.Rejections, "service profile and component are required")
	}
	if !req.Valid(now) || req.Overlay.Scope != req.Lease.Request.Scope {
		r.Rejections = append(r.Rejections, "invalid or mismatched monitor request")
	}
	max := sel.MaxTargets
	if max <= 0 {
		max = 16
	}
	if max > 64 {
		max = 64
	}
	seen := map[string]bool{}
	add := func(raw string, role TargetRole) {
		if len(r.Plan.Targets)+len(r.Plan.Controls) >= max {
			return
		}
		if raw == "" || seen[raw] {
			return
		}
		seen[raw] = true
		r.Plan.Targets = append(r.Plan.Targets, PlannedTarget{ID: targetHash(req.Overlay.Scope, raw), Host: raw, URL: raw, ComponentID: sel.ComponentID, Role: role, Scope: req.Overlay.Scope})
	}
	for _, d := range sel.Domains {
		add(d, RoleUserTarget)
	}
	for _, u := range sel.URLs {
		add(u, RoleUserTarget)
	}
	if len(r.Plan.Targets) == 0 {
		r.Rejections = append(r.Rejections, "at least one bounded user target is required")
	}
	// Controls are mandatory and intentionally separate from action scope.
	for i, h := range req.Overlay.ControlHashes {
		if h == "" {
			continue
		}
		r.Plan.Controls = append(r.Plan.Controls, PlannedTarget{ID: h, Host: "control-" + h, ComponentID: sel.ComponentID, Role: RoleSameServiceControl, Scope: req.Overlay.Scope})
		if i >= 3 {
			break
		}
	}
	if len(r.Plan.Controls) == 0 {
		r.Rejections = append(r.Rejections, "same-service control is required")
	}
	r.Plan.Controls = append(r.Plan.Controls, PlannedTarget{ID: targetHash(req.Overlay.Scope, "clean-baseline"), Host: "clean-baseline", ComponentID: sel.ComponentID, Role: RoleCleanBaseline, Scope: req.Overlay.Scope})
	r.PreservedControls = len(r.Plan.Controls)
	r.Plan.PlanID = targetHash(req.Overlay.Scope, sel.SelectionID+sel.ComponentID)
	if len(r.Rejections) == 0 {
		r.Accepted = true
	}
	return r
}

func (p DiagnosticTargetPlan) Valid() bool {
	if p.PlanID == "" || !p.Scope.Valid() || len(p.Targets) == 0 || len(p.Controls) < 2 {
		return false
	}
	for _, t := range append(append([]PlannedTarget{}, p.Targets...), p.Controls...) {
		if t.Scope != p.Scope || t.ID == "" || t.Role == "" {
			return false
		}
	}
	return true
}

var ErrInvalidTargetPlan = errors.New("invalid diagnostic target plan")

func (p DiagnosticTargetPlan) QuickTargets() []PlannedTarget {
	n := p.Budget.QuickTargets
	if n <= 0 || n > len(p.Targets) {
		n = len(p.Targets)
	}
	out := append([]PlannedTarget(nil), p.Targets[:n]...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
