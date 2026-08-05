// Production nested-WARP hard-gate producers (§73B nested block, addendum
// v1.2 §62.4 "Nested WARP dependency graph").
//
// Like the §72 producers in runtime.go, the violating branches below are the
// production violation paths of the nested lifecycle: a count != 0 in a
// validation window is a genuine nested-WARP violation, not synthetic
// telemetry. Promotion of a child route is only legal when all of the
// §62.4 rules hold:
//
//   - child promotion requires a current healthy parent link;
//   - parent reconnect invalidates the child link until revalidated against
//     the new parent SessionGen;
//   - the child cannot use a parent route token from a retired generation;
//   - inner control MUST traverse the inner control path (mark applied),
//     never a direct base-path leak.
package warp

import (
	"errors"

	"github.com/daniellavrushin/b4/observability"
)

// NestedPromote activates a child route through its parent dependency link.
// Violating branches (in evaluation order) increment exactly one
// warp_nested_* counter each:
//
//  1. no current parent link           -> warp_nested_missing_parent_link_total;
//  2. parent link not healthy          -> warp_nested_route_active_without_parent_health_total;
//  3. parent generation mismatch       -> warp_nested_parent_generation_mismatch_total.
//
// parentSessionGen is the parent SessionGen the promotion claims; it must
// equal the generation the link was revalidated against (§62.4 rule:
// "parent reconnect invalidates child link until revalidated against new
// parent SessionGen").
func (rt *Runtime) NestedPromote(b *NestedBackend, parentSessionGen uint64) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if b == nil || !b.Link.Valid || b.Link.ParentSession == "" {
		observability.Default().Metrics.Inc(observability.MetricWarpNestedMissingParentLink, nil, 1)
		return errors.New("nested route promotion without parent link")
	}
	if !b.Link.ParentHealthy {
		observability.Default().Metrics.Inc(observability.MetricWarpNestedRouteActiveWithoutParentHealth, nil, 1)
		return errors.New("nested route promotion with unhealthy parent")
	}
	if !b.Link.Revalidated || b.Link.ParentSessionGen != parentSessionGen {
		observability.Default().Metrics.Inc(observability.MetricWarpNestedParentGenerationMismatch, nil, 1)
		return errors.New("nested route promotion with mismatched parent generation")
	}
	return nil
}

// NestedUseParentToken binds a child route to a parent route token. A token
// from a retired generation (the link was revalidated against a newer parent
// generation) must never be used (§62.4 rule: "child cannot use parent route
// token from retired generation") -> warp_nested_stale_parent_token_total.
func (rt *Runtime) NestedUseParentToken(b *NestedBackend, parentRouteID string, parentRouteGen uint64) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if b == nil || !b.Link.Valid {
		observability.Default().Metrics.Inc(observability.MetricWarpNestedMissingParentLink, nil, 1)
		return errors.New("parent token use without parent link")
	}
	if b.Link.ParentRouteID != parentRouteID || b.Link.ParentRouteGen != parentRouteGen {
		observability.Default().Metrics.Inc(observability.MetricWarpNestedStaleParentToken, nil, 1)
		return errors.New("stale parent route token")
	}
	return nil
}

// NestedControl routes one inner-control flow. Inner control MUST traverse
// the inner control path (inner-control mark applied, §62.4 event
// warp_inner_control_mark_applied / warp_inner_control_entered_base); a flow
// that enters the base path directly without the inner mark is a control
// leak -> warp_nested_control_direct_leak_total.
func (rt *Runtime) NestedControl(innerMarkApplied bool) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	if !innerMarkApplied {
		observability.Default().Metrics.Inc(observability.MetricWarpNestedControlDirectLeak, nil, 1)
		return errors.New("inner control direct leak into base path")
	}
	return nil
}
