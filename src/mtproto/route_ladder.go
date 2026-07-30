package mtproto

type BridgeRoute string

const (
	RoutePrimary BridgeRoute = "primary"
	RouteWorker  BridgeRoute = "worker"
	RouteDirect  BridgeRoute = "direct"
)

type RouteAttempt struct {
	Route   BridgeRoute
	Success bool
	Reason  BridgeReason
}
type RoutePlan struct {
	Attempts       []BridgeRoute
	RecursionGuard bool
	Terminal       BridgeReason
}

func DefaultRoutePlan() RoutePlan {
	return RoutePlan{Attempts: []BridgeRoute{RoutePrimary, RouteWorker, RouteDirect}, RecursionGuard: true}
}
func ExecuteRoutePlan(p RoutePlan, dial func(BridgeRoute) error) RouteAttempt {
	for _, r := range p.Attempts {
		if p.RecursionGuard && r == RoutePrimary {
			if err := dial(r); err == nil {
				return RouteAttempt{Route: r, Success: true}
			} else {
				p.Terminal = ReasonDialFailed
			}
		} else if err := dial(r); err == nil {
			return RouteAttempt{Route: r, Success: true}
		}
	}
	return RouteAttempt{Route: p.Attempts[len(p.Attempts)-1], Reason: p.Terminal}
}
