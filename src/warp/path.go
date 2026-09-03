package warp

// Path-proof evidence types for the WARP route/path lifecycle (addendum v1.2
// §62.2 route and path proof, §62.3 forwarded-flow correlation, §62.6 DNS and
// IPv6 path proof). These are the minimal normative subsets the production
// layer validates on the violating branches of path_runtime.go; the full
// evidence contracts live in the field-test layer (src/fieldtest).

// TransportPathProof is the path-proof event of one significant probe
// (§62.2). Route/rule existence is NOT path proof: the proof must carry a
// positive counter delta and must not observe direct WAN or recursion.
type TransportPathProof struct {
	ProofID   string
	ProofKind string // router | forwarded | inner-control | geo | dns | ipv6 | target

	ExpectedSessionGen uint64
	ExpectedRouteGen   uint64

	CounterBeforePackets uint64
	CounterAfterPackets  uint64

	DirectWANObserved      bool
	RecursiveRouteObserved bool
	Passed                 bool
}

// ForwardedFlowCorrelation is the forwarded Android/LAN flow correlation
// (§62.3). Real client proof MUST form one causal chain that includes
// BindingID -> RouteTokenID -> PathProofID; a router-origin probe cannot
// satisfy forwarded-client proof.
type ForwardedFlowCorrelation struct {
	BindingID    string
	RouteTokenID string
	PathProofID  string

	RouterOrigin bool
}

// DNSPathTrace is the DNS path proof event (§62.6). The observed resolver
// path must equal the expected path and must not observe direct WAN.
type DNSPathTrace struct {
	PathID       string
	ExpectedPath string
	ObservedPath string

	DirectWANObserved bool
	Passed            bool
}

// IPFamilyPathTrace is the IPv6 path proof event (§62.6). A strict non-RU
// route requires a current independent IPv6 path proof (or IPv6 disabled for
// the exact selected scope) with no direct WAN observation.
type IPFamilyPathTrace struct {
	PathID string
	Family string

	DirectWANObserved bool
	Passed            bool
}
