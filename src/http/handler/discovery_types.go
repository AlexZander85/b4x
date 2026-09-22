package handler

import "github.com/daniellavrushin/b4/monitor"

// DiscoveryAdaptiveSynthesisRequest is the AFS §76 run-request extension. The
// server denies Allowed=true whenever the global opt-in is off; it never
// silently accepts the field.
type DiscoveryAdaptiveSynthesisRequest struct {
	Allowed       bool   `json:"allowed"`
	Trigger       string `json:"trigger,omitempty"`
	MaxCandidates uint16 `json:"max_candidates,omitempty"`
}

type DiscoveryRequest struct {
	CheckURL        string   `json:"check_url,omitempty"`
	CheckURLs       []string `json:"check_urls,omitempty"`
	SkipDNS         bool     `json:"skip_dns,omitempty"`
	SkipCache       bool     `json:"skip_cache,omitempty"`
	PayloadFiles    []string `json:"payload_files,omitempty"`
	ValidationTries int      `json:"validation_tries,omitempty"`
	TLSVersion      string   `json:"tls_version,omitempty"` // "auto", "tls12", "tls13"
	IPVersion       string   `json:"ip_version,omitempty"`  // "auto", "ipv4", "ipv6"

	// AFS §76: optional exact scope and bounded-synthesis request. Scope is the
	// canonical Monitor/Discovery scope; when adaptive synthesis is requested the
	// server checks the global opt-in against its service profile.
	Scope             *monitor.MonitorScopeKey           `json:"scope,omitempty"`
	AdaptiveSynthesis *DiscoveryAdaptiveSynthesisRequest `json:"adaptive_synthesis,omitempty"`
}

type DiscoveryResponse struct {
	Id             string   `json:"id"`
	Domain         string   `json:"domain"`
	Domains        []string `json:"domains,omitempty"`
	CheckURL       string   `json:"check_url"`
	EstimatedTests int      `json:"estimated_tests"`
	Message        string   `json:"message"`
}
