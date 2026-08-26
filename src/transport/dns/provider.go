package dnspath

import (
	"context"
	"time"
)

// DNSPathCapabilities describes what a provider can do right now.
type DNSPathCapabilities struct {
	State           CapabilityState `json:"state"`
	Reason          string          `json:"reason,omitempty"`
	IPv4            bool            `json:"ipv4"`
	IPv6            bool            `json:"ipv6"`
	DNSSEC          bool            `json:"dnssec"`
	MultiResponse   bool            `json:"multi_response"` // UDP race observation
	Segmentation    bool            `json:"segmentation"`   // proven on-wire TCP segmentation
	ProviderVersion string          `json:"provider_version,omitempty"`
}

// DNSProbeQuery is one diagnostic query from the canonical suite.
type DNSProbeQuery struct {
	Name        string        `json:"-"` // never exported raw
	NameHash    string        `json:"name_hash"`
	QType       uint16        `json:"qtype"`
	SuiteCase   string        `json:"suite_case"` // A | AAAA | CNAME | HTTPS | NXDOMAIN | SERVFAIL | TRUNCATION | MULTI | DNSSEC_VALID | DNSSEC_BOGUS | CONTROL_SAME | CONTROL_UNRELATED
	Timeout     time.Duration `json:"timeout"`
	ObserveRace bool          `json:"observe_race,omitempty"`
}

// DNSQuery is a production resolution request.
type DNSQuery struct {
	Name     string `json:"-"`
	NameHash string `json:"name_hash"`
	QType    uint16 `json:"qtype"`
	TxID     uint16 `json:"txid"`
}

// DNSResponse is the normalized provider response envelope.
type DNSResponse struct {
	Payload       []byte              `json:"-"`
	Fingerprint   ResponseFingerprint `json:"fingerprint"`
	RCode         int                 `json:"rcode"`
	Truncated     bool                `json:"truncated"`
	Latency       time.Duration       `json:"latency"`
	FromCache     bool                `json:"from_cache"`
	ResponseCount uint16              `json:"response_count"`
}

// DNSPathHealth is the provider health snapshot (addendum §79 axes feed the
// manager-level composition).
type DNSPathHealth struct {
	State          CapabilityState `json:"state"`
	LastSuccess    time.Time       `json:"last_success,omitempty"`
	LastFailure    time.Time       `json:"last_failure,omitempty"`
	ConsecutiveErr int             `json:"consecutive_errors"`
	LatencyEWMA    time.Duration   `json:"latency_ewma"`
}

// PreparedDNSPath is the provider-prepared handle for one path generation.
type PreparedDNSPath struct {
	PathID     DNSPathID `json:"path_id"`
	Generation uint64    `json:"generation"`
	PreparedAt time.Time `json:"prepared_at"`
	// Handle is provider-private runtime state (listener, client, process).
	Handle any `json:"-"`
}

// DNSPrepareRequest carries preparation context.
type DNSPrepareRequest struct {
	Generation       uint64
	NetworkContextID string
	RuntimeEpoch     string
	Diagnostic       bool // diagnostic instance: cache off, ephemeral
}

// DNSPathProvider is the common provider contract (addendum §31). A provider
// never selects itself and never performs promotion.
type DNSPathProvider interface {
	ID() DNSPathID
	Capabilities() DNSPathCapabilities

	Prepare(ctx context.Context, req DNSPrepareRequest) (PreparedDNSPath, error)
	Probe(ctx context.Context, prepared PreparedDNSPath, q DNSProbeQuery) (DNSPathProbeOutcome, error)
	Resolve(ctx context.Context, prepared PreparedDNSPath, q DNSQuery) (DNSResponse, error)
	Health(ctx context.Context, prepared PreparedDNSPath) DNSPathHealth
	Retire(ctx context.Context, prepared PreparedDNSPath) error
}
