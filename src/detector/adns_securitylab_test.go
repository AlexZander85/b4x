package detector

import (
	"context"
	"testing"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// securityLabProvider models the transparent UDP/53 interception described in
// the SecurityLab incident: the same apparent resolver identity is poisoned
// on UDP while TCP to that resolver remains correct. A second resolver
// identity is used as the independent truth source.
type securityLabProvider struct {
	id       dnspath.DNSPathID
	poisoned bool
}

func (p *securityLabProvider) ID() dnspath.DNSPathID { return p.id }
func (p *securityLabProvider) Capabilities() dnspath.DNSPathCapabilities {
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: true}
}
func (p *securityLabProvider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	return dnspath.PreparedDNSPath{PathID: p.id, Generation: req.Generation, PreparedAt: time.Now()}, nil
}
func (p *securityLabProvider) Retire(context.Context, dnspath.PreparedDNSPath) error { return nil }
func (p *securityLabProvider) Health(context.Context, dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapReady}
}
func (p *securityLabProvider) Resolve(context.Context, dnspath.PreparedDNSPath, dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	return dnspath.DNSResponse{}, nil
}
func (p *securityLabProvider) Probe(_ context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	out := dnspath.DNSPathProbeOutcome{
		PathID: prepared.PathID, QuerySuiteID: q.SuiteCase,
		Stage: dnspath.StageAnswer, Latency: 10 * time.Millisecond,
		ResponseCount: 1, ObservedAt: time.Now(),
	}
	if p.poisoned {
		// The injected answer is syntactically DNS but semantically contradicts
		// the requested positive/control cases and has no authority SOA proof.
		// Real providers classify this before quorum as RCODE_MISMATCH or
		// ANSWER_CONFLICT; either is poisoning evidence, never PASS_CORRECT.
		out.RCode = 3
		if q.SuiteCase == "NXDOMAIN" {
			out.Class = dnspath.OutcomeAnswerConflict
			out.FailureCode = "negative_without_authority_soa"
		} else {
			out.Class = dnspath.OutcomeRCodeMismatch
			out.FailureCode = "expected_positive_rcode"
		}
		return out, nil
	}
	out.Class = dnspath.OutcomeInconclusive
	switch q.SuiteCase {
	case "NXDOMAIN":
		out.RCode = 3
		out.EvidenceRefs = []string{"authority-soa"}
	case "CNAME":
		out.CNAMEFingerprint = "cname-good"
	case "HTTPS":
		out.HTTPSFingerprint = "https-good"
	default:
		out.AnswerFingerprint = "address-good"
	}
	return out, nil
}

func TestSecurityLabUDPInterceptionSelectsTCPBypass(t *testing.T) {
	victimUDP := &securityLabProvider{poisoned: true, id: dnspath.DNSPathID{
		Family: dnspath.DNSPathUDP, ResolverID: "resolver-victim", EndpointID: "victim-53",
		IPFamily: "ipv4", CatalogVersion: "securitylab-test",
	}}
	victimTCP := &securityLabProvider{id: dnspath.DNSPathID{
		Family: dnspath.DNSPathTCP, ResolverID: "resolver-victim", EndpointID: "victim-53",
		IPFamily: "ipv4", CatalogVersion: "securitylab-test",
	}}
	controlTCP := &securityLabProvider{id: dnspath.DNSPathID{
		Family: dnspath.DNSPathTCP, ResolverID: "resolver-control", EndpointID: "control-53",
		IPFamily: "ipv4", CatalogVersion: "securitylab-test",
	}}

	policy := dnspath.DefaultAdaptivePolicy()
	policy.Enabled = true
	policy.RequireNoLogClaim = false
	policy.RequireNoFilterClaim = false
	policy.RequireDNSSECCapable = false
	policy.Preference = dnspath.PreferenceMinimumDependency

	diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
		Providers: []dnspath.DNSPathProvider{victimUDP, victimTCP, controlTCP},
		Policy: policy,
		Suite: CanonicalSuite("blocked.example", "control.example"),
		Deep: true, AttemptsQuick: 2, AttemptsValid: 3,
		NetworkContext: "wan-securitylab", Generation: 1, RuntimeEpoch: "test",
		CatalogVersion: "securitylab-test", PolicyDigest: policy.Digest(), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !diag.PoisoningDetected {
		t.Fatal("repeated forged UDP NXDOMAIN must set poisoning evidence")
	}
	if diag.Profile == nil || diag.Profile.Status != dnspath.ProfileStatusReady {
		t.Fatalf("validated TCP paths must keep a READY bypass profile: %+v", diag.Profile)
	}
	if diag.Profile.Primary.Family != dnspath.DNSPathTCP {
		t.Fatalf("poisoned UDP must not remain primary; got %s", diag.Profile.Primary.Family)
	}
	for _, path := range append([]dnspath.DNSPathID{diag.Profile.Primary}, diag.Profile.Fallbacks...) {
		if path.Hash() == victimUDP.id.Hash() {
			t.Fatal("poisoned UDP path must not appear in selected production ladder")
		}
	}
	victimTCPPassed := false
	for _, out := range diag.Outcomes {
		if out.PathID.Hash() == victimTCP.id.Hash() && out.Class.Pass() {
			victimTCPPassed = true
		}
		if out.PathID.Hash() == victimUDP.id.Hash() && out.Class.Pass() {
			t.Fatalf("forged UDP evidence was incorrectly promoted: %+v", out)
		}
	}
	if !victimTCPPassed {
		t.Fatal("TCP to the same apparent resolver must remain usable when independently corroborated")
	}
}
