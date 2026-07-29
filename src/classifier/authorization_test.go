package classifier

import (
	"net/netip"
	"testing"
	"time"
)

func TestCaptureCandidateRequiresScopedAuthorization(t *testing.T) {
	now := time.Unix(1000, 0)
	client := testClient()
	flow := NewFlowKey(client, client.SourceIP, netip.MustParseAddr("203.0.113.10"), 51000, 443, 6)
	base := Evidence{Client: client, DestinationIP: netip.MustParseAddr("203.0.113.10"), DestinationPort: 443, L4Proto: 6, SetID: "youtube", ConfigGen: 9, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	candidateEvidence := base
	candidateEvidence.Source = EvidenceStaticIP
	candidate := CandidateFromEvidence(flow, candidateEvidence)
	if _, ok := AuthorizeCandidate(candidate, candidateEvidence, DomainPolicyScopedHints, true, now); ok {
		t.Fatal("static IP directly authorized a domain-scoped action")
	}
	clear := base
	clear.Source, clear.Domain, clear.DomainEvidence, clear.Confidence = EvidencePacketSNI, "youtube.com", true, 98
	auth, ok := AuthorizeCandidate(candidate, clear, DomainPolicyStrict, true, now)
	if !ok || auth.SetID != "youtube" || auth.FlowKey != flow.Normalize() {
		t.Fatalf("clear SNI authorization = %+v ok=%v", auth, ok)
	}
}

func TestScopedHintsAndScopeMismatch(t *testing.T) {
	now := time.Unix(1100, 0)
	client := testClient()
	dst := netip.MustParseAddr("203.0.113.11")
	flow := NewFlowKey(client, client.SourceIP, dst, 51001, 443, 6)
	e := Evidence{Source: EvidenceDNSAnswer, Client: client, DestinationIP: dst, DestinationPort: 443, L4Proto: 6, Domain: "api.youtube.com", SetID: "youtube", Confidence: 89, DomainEvidence: true, CreatedAt: now, ExpiresAt: now.Add(time.Minute), ConfigGen: 11}
	candidate := CandidateFromEvidence(flow, Evidence{Source: EvidenceStaticIP, Client: client, DestinationIP: dst, DestinationPort: 443, L4Proto: 6, SetID: "youtube", ConfigGen: 11})
	if _, ok := AuthorizeCandidate(candidate, e, DomainPolicyStrict, true, now); ok {
		t.Fatal("DNS hint authorized strict policy")
	}
	auth, ok := AuthorizeCandidate(candidate, e, DomainPolicyScopedHints, true, now)
	if !ok {
		t.Fatal("fresh scoped DNS hint did not authorize scoped-hints")
	}
	other := client
	other.SourceIP = netip.MustParseAddr("192.0.2.99")
	if auth.ValidFor(flow, other, "youtube", 11, 443, 6, now) {
		t.Fatal("authorization reused by another client")
	}
	if auth.ValidFor(NewFlowKey(client, client.SourceIP, dst, 51002, 443, 6), client, "youtube", 11, 443, 6, now) {
		t.Fatal("authorization reused by another flow")
	}
	if auth.ValidFor(flow, client, "youtube", 12, 443, 6, now) {
		t.Fatal("authorization survived generation mismatch")
	}
}
