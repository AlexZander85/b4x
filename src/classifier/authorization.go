package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"time"
)

type CaptureCandidate struct {
	FlowKey         FlowKey
	Client          ClientKey
	CandidateSetID  string
	Source          EvidenceSource
	DestinationIP   netip.Addr
	DestinationPort uint16
	L4Proto         uint8
	ConfigGen       uint64
	Reason          string
}

type ActionAuthorization struct {
	ID             string
	FlowKey        FlowKey
	Client         ClientKey
	SetID          string
	Domain         string
	EvidenceSource EvidenceSource
	Confidence     uint8
	DomainPolicy   DomainPolicy
	ConfigGen      uint64
	Final          bool
	ExpiresAt      time.Time
}

func CandidateFromEvidence(flow FlowKey, evidence Evidence) CaptureCandidate {
	flow = flow.Normalize()
	client := evidence.Client
	if client.IsZero() {
		client = flow.Client
	}
	return CaptureCandidate{
		FlowKey: flow, Client: client, CandidateSetID: strings.TrimSpace(evidence.SetID), Source: evidence.Source,
		DestinationIP: evidence.DestinationIP, DestinationPort: evidence.DestinationPort,
		L4Proto: evidence.L4Proto, ConfigGen: evidence.ConfigGen, Reason: evidence.Reason,
	}
}

func (a ActionAuthorization) ValidFor(flow FlowKey, client ClientKey, setID string, configGen uint64, port uint16, proto uint8, now time.Time) bool {
	if strings.TrimSpace(a.SetID) == "" || strings.TrimSpace(a.SetID) != strings.TrimSpace(setID) {
		return false
	}
	if a.FlowKey.Normalize() != flow.Normalize() || (!client.IsZero() && a.Client != client) {
		return false
	}
	if configGen != 0 && a.ConfigGen != 0 && a.ConfigGen != configGen {
		return false
	}
	if port != 0 && a.FlowKey.DstPort != 0 && a.FlowKey.SrcPort != port && a.FlowKey.DstPort != port {
		return false
	}
	if proto != 0 && a.FlowKey.Proto != 0 && a.FlowKey.Proto != proto {
		return false
	}
	if !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt) {
		return false
	}
	return a.Final && a.Confidence > 0
}

func AuthorizeCandidate(candidate CaptureCandidate, evidence Evidence, policy DomainPolicy, final bool, now time.Time) (ActionAuthorization, bool) {
	evidence = NormalizeEvidence(evidence)
	if candidate.FlowKey.Normalize() == (FlowKey{}) || strings.TrimSpace(candidate.CandidateSetID) == "" ||
		candidate.CandidateSetID != evidence.SetID || !ValidForContext(evidence, DecisionContext{
		Now: now, Client: candidate.Client, ConfigGen: candidate.ConfigGen, DestinationPort: candidate.DestinationPort,
		L4Proto: candidate.L4Proto, FlowKey: candidate.FlowKey,
	}) {
		return ActionAuthorization{}, false
	}
	if evidence.Client.IsZero() || evidence.Client != candidate.Client || !evidence.DestinationIP.IsValid() ||
		(candidate.DestinationIP.IsValid() && candidate.DestinationIP != evidence.DestinationIP) {
		return ActionAuthorization{}, false
	}
	if !authorizationSourceAllowed(policy, evidence) {
		return ActionAuthorization{}, false
	}
	auth := ActionAuthorization{
		FlowKey: candidate.FlowKey.Normalize(), Client: candidate.Client, SetID: evidence.SetID, Domain: evidence.Domain,
		EvidenceSource: evidence.Source, Confidence: EffectiveConfidence(evidence), DomainPolicy: policy,
		ConfigGen: candidate.ConfigGen, Final: final, ExpiresAt: evidence.ExpiresAt,
	}
	auth.ID = authorizationID(auth)
	return auth, auth.ValidFor(candidate.FlowKey, candidate.Client, candidate.CandidateSetID, candidate.ConfigGen, candidate.DestinationPort, candidate.L4Proto, now)
}

func authorizationSourceAllowed(policy DomainPolicy, evidence Evidence) bool {
	if policy == DomainPolicyDisabled {
		return true
	}
	if !evidence.DomainEvidence || strings.TrimSpace(evidence.Domain) == "" {
		return false
	}
	switch policy {
	case DomainPolicyStrict, DomainPolicyLegacy, DomainPolicyInherit:
		return evidence.Source == EvidencePacketSNI || evidence.Source == EvidenceReassembledSNI || evidence.Source == EvidenceStaticHost
	case DomainPolicyScopedHints:
		switch evidence.Source {
		case EvidencePacketSNI, EvidenceReassembledSNI, EvidenceStaticHost, EvidenceQUICSNI, EvidenceDNSAnswer, EvidenceDNSHTTPS:
			return true
		}
	}
	return false
}

func authorizationID(a ActionAuthorization) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		a.SetID, a.Domain, a.EvidenceSource.String(), a.FlowKey.SrcIP.String(), a.FlowKey.DstIP.String(),
	}, "|") + "|" + time.Unix(0, int64(a.ConfigGen)).UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:8])
}
