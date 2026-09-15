package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// ADNS query suite version (registry-known).
const ADNSQuerySuiteVersion = "adns-suite-v1"

// ADNSSuiteCase is one canonical query suite case (addendum §54).
type ADNSSuiteCase struct {
	ID    string
	Name  string // controlled fixture or reviewed service-profile target
	QType uint16
}

// CanonicalSuite returns the minimum field-safe canonical suite. Controlled
// SERVFAIL/truncation/multi-answer/DNSSEC fixtures are exercised separately;
// production diagnosis must not invent public names that are expected to
// exhibit those failure semantics.
func CanonicalSuite(target, control string) []ADNSSuiteCase {
	return []ADNSSuiteCase{
		{ID: "A", Name: target, QType: 1},
		{ID: "AAAA", Name: target, QType: 28},
		{ID: "CNAME", Name: target, QType: 5},
		{ID: "HTTPS", Name: target, QType: 65},
		{ID: "NXDOMAIN", Name: "nonexistent." + target, QType: 1},
		{ID: "CONTROL_SAME", Name: target, QType: 1},
		{ID: "CONTROL_UNRELATED", Name: control, QType: 1},
	}
}

// ADNSDiagnosisInput configures one bounded differential run.
type ADNSDiagnosisInput struct {
	Providers      []dnspath.DNSPathProvider
	Policy         dnspath.AdaptivePolicy
	Suite          []ADNSSuiteCase
	Deep           bool
	AttemptsQuick  int
	AttemptsValid  int
	NetworkContext string
	Generation     uint64
	RuntimeEpoch   string
	CatalogVersion string
	PolicyDigest   string
	SourceProfile  string
	TTL            time.Duration
	Now            func() time.Time
}

// ADNSDiagnosis is the detector output: normalized outcomes plus the
// compiled profile. It is evidence, not authorization (§4).
type ADNSDiagnosis struct {
	Outcomes []dnspath.DNSPathProbeOutcome
	Profile  *dnspath.DNSPathProfile
	// Flags feed the failure-to-family prior (§67).
	PoisoningDetected    bool
	InjectionDetected    bool
	UDPDropDetected      bool
	Port53Blocked        bool
	EncryptedPathBlocked bool
	// EncryptedFamiliesFiltered lists encrypted families cut mid-handshake
	// (RST/EOF after ClientHello — the 2026-08 DoH/DoT DPI signature). The
	// path controller uses this to quarantine those families while plaintext
	// UDP fallback to the same resolver IPs stays eligible.
	EncryptedFamiliesFiltered []dnspath.DNSPathFamily
}

// RunADNSDiagnosis executes the bounded quick/deep matrix and compiles a
// fresh canonical DNSPathProfile. A provider can prove transport/message
// validity, but PASS_CORRECT is granted only after repeated independent
// differential corroboration and both controls pass.
func RunADNSDiagnosis(ctx context.Context, in ADNSDiagnosisInput) (*ADNSDiagnosis, error) {
	if len(in.Providers) == 0 {
		return nil, fmt.Errorf("adns diagnosis requires at least one provider")
	}
	if in.AttemptsQuick <= 0 {
		in.AttemptsQuick = 2
	}
	if in.AttemptsValid <= 0 {
		in.AttemptsValid = 5
	}
	if in.Now == nil {
		in.Now = time.Now
	}
	if in.TTL <= 0 {
		in.TTL = 24 * time.Hour
	}
	attempts := in.AttemptsQuick
	maxCandidates := in.Policy.MaxQuickCandidates
	if in.Deep {
		attempts = in.AttemptsValid
		maxCandidates = in.Policy.MaxDeepCandidates
	}
	if maxCandidates <= 0 {
		maxCandidates = 8
	}

	diag := &ADNSDiagnosis{}
	type pathStats struct {
		pass         int
		fail         int
		latency      time.Duration
		latencyN     int
		timeouts     int
		conflicts    int
		injection    bool
		midHandshake bool
		outcomes     []dnspath.DNSPathProbeOutcome
	}
	stats := map[string]*pathStats{}
	paths := map[string]dnspath.DNSPathID{}
	capabilities := map[string]dnspath.DNSPathCapabilities{}

	limit := len(in.Providers)
	if limit > maxCandidates {
		limit = maxCandidates
	}
	for _, prov := range in.Providers[:limit] {
		caps := prov.Capabilities()
		id := prov.ID()
		paths[id.Hash()] = id
		capabilities[id.Hash()] = caps
		st := &pathStats{}
		stats[id.Hash()] = st
		if caps.State == dnspath.CapUnsupported || caps.State.Terminal() {
			continue
		}
		if !in.Policy.AllowsFamily(id.Family) {
			continue
		}
		prepared, err := prov.Prepare(ctx, dnspath.DNSPrepareRequest{
			Generation: in.Generation, NetworkContextID: in.NetworkContext,
			RuntimeEpoch: in.RuntimeEpoch, Diagnostic: true,
		})
		if err != nil {
			// Preparation/bootstrap failure is explicit negative evidence, not
			// absence of evidence. Record every suite case so required-case
			// validation cannot accidentally treat the path as merely untested.
			for _, sc := range in.Suite {
				for attempt := 1; attempt <= attempts; attempt++ {
					st.outcomes = append(st.outcomes, dnspath.DNSPathProbeOutcome{
						PathID: id, QuerySuiteID: sc.ID, Attempt: uint16(attempt),
						Stage: dnspath.StageRouteBootstrap, Class: dnspath.OutcomeObserverUnavailable,
						FailureCode: "provider_prepare_error", Attribution: err.Error(), ObservedAt: in.Now(),
					})
				}
			}
			continue
		}
		for _, sc := range in.Suite {
			for attempt := 1; attempt <= attempts; attempt++ {
				out, err := prov.Probe(ctx, prepared, dnspath.DNSProbeQuery{
					Name: sc.Name, NameHash: dnspath.HashQName(sc.Name),
					QType: sc.QType, SuiteCase: sc.ID, Timeout: 3 * time.Second,
					ObserveRace: id.Family == dnspath.DNSPathUDP && sc.ID == "A",
				})
				if err != nil {
					out = dnspath.DNSPathProbeOutcome{
						PathID: id, QuerySuiteID: sc.ID, Attempt: uint16(attempt),
						Stage: dnspath.StageConnect, Class: dnspath.OutcomeObserverUnavailable,
						FailureCode: "provider_probe_error", ObservedAt: in.Now(),
					}
					st.outcomes = append(st.outcomes, out)
					continue
				}
				out.Attempt = uint16(attempt)
				st.outcomes = append(st.outcomes, out)
			}
		}
		_ = prov.Retire(ctx, prepared)
	}

	var provisional []dnspath.DNSPathProbeOutcome
	for _, st := range stats {
		provisional = append(provisional, st.outcomes...)
	}
	verifiedOutcomes, verifiedStats := verifyADNSOutcomes(provisional, in.Suite, attempts)
	for hash, st := range stats {
		v := verifiedStats[hash]
		st.pass = v.Pass
		st.fail = v.Fail
		st.latency = v.Latency
		st.latencyN = v.LatencyN
		st.timeouts = v.Timeouts
		st.conflicts = v.Conflicts
		st.injection = v.Injection
		st.midHandshake = v.MidHandshake
		st.outcomes = st.outcomes[:0]
		for _, o := range verifiedOutcomes {
			if o.PathID.Hash() == hash {
				st.outcomes = append(st.outcomes, o)
			}
		}
	}

	diag.PoisoningDetected, diag.InjectionDetected, diag.UDPDropDetected,
		diag.Port53Blocked, diag.EncryptedPathBlocked, diag.EncryptedFamiliesFiltered =
		classifyDiagnosisFlags(verifiedOutcomes, paths, verifiedStats, attempts)

	// Refine transport attribution with a controlled variable: UDP failure is
	// called interference/drop only when TCP to the same apparent resolver has
	// independently passed the full suite. This prevents generic resolver/WAN
	// outages from being mislabeled as UDP-specific filtering.
	var sameResolverConflict bool
	verifiedOutcomes, diag.UDPDropDetected, sameResolverConflict =
		applyTransportDifferentialEvidence(verifiedOutcomes, paths, verifiedStats, attempts)
	if sameResolverConflict {
		diag.PoisoningDetected = true
	}
	// Likewise, a port-53 block requires corroborated UDP+TCP failure and a
	// working independently validated encrypted path.
	diag.Port53Blocked = corroboratedPort53Block(paths, verifiedStats, attempts)

	// Rebind per-path outcome slices after evidence annotation.
	for hash, st := range stats {
		st.outcomes = st.outcomes[:0]
		for _, o := range verifiedOutcomes {
			if o.PathID.Hash() == hash {
				st.outcomes = append(st.outcomes, o)
			}
		}
	}

	// Build candidate evidence and rank deterministically. Correctness and
	// controls are per-suite-case gates; aggregate pass counts are not enough.
	// Trust/privacy claims are fail-closed and originate in provider/catalog
	// capabilities; transport success never manufactures those claims.
	var candidates []dnspath.CandidateEvidence
	for hash, st := range stats {
		id := paths[hash]
		total := st.pass + st.fail
		if total == 0 {
			continue
		}
		stability := float64(st.pass) / float64(total)
		var lat time.Duration
		if st.latencyN > 0 {
			lat = st.latency / time.Duration(st.latencyN)
		}
		timeoutRate := float64(st.timeouts) / float64(total)
		v := verifiedStats[hash]
		caps := capabilities[hash]
		candidates = append(candidates, dnspath.CandidateEvidence{
			Path:            id,
			CorrectnessPass: v.CorrectnessPass,
			ControlsPass:    v.ControlsPass,
			Stability:       stability,
			Latency:         lat,
			TimeoutRate:     timeoutRate,
			DNSSEC:          caps.DNSSEC,
			NoLogClaim:      caps.NoLogClaim,
			NoFilterClaim:   caps.NoFilterClaim,
			CatalogTrusted:  caps.CatalogTrusted,
			Anonymized:      caps.Anonymized,
			CorrelatedGroup: correlatedGroup(id),
		})
	}
	ranked := dnspath.RankCandidates(candidates, in.Policy)
	allCorrect := true
	sawAny := false
	for hash, st := range stats {
		if st.pass+st.fail == 0 {
			continue
		}
		sawAny = true
		v := verifiedStats[hash]
		if !v.CorrectnessPass || !v.ControlsPass || st.fail > 0 || st.injection || st.conflicts > 0 {
			allCorrect = false
			break
		}
	}
	if !sawAny {
		allCorrect = false
	}
	prior := dnspath.PriorFromEvidence(
		diag.PoisoningDetected, diag.UDPDropDetected, diag.Port53Blocked,
		diag.EncryptedPathBlocked, false, false, false, allCorrect,
	)
	ranked = prior.ApplyTo(ranked)

	primary, fallbacks := dnspath.CompileProfileSelection(ranked, 2, 20)
	outcomes := append([]dnspath.DNSPathProbeOutcome(nil), verifiedOutcomes...)
	sort.SliceStable(outcomes, func(i, j int) bool {
		if outcomes[i].PathID.Hash() != outcomes[j].PathID.Hash() {
			return outcomes[i].PathID.Hash() < outcomes[j].PathID.Hash()
		}
		if outcomes[i].QuerySuiteID != outcomes[j].QuerySuiteID {
			return outcomes[i].QuerySuiteID < outcomes[j].QuerySuiteID
		}
		return outcomes[i].Attempt < outcomes[j].Attempt
	})
	diag.Outcomes = outcomes

	profile := &dnspath.DNSPathProfile{
		Status:                  dnspath.ProfileStatusReady,
		NetworkContextID:        in.NetworkContext,
		ConfigGeneration:        in.Generation,
		RuntimeEpoch:            in.RuntimeEpoch,
		SourceBlockingProfileID: in.SourceProfile,
		QuerySuiteVersion:       ADNSQuerySuiteVersion,
		ResolverCatalogVersion:  in.CatalogVersion,
		PolicyDigest:            in.PolicyDigest,
		CandidateOutcomes:       outcomes,
		PoisoningDetected:       diag.PoisoningDetected,
		InjectionDetected:       diag.InjectionDetected,
		UDPDropDetected:         diag.UDPDropDetected,
		Port53Blocked:           diag.Port53Blocked,
		EncryptedPathBlocked:    diag.EncryptedPathBlocked,
		CreatedAt:               in.Now(),
		ValidatedAt:             in.Now(),
		ValidUntil:              in.Now().Add(in.TTL),
	}
	if primary == nil {
		profile.Status = dnspath.ProfileStatusInvalid
	} else {
		profile.Primary = primary.Candidate.Path
		for _, fb := range fallbacks {
			profile.Fallbacks = append(profile.Fallbacks, fb.Candidate.Path)
		}
	}
	// Exclusions for terminal-state providers.
	for _, prov := range in.Providers[:limit] {
		caps := prov.Capabilities()
		if caps.State.Terminal() || caps.State == dnspath.CapUnsupported {
			profile.Excluded = append(profile.Excluded, dnspath.DNSPathExclusion{
				Path: prov.ID(), Reason: string(caps.State) + ": " + caps.Reason,
			})
		}
	}
	supports, contradictions := 0, 0
	for _, st := range stats {
		supports += st.pass
		contradictions += st.conflicts
	}
	profile.Confidence = dnspath.ConfidenceSummary{
		Supports: supports, Contradictions: contradictions,
		Score: confidenceScore(supports, contradictions),
	}
	idSum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", in.NetworkContext, in.Generation, profile.CreatedAt.UnixNano())))
	profile.ProfileID = "dnsprof-" + hex.EncodeToString(idSum[:6])
	if err := profile.Seal(); err != nil {
		return nil, err
	}
	diag.Profile = profile
	return diag, nil
}

// controlsPass requires same-service and unrelated control cases to pass
// (§71.4, zero-tolerance dns_promotion_without_controls_total).
func controlsPass(outcomes []dnspath.DNSPathProbeOutcome) bool {
	same, unrelated := false, false
	for _, o := range outcomes {
		if !o.Class.Pass() {
			continue
		}
		switch o.QuerySuiteID {
		case "CONTROL_SAME":
			same = true
		case "CONTROL_UNRELATED":
			unrelated = true
		}
	}
	return same && unrelated
}

func correlatedGroup(id dnspath.DNSPathID) string {
	// same resolver across transports shares a failure domain
	return id.ResolverID
}

func confidenceScore(supports, contradictions int) float64 {
	if supports+contradictions == 0 {
		return 0
	}
	s := float64(supports) / float64(supports+contradictions)
	if s > 1 {
		s = 1
	}
	return s
}
