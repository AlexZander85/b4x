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

// CanonicalSuite returns the minimum canonical suite (§54). Names must come
// from controlled field fixtures or reviewed service profiles.
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
// fresh canonical DNSPathProfile. One transient timeout never starts a deep
// matrix and one successful resolver never becomes primary (§5).
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
	maxCandidates := in.Policy.MaxQuickCandidates
	if in.Deep {
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

	limit := len(in.Providers)
	if limit > maxCandidates {
		limit = maxCandidates
	}
	for _, prov := range in.Providers[:limit] {
		caps := prov.Capabilities()
		id := prov.ID()
		paths[id.Hash()] = id
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
			continue
		}
		for _, sc := range in.Suite {
			for attempt := 1; attempt <= in.AttemptsQuick; attempt++ {
				out, err := prov.Probe(ctx, prepared, dnspath.DNSProbeQuery{
					Name: sc.Name, NameHash: dnspath.HashQName(sc.Name),
					QType: sc.QType, SuiteCase: sc.ID, Timeout: 3 * time.Second,
				})
				if err != nil {
					st.fail++
					continue
				}
				out.Attempt = uint16(attempt)
				st.outcomes = append(st.outcomes, out)
				switch {
				case out.Class.Pass():
					st.pass++
					st.latency += out.Latency
					st.latencyN++
				case out.Class == dnspath.OutcomeTimeout:
					st.timeouts++
					st.fail++
				case out.Class == dnspath.OutcomeAnswerConflict:
					st.conflicts++
					st.fail++
				case out.Class == dnspath.OutcomeEarlyInjectionSuspected:
					st.injection = true
					st.fail++
				case out.Class == dnspath.OutcomeTLSMidHandshakeReset:
					st.midHandshake = true
					st.fail++
				default:
					st.fail++
				}
			}
		}
		_ = prov.Retire(ctx, prepared)
	}

	// Aggregate evidence flags (§59: poisoning requires repeated
	// control/reference-contradicting answers, not one mismatch).
	poisonVotes, injectionVotes, udpDropVotes := 0, 0, 0
	for hash, st := range stats {
		id := paths[hash]
		if st.injection {
			injectionVotes++
		}
		if st.conflicts >= 2 {
			poisonVotes++
		}
		if st.timeouts >= 2 && (id.Family == dnspath.DNSPathUDP || id.Family == dnspath.DNSPathSystemForward) {
			udpDropVotes++
		}
	}
	diag.PoisoningDetected = poisonVotes > 0
	diag.InjectionDetected = injectionVotes > 0
	diag.UDPDropDetected = udpDropVotes > 0

	// Mid-handshake DPI cut is a family-level filter: one observation marks
	// the family (fast recurrence — retries against a stable DPI rule are
	// useless), and plaintext families are never listed here.
	for hash, st := range stats {
		if st.midHandshake {
			diag.EncryptedFamiliesFiltered = append(diag.EncryptedFamiliesFiltered, paths[hash].Family)
		}
	}

	// Build candidate evidence and rank deterministically.
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
		candidates = append(candidates, dnspath.CandidateEvidence{
			Path:            id,
			CorrectnessPass: st.pass >= in.AttemptsQuick && st.conflicts == 0 && !st.injection,
			ControlsPass:    controlsPass(st.outcomes),
			Stability:       stability,
			Latency:         lat,
			TimeoutRate:     timeoutRate,
			DNSSEC:          true,
			NoLogClaim:      true,
			NoFilterClaim:   true,
			CatalogTrusted:  true,
			CorrelatedGroup: correlatedGroup(id),
		})
	}
	ranked := dnspath.RankCandidates(candidates, in.Policy)
	allCorrect := true
	sawAny := false
	for _, st := range stats {
		if st.pass+st.fail == 0 {
			continue
		}
		sawAny = true
		if st.fail > 0 || st.injection || st.conflicts > 0 {
			allCorrect = false
			break
		}
	}
	if !sawAny {
		allCorrect = false
	}
	prior := dnspath.PriorFromEvidence(
		diag.PoisoningDetected, diag.UDPDropDetected, diag.Port53Blocked,
		false, false, false, false, allCorrect,
	)
	ranked = prior.ApplyTo(ranked)

	primary, fallbacks := dnspath.CompileProfileSelection(ranked, 2, 20)
	var outcomes []dnspath.DNSPathProbeOutcome
	for _, st := range stats {
		outcomes = append(outcomes, st.outcomes...)
	}
	sort.SliceStable(outcomes, func(i, j int) bool {
		if outcomes[i].PathID.Hash() != outcomes[j].PathID.Hash() {
			return outcomes[i].PathID.Hash() < outcomes[j].PathID.Hash()
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
