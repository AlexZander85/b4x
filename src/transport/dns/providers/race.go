package providers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// RaceVerdict is the classification of a UDP response-race observation
// (addendum §60). "Last response wins" is never applied by order alone.
type RaceVerdict string

const (
	RaceNormal            RaceVerdict = "normal"
	RaceEarlyInjection    RaceVerdict = "early_injection_suspected"
	RaceDuplicate         RaceVerdict = "duplicate"
	RaceConflicting       RaceVerdict = "conflicting"
	RaceInconclusive      RaceVerdict = "inconclusive"
	RaceMalformedRejected RaceVerdict = "malformed_rejected"
)

// RaceResponse is one validated candidate response in arrival order.
type RaceResponse struct {
	ArrivalIndex int
	ArrivalDelta time.Duration
	Fingerprint  dnspath.ResponseFingerprint
	Valid        bool
	RejectReason string
}

// RaceObservation is the full UDPResponseRaceObservation record (§9/§60).
type RaceObservation struct {
	Responses []RaceResponse
	Verdict   RaceVerdict
	Digest    string
}

// ObserveUDPRace sends one UDP query through the provider and collects all
// structurally validated responses inside the bounded window.
func ObserveUDPRace(ctx context.Context, p *UDPProvider, name string, qtype uint16) (RaceObservation, error) {
	query := b4dns.BuildQuery(name, uint16(time.Now().UnixNano()), qtype)
	raw, _, err := p.exchangeRaw(ctx, query, true)
	if err != nil && len(raw) == 0 {
		return RaceObservation{Verdict: RaceInconclusive}, err
	}
	obs := RaceObservation{}
	digestSeed := ""
	for i, r := range raw {
		rr := RaceResponse{ArrivalIndex: i, ArrivalDelta: r.Delta}
		if verr := validateResponse(query, r.Payload); verr != nil {
			rr.Valid = false
			rr.RejectReason = verr.Error()
			obs.Responses = append(obs.Responses, rr)
			continue
		}
		_, fp, perr := parseStructured(r.Payload, p.ID().ResolverID, time.Now())
		if perr != nil {
			rr.Valid = false
			rr.RejectReason = perr.Error()
			obs.Responses = append(obs.Responses, rr)
			continue
		}
		rr.Valid = true
		rr.Fingerprint = fp
		obs.Responses = append(obs.Responses, rr)
		digestSeed += fmt.Sprintf("%d:%s;", i, fp.AnswerDigest)
	}
	sum := sha256.Sum256([]byte(digestSeed))
	obs.Digest = hex.EncodeToString(sum[:8])
	obs.Verdict = ClassifyRace(obs, nil)
	return obs, nil
}

// ClassifyRace applies the §60 verdict table. reference may be nil when no
// encrypted/reference quorum is available; conflicting responses without a
// reference quorum stay INCONCLUSIVE.
func ClassifyRace(obs RaceObservation, reference *dnspath.ResponseFingerprint) RaceVerdict {
	valid := make([]RaceResponse, 0, len(obs.Responses))
	for _, r := range obs.Responses {
		if r.Valid {
			valid = append(valid, r)
		}
	}
	if len(valid) == 0 {
		if len(obs.Responses) > 0 {
			return RaceMalformedRejected
		}
		return RaceInconclusive
	}
	if len(valid) == 1 {
		if reference != nil && dnspath.CompareAnswers(valid[0].Fingerprint, *reference) == dnspath.RelationIdentical {
			return RaceNormal
		}
		if reference == nil {
			return RaceNormal
		}
		return RaceInconclusive
	}
	// multiple valid responses: identical set → duplicate; otherwise check
	// early-conflicting + later-reference-consistent
	same := true
	for i := 1; i < len(valid); i++ {
		if valid[i].Fingerprint.AnswerDigest != valid[0].Fingerprint.AnswerDigest ||
			valid[i].Fingerprint.RCode != valid[0].Fingerprint.RCode {
			same = false
			break
		}
	}
	if same {
		return RaceDuplicate
	}
	if reference != nil {
		last := valid[len(valid)-1]
		earlyConflicts := false
		for _, r := range valid[:len(valid)-1] {
			if dnspath.CompareAnswers(r.Fingerprint, *reference) == dnspath.RelationDisjoint ||
				dnspath.CompareAnswers(r.Fingerprint, *reference) == dnspath.RelationRCodeDiff {
				earlyConflicts = true
			}
		}
		if earlyConflicts && dnspath.CompareAnswers(last.Fingerprint, *reference) == dnspath.RelationIdentical {
			return RaceEarlyInjection
		}
		return RaceConflicting
	}
	return RaceInconclusive
}

// SortRaceResponses keeps deterministic arrival ordering for evidence.
func SortRaceResponses(rs []RaceResponse) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].ArrivalIndex < rs[j].ArrivalIndex })
}
