package dnspath

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	b4dns "github.com/daniellavrushin/b4/dns"
)

// ResponseFingerprint is the normalized comparison view of a DNS answer
// (addendum §28). A differing CDN answer set does not mean poisoning without
// control/reference/context analysis.
type ResponseFingerprint struct {
	QuestionName  string   `json:"question_name"`
	QuestionType  uint16   `json:"question_type"`
	RCode         int      `json:"rcode"`
	AnswerSet     []string `json:"answer_set"`   // order-independent A/AAAA set
	CNAMEChain    []string `json:"cname_chain"`  // order significant
	HTTPSParams   []string `json:"https_params"` // normalized SVCB/HTTPS params
	TTLMin        uint32   `json:"ttl_min"`
	TTLMax        uint32   `json:"ttl_max"`
	Truncated     bool     `json:"truncated"`
	HasECH        bool     `json:"has_ech"`
	AnswerDigest  string   `json:"answer_digest"`
	CNAMEDigest   string   `json:"cname_digest"`
	HTTPSDigest   string   `json:"https_digest"`
}

// FingerprintObservation normalizes a parsed structured response.
func FingerprintObservation(obs b4dns.DNSObservation) ResponseFingerprint {
	fp := ResponseFingerprint{
		QuestionName: strings.ToLower(obs.QueryName),
		RCode:        obs.RCode,
		Truncated:    obs.Truncated,
		TTLMin:       ^uint32(0),
	}
	if len(obs.Questions) > 0 {
		fp.QuestionType = obs.Questions[0].Type
	}
	seen := map[string]bool{}
	for _, a := range obs.Answers {
		key := a.IP.String()
		if !seen[key] {
			seen[key] = true
			fp.AnswerSet = append(fp.AnswerSet, key)
		}
		if a.TTLSeconds < fp.TTLMin {
			fp.TTLMin = a.TTLSeconds
		}
		if a.TTLSeconds > fp.TTLMax {
			fp.TTLMax = a.TTLSeconds
		}
	}
	sort.Strings(fp.AnswerSet)
	for _, c := range obs.CNAMEs {
		fp.CNAMEChain = append(fp.CNAMEChain,
			fmt.Sprintf("%s>%s", strings.ToLower(c.Name), strings.ToLower(c.Target)))
	}
	for _, h := range obs.HTTPSRecords {
		params := make([]string, 0, len(h.Params))
		for k := range h.Params {
			params = append(params, fmt.Sprintf("%d", k))
		}
		sort.Strings(params)
		fp.HTTPSParams = append(fp.HTTPSParams,
			fmt.Sprintf("%d|%s|%s", h.Priority, strings.ToLower(h.Target), strings.Join(params, ",")))
		if h.HasECHConfig {
			fp.HasECH = true
		}
	}
	if len(fp.AnswerSet) == 0 {
		fp.TTLMin = 0
	}
	fp.AnswerDigest = digestStrings(fp.AnswerSet)
	fp.CNAMEDigest = digestStrings(fp.CNAMEChain)
	fp.HTTPSDigest = digestStrings(fp.HTTPSParams)
	return fp
}

func digestStrings(items []string) string {
	if len(items) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(items, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// CompareAnswers classifies the relationship between a candidate and a
// reference fingerprint. It never declares poisoning on its own: the caller
// must combine this with control/reference quorum (addendum §59).
type AnswerRelation string

const (
	RelationIdentical   AnswerRelation = "identical"
	RelationSubset      AnswerRelation = "subset"       // CDN rotation candidate
	RelationDisjoint    AnswerRelation = "disjoint"     // conflict candidate
	RelationRCodeDiff   AnswerRelation = "rcode_diff"
	RelationCNAMEAltered AnswerRelation = "cname_altered"
)

func CompareAnswers(candidate, reference ResponseFingerprint) AnswerRelation {
	if candidate.RCode != reference.RCode {
		return RelationRCodeDiff
	}
	if candidate.CNAMEDigest != reference.CNAMEDigest &&
		(candidate.CNAMEDigest != "" || reference.CNAMEDigest != "") {
		return RelationCNAMEAltered
	}
	if candidate.AnswerDigest == reference.AnswerDigest {
		return RelationIdentical
	}
	if len(candidate.AnswerSet) == 0 || len(reference.AnswerSet) == 0 {
		return RelationDisjoint
	}
	ref := map[string]bool{}
	for _, a := range reference.AnswerSet {
		ref[a] = true
	}
	allIn := true
	for _, a := range candidate.AnswerSet {
		if !ref[a] {
			allIn = false
			break
		}
	}
	if allIn {
		return RelationSubset
	}
	return RelationDisjoint
}
