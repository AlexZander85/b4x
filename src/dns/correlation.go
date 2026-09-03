package dns

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

type HintSetCandidate struct {
	SetID      string
	Confidence uint8
}

type HintSetResolver interface {
	Resolve(domain string, client classifier.ClientKey, sourceDevice string, protocol uint8) []HintSetCandidate
}

type HintSetResolverFunc func(domain string, client classifier.ClientKey, sourceDevice string, protocol uint8) []HintSetCandidate

func (f HintSetResolverFunc) Resolve(domain string, client classifier.ClientKey, sourceDevice string, protocol uint8) []HintSetCandidate {
	return f(domain, client, sourceDevice, protocol)
}

type DNSCorrelationResult struct {
	PositiveHints   int
	CandidateDomain []string
	RCode           int
	Negative        bool
	Truncated       bool
	Reason          string
}

type DNSHintCorrelator struct {
	store     *classifier.HostHintStore
	resolver  HintSetResolver
	protocols []uint8
}

func NewDNSHintCorrelator(store *classifier.HostHintStore, resolver HintSetResolver, protocols ...uint8) *DNSHintCorrelator {
	if len(protocols) == 0 {
		protocols = []uint8{6, 17}
	}
	seen := make(map[uint8]struct{}, len(protocols))
	ordered := make([]uint8, 0, len(protocols))
	for _, protocol := range protocols {
		if protocol == 0 {
			continue
		}
		if _, exists := seen[protocol]; exists {
			continue
		}
		seen[protocol] = struct{}{}
		ordered = append(ordered, protocol)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	return &DNSHintCorrelator{store: store, resolver: resolver, protocols: ordered}
}

// ObserveResponse turns one valid DNS response into source-scoped TCP/UDP
// evidence. Negative or truncated responses are diagnostic-only and never
// create positive hints.
func (c *DNSHintCorrelator) ObserveResponse(observation DNSObservation, sourceDevice string, configGeneration uint64) (DNSCorrelationResult, error) {
	result := DNSCorrelationResult{RCode: observation.RCode, Truncated: observation.Truncated}
	if observation.RCode != 0 {
		result.Negative = true
		result.Reason = fmt.Sprintf("DNS negative response rcode=%d", observation.RCode)
		return result, nil
	}
	if observation.Truncated {
		result.Reason = "truncated DNS response; no positive hint"
		return result, nil
	}
	if c == nil || c.store == nil || c.resolver == nil {
		return result, fmt.Errorf("DNS hint correlator is not configured")
	}
	if len(observation.Answers) == 0 {
		result.Reason = "DNS response has no address answers"
		return result, nil
	}

	domains := observationDomains(observation)
	result.CandidateDomain = append([]string(nil), domains...)
	if len(domains) == 0 {
		result.Reason = "DNS response has no canonical hostname"
		return result, nil
	}
	createdAt := observation.Timestamp
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	var firstErr error
	for _, answer := range observation.Answers {
		if !answer.IP.IsValid() || answer.TTL <= 0 {
			continue
		}
		expiresAt := createdAt.Add(answer.TTL)
		for _, protocol := range c.protocols {
			for _, domain := range domains {
				for _, candidate := range uniqueSetCandidates(c.resolver.Resolve(domain, observation.Client, sourceDevice, protocol)) {
					if strings.TrimSpace(candidate.SetID) == "" {
						continue
					}
					evidence := classifier.Evidence{
						Source:          classifier.EvidenceDNSAnswer,
						Client:          observation.Client,
						DestinationIP:   answer.IP,
						DestinationPort: 443,
						L4Proto:         protocol,
						SourceDevice:    sourceDevice,
						Domain:          domain,
						SetID:           candidate.SetID,
						Confidence:      candidate.Confidence,
						DomainEvidence:  true,
						CreatedAt:       createdAt,
						ExpiresAt:       expiresAt,
						ConfigGen:       configGeneration,
						Reason:          "source-scoped DNS A/AAAA answer",
					}
					if err := c.store.Observe(evidence); err != nil {
						if firstErr == nil {
							firstErr = err
						}
						continue
					}
					result.PositiveHints++
				}
			}
		}

		for _, record := range observation.HTTPSRecords {
			if record.TTL <= 0 {
				continue
			}
			httpsDomains := []string{normalizeCorrelationDomain(record.Name)}
			if httpsDomains[0] == "" {
				httpsDomains = domains
			}
			for _, protocol := range c.protocols {
				for _, domain := range uniqueStrings(httpsDomains) {
					for _, candidate := range uniqueSetCandidates(c.resolver.Resolve(domain, observation.Client, sourceDevice, protocol)) {
						if strings.TrimSpace(candidate.SetID) == "" {
							continue
						}
						evidence := classifier.Evidence{
							Source:          classifier.EvidenceDNSHTTPS,
							Client:          observation.Client,
							DestinationIP:   answer.IP,
							DestinationPort: 443,
							L4Proto:         protocol,
							SourceDevice:    sourceDevice,
							Domain:          domain,
							SetID:           candidate.SetID,
							Confidence:      candidate.Confidence,
							DomainEvidence:  true,
							ECHRelated:      record.HasECHConfig,
							CreatedAt:       createdAt,
							ExpiresAt:       createdAt.Add(record.TTL),
							ConfigGen:       configGeneration,
							Reason:          "source-scoped DNS HTTPS/SVCB metadata",
						}
						if err := c.store.Observe(evidence); err != nil {
							if firstErr == nil {
								firstErr = err
							}
							continue
						}
						result.PositiveHints++
					}
				}
			}
		}
	}
	if result.PositiveHints == 0 && firstErr == nil {
		result.Reason = "DNS response produced no eligible source-scoped set"
	}
	return result, firstErr
}

func observationDomains(observation DNSObservation) []string {
	values := []string{observation.QueryName, observation.Canonical}
	for _, answer := range observation.Answers {
		values = append(values, answer.Name, answer.CanonicalName)
	}
	for _, record := range observation.HTTPSRecords {
		values = append(values, record.Name)
	}
	return uniqueStrings(values)
}

func uniqueSetCandidates(candidates []HintSetCandidate) []HintSetCandidate {
	byID := make(map[string]HintSetCandidate, len(candidates))
	for _, candidate := range candidates {
		candidate.SetID = strings.TrimSpace(candidate.SetID)
		if candidate.SetID == "" {
			continue
		}
		if previous, exists := byID[candidate.SetID]; !exists || candidate.Confidence > previous.Confidence {
			byID[candidate.SetID] = candidate
		}
	}
	result := make([]HintSetCandidate, 0, len(byID))
	for _, candidate := range byID {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].SetID != result[j].SetID {
			return result[i].SetID < result[j].SetID
		}
		return result[i].Confidence > result[j].Confidence
	})
	return result
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeCorrelationDomain(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeCorrelationDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}
