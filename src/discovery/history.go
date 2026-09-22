package discovery

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/monitor"
)

const (
	discoveryHistoryFile          = "discovery_history.json"
	maxHistoryEntries             = 100
	maxSynthesizedWinnerEntries   = 64
	maxSynthesizedWinnersPerScope = 4
)

// HistoryEntry represents a completed discovery result for a single domain.
type HistoryEntry struct {
	Domain        string                         `json:"domain"`
	Url           string                         `json:"url"`
	BestPreset    string                         `json:"best_preset"`
	BestSpeed     float64                        `json:"best_speed"`
	BestSuccess   bool                           `json:"best_success"`
	BestFamily    StrategyFamily                 `json:"best_family,omitempty"`
	Status        CheckStatus                    `json:"status"`
	StartTime     time.Time                      `json:"start_time"`
	EndTime       time.Time                      `json:"end_time"`
	Results       map[string]*DomainPresetResult `json:"results,omitempty"`
	DNSResult     *DNSDiscoveryResult            `json:"dns_result,omitempty"`
	BaselineSpeed float64                        `json:"baseline_speed,omitempty"`
	Improvement   float64                        `json:"improvement,omitempty"`
}

// SynthesizedWinnerCompatibilityKey extends the canonical MonitorScopeKey only
// with context dimensions not already represented there. MonitorScopeKey owns
// service/component/client class, network context, config generation and IP
// family. The remaining dimensions below prevent reuse across WAN,
// resolver/TLS, grammar or capability-generation drift.
//
// Local winners are exact-context revalidation seeds, never universal presets
// or apply grants.
type SynthesizedWinnerCompatibilityKey struct {
	Scope                 monitor.MonitorScopeKey `json:"scope"`
	WANFingerprint        string                  `json:"wan_fingerprint"`
	ResolverContextID     string                  `json:"resolver_context_id"`
	TLSContextID          string                  `json:"tls_context_id"`
	GrammarVersion        string                  `json:"grammar_version"`
	CapabilityGenerations map[string]uint64       `json:"capability_generations,omitempty"`
}

func (k SynthesizedWinnerCompatibilityKey) Valid() bool {
	return k.Scope.Valid() && k.WANFingerprint != "" && k.GrammarVersion != ""
}

func (k SynthesizedWinnerCompatibilityKey) ExactMatch(other SynthesizedWinnerCompatibilityKey) bool {
	if !k.Valid() || !other.Valid() || k.Scope != other.Scope || k.WANFingerprint != other.WANFingerprint || k.ResolverContextID != other.ResolverContextID || k.TLSContextID != other.TLSContextID || k.GrammarVersion != other.GrammarVersion {
		return false
	}
	if len(k.CapabilityGenerations) != len(other.CapabilityGenerations) {
		return false
	}
	for name, generation := range k.CapabilityGenerations {
		if other.CapabilityGenerations[name] != generation {
			return false
		}
	}
	return true
}

type SynthesizedWinnerRecord struct {
	Compatibility    SynthesizedWinnerCompatibilityKey `json:"compatibility"`
	Candidate        SynthesizedCandidatePlan          `json:"candidate"`
	EvidenceRefs     []string                          `json:"evidence_refs"`
	PromotedAt       time.Time                         `json:"promoted_at"`
	ExpiresAt        time.Time                         `json:"expires_at"`
	RevalidateAt     time.Time                         `json:"revalidate_at"`
	QuarantinedAt    time.Time                         `json:"quarantined_at,omitempty"`
	QuarantineReason string                            `json:"quarantine_reason,omitempty"`
}

// Valid validates persistence integrity. Quarantine is intentionally not an
// integrity failure: quarantined records remain auditable but are not reusable.
func (r SynthesizedWinnerRecord) Valid(now time.Time) bool {
	return r.Compatibility.Valid() && r.Candidate.ValidIdentity() && r.Candidate.Scope == r.Compatibility.Scope && r.Candidate.GrammarVersion == r.Compatibility.GrammarVersion && len(r.EvidenceRefs) > 0 && !r.PromotedAt.IsZero() && (r.ExpiresAt.IsZero() || now.Before(r.ExpiresAt))
}

func (r SynthesizedWinnerRecord) Reusable(now time.Time) bool {
	return r.Valid(now) && r.QuarantinedAt.IsZero()
}

func (r SynthesizedWinnerRecord) NeedsRevalidation(now time.Time) bool {
	return !r.RevalidateAt.IsZero() && !now.Before(r.RevalidateAt)
}

// DiscoveryHistory remains the single persistent Discovery history owner.
type DiscoveryHistory struct {
	Entries            []HistoryEntry            `json:"entries"`
	SynthesizedWinners []SynthesizedWinnerRecord `json:"synthesized_winners,omitempty"`
	mu                 sync.Mutex                `json:"-"`
}

func historyFilePath(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), discoveryHistoryFile)
}

func LoadDiscoveryHistory(configPath string) *DiscoveryHistory {
	history := &DiscoveryHistory{}
	path := historyFilePath(configPath)
	if path == "" {
		return history
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return history
	}
	if err := json.Unmarshal(data, history); err != nil {
		log.Errorf("Failed to parse discovery history: %v", err)
		return &DiscoveryHistory{}
	}
	log.Tracef("Loaded discovery history with %d entries and %d synthesized winners", len(history.Entries), len(history.SynthesizedWinners))
	return history
}

func (dh *DiscoveryHistory) Save(configPath string) error {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	path := historyFilePath(configPath)
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(dh, "", "  ")
	if err != nil {
		return log.Errorf("failed to marshal discovery history: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return log.Errorf("failed to write discovery history: %v", err)
	}
	log.Tracef("Saved discovery history with %d entries and %d synthesized winners to %s", len(dh.Entries), len(dh.SynthesizedWinners), path)
	return nil
}

func (dh *DiscoveryHistory) AddFromSuite(suite *CheckSuite) {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	if suite.DomainDiscoveryResults == nil {
		return
	}
	for _, domainResult := range suite.DomainDiscoveryResults {
		bestFamily := StrategyFamily("")
		if domainResult.BestPreset != "" {
			if r, ok := domainResult.Results[domainResult.BestPreset]; ok {
				bestFamily = r.Family
			}
		}
		entry := HistoryEntry{
			Domain: domainResult.Domain, Url: domainResult.Url, BestPreset: domainResult.BestPreset,
			BestSpeed: domainResult.BestSpeed, BestSuccess: domainResult.BestSuccess, BestFamily: bestFamily,
			Status: suite.Status, StartTime: suite.StartTime, EndTime: suite.EndTime, Results: domainResult.Results,
			DNSResult: domainResult.DNSResult, BaselineSpeed: domainResult.BaselineSpeed, Improvement: domainResult.Improvement,
		}
		replaced := false
		for i, existing := range dh.Entries {
			if existing.Domain == domainResult.Domain {
				dh.Entries[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			dh.Entries = append(dh.Entries, entry)
		}
	}
	if len(dh.Entries) > maxHistoryEntries {
		sort.Slice(dh.Entries, func(i, j int) bool { return dh.Entries[i].EndTime.After(dh.Entries[j].EndTime) })
		dh.Entries = dh.Entries[:maxHistoryEntries]
	}
}

// AddSynthesizedWinner records only a candidate that has already passed the
// external canary/promotion gates. It performs no promotion itself. The store
// keeps at most four winners per exact Monitor scope and remains globally
// bounded as defense in depth.
func (dh *DiscoveryHistory) AddSynthesizedWinner(record SynthesizedWinnerRecord, now time.Time) error {
	if dh == nil || !record.Valid(now) || !record.QuarantinedAt.IsZero() {
		return errors.New("invalid synthesized winner record")
	}
	dh.mu.Lock()
	defer dh.mu.Unlock()
	record.EvidenceRefs = stableUniqueStrings(record.EvidenceRefs)
	for i := range dh.SynthesizedWinners {
		existing := dh.SynthesizedWinners[i]
		if existing.Candidate.CandidateID == record.Candidate.CandidateID && existing.Compatibility.ExactMatch(record.Compatibility) {
			dh.SynthesizedWinners[i] = record
			dh.trimSynthesizedWinnersLocked(record.Compatibility.Scope)
			return nil
		}
	}
	dh.SynthesizedWinners = append(dh.SynthesizedWinners, record)
	dh.trimSynthesizedWinnersLocked(record.Compatibility.Scope)
	return nil
}

func (dh *DiscoveryHistory) trimSynthesizedWinnersLocked(scope monitor.MonitorScopeKey) {
	sort.SliceStable(dh.SynthesizedWinners, func(i, j int) bool {
		return dh.SynthesizedWinners[i].PromotedAt.After(dh.SynthesizedWinners[j].PromotedAt)
	})
	kept := make([]SynthesizedWinnerRecord, 0, len(dh.SynthesizedWinners))
	matchingScope := 0
	for _, winner := range dh.SynthesizedWinners {
		if winner.Compatibility.Scope == scope {
			matchingScope++
			if matchingScope > maxSynthesizedWinnersPerScope {
				continue
			}
		}
		kept = append(kept, winner)
	}
	if len(kept) > maxSynthesizedWinnerEntries {
		kept = kept[:maxSynthesizedWinnerEntries]
	}
	dh.SynthesizedWinners = kept
}

// QuarantineSynthesizedWinner prevents automatic reuse after rollback or
// collateral regression while retaining the record for audit/debugging.
func (dh *DiscoveryHistory) QuarantineSynthesizedWinner(key SynthesizedWinnerCompatibilityKey, candidateID, reason string, now time.Time) error {
	if dh == nil || !key.Valid() || candidateID == "" || reason == "" || now.IsZero() {
		return errors.New("invalid synthesized winner quarantine request")
	}
	dh.mu.Lock()
	defer dh.mu.Unlock()
	for i := range dh.SynthesizedWinners {
		winner := &dh.SynthesizedWinners[i]
		if winner.Candidate.CandidateID == candidateID && winner.Compatibility.ExactMatch(key) {
			winner.QuarantinedAt = now
			winner.QuarantineReason = reason
			return nil
		}
	}
	return errors.New("synthesized winner not found")
}

// CompatibleSynthesizedWinners returns exact-context local seeds only. They
// still require static validation and ordinary Discovery revalidation. A
// quarantine record is never returned as a reusable seed.
func (dh *DiscoveryHistory) CompatibleSynthesizedWinners(key SynthesizedWinnerCompatibilityKey, now time.Time) []SynthesizedWinnerRecord {
	if dh == nil || !key.Valid() {
		return nil
	}
	dh.mu.Lock()
	defer dh.mu.Unlock()
	out := make([]SynthesizedWinnerRecord, 0)
	for _, winner := range dh.SynthesizedWinners {
		if winner.Reusable(now) && winner.Compatibility.ExactMatch(key) {
			out = append(out, winner)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].PromotedAt.After(out[j].PromotedAt) })
	return out
}

func (dh *DiscoveryHistory) Clear() {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	dh.Entries = nil
	dh.SynthesizedWinners = nil
}

func (dh *DiscoveryHistory) RemoveDomain(domain string) {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	for i, entry := range dh.Entries {
		if entry.Domain == domain {
			dh.Entries = append(dh.Entries[:i], dh.Entries[i+1:]...)
			return
		}
	}
}

// QuarantineSynthesizedWinnersForScope invalidates every persisted synthesized
// winner whose exact Monitor scope matches. It is the operator revert-to-catalog
// path (AFS §73): after revert the record stays for audit but is never reusable.
// It performs no promotion or configuration mutation and is idempotent.
func (dh *DiscoveryHistory) QuarantineSynthesizedWinnersForScope(scope monitor.MonitorScopeKey, reason string, now time.Time) int {
	if dh == nil || !scope.Valid() || strings.TrimSpace(reason) == "" || now.IsZero() {
		return 0
	}
	dh.mu.Lock()
	defer dh.mu.Unlock()
	count := 0
	for i := range dh.SynthesizedWinners {
		winner := &dh.SynthesizedWinners[i]
		if winner.Compatibility.Scope == scope && winner.QuarantinedAt.IsZero() {
			winner.QuarantinedAt = now
			winner.QuarantineReason = reason
			count++
		}
	}
	return count
}
