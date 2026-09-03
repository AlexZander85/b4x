package runtimecontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
)

func validateCanaryOutcome(spec CanarySpec, outcome CanaryOutcome) error {
	if outcome.Samples < spec.MinSamples {
		return fmt.Errorf("canary minimum samples not met: got %d, need %d", outcome.Samples, spec.MinSamples)
	}
	rate := outcome.FailureRate
	if rate == 0 && outcome.Samples > 0 {
		rate = float64(outcome.Failures) / float64(outcome.Samples)
	}
	if spec.Stop.MaxFailures > 0 && outcome.Failures > spec.Stop.MaxFailures {
		return fmt.Errorf("canary stop condition: failures=%d exceeds %d", outcome.Failures, spec.Stop.MaxFailures)
	}
	if spec.Stop.MaxFailureRate > 0 && rate > spec.Stop.MaxFailureRate {
		return fmt.Errorf("canary stop condition: failure_rate=%.4f exceeds %.4f", rate, spec.Stop.MaxFailureRate)
	}
	if spec.Stop.StopOnQueueDrops && outcome.QueueDrops > 0 {
		return fmt.Errorf("canary stop condition: queue drops=%d", outcome.QueueDrops)
	}
	if spec.Stop.StopOnCaptureIncomplete && outcome.CaptureIncomplete {
		return errors.New("canary stop condition: capture incomplete")
	}
	if !outcome.StartedAt.IsZero() && !outcome.CompletedAt.IsZero() {
		if outcome.CompletedAt.Before(outcome.StartedAt) {
			return errors.New("canary timestamps are out of order")
		}
		if outcome.CompletedAt.Sub(outcome.StartedAt) > spec.Duration {
			return fmt.Errorf("canary duration exceeded: %s", outcome.CompletedAt.Sub(outcome.StartedAt))
		}
	}
	if !outcome.Passed {
		if outcome.StopReason != "" {
			return errors.New(outcome.StopReason)
		}
		return errors.New("canary reported failure")
	}
	return nil
}

func makeGenerationMeta(cfg *config.Config, now time.Time) GenerationMeta {
	hash := fingerprintConfig(cfg)
	setIDs := make([]string, 0, len(cfg.Sets))
	strategyIDs := make([]string, 0, len(cfg.Sets))
	for i, set := range cfg.Sets {
		if set == nil {
			continue
		}
		id := strings.TrimSpace(set.Id)
		if id == "" {
			id = fmt.Sprintf("set-%d", i)
		}
		setIDs = append(setIDs, id)
		strategyIDs = append(strategyIDs, id+":tcp="+set.TCP.Desync.Mode+":udp="+set.UDP.FakingStrategy+":frag="+set.Fragmentation.Strategy)
	}
	sort.Strings(setIDs)
	sort.Strings(strategyIDs)
	return GenerationMeta{ID: hash, ConfigHash: hash, SchemaVersion: cfg.System.Classifier.SchemaVersion, StrategyIDs: setIDsToStrategies(strategyIDs), SetIDs: setIDs, Validation: ValidationSummary{Valid: true, CheckedAt: now, ConfigSchema: cfg.System.Classifier.SchemaVersion}, CreatedAt: now}
}

func setIDsToStrategies(ids []string) []string { return append([]string(nil), ids...) }

func fingerprintConfig(cfg *config.Config) string {
	clone := cfg.Clone()
	clone.ConfigPath = ""
	clone.RuntimeGeneration = ""
	clone.System.WebServer.Password = ""
	clone.System.API.IPInfoToken = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sanitizeLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return limitString(b.String(), 64)
}
func limitString(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func cloneCanary(c CanaryOutcome) CanaryOutcome { return c }
