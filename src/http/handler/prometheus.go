// src/http/handler/prometheus.go
package handler

// Prometheus text-format exporter (FB-03 criterion 4): /metrics renders the
// internal observability metrics snapshot (observability.Default().Metrics)
// with identical names, labels and values, so scrapers observe the same
// counters the validation API and the hard-gate evaluation consume.
//
// Metric names are rendered as-is (they are already Prometheus-compatible
// [_a-zA-Z0-9]); label keys/values are escaped per the exposition format.
// Histograms are rendered as <name>_bucket{le=...} / <name>_sum / <name>_count.

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

// prometheusMetricsPath is the Prometheus scrape endpoint.
const prometheusMetricsPath = "/metrics"

// RegisterPrometheusAPI wires the Prometheus text exporter into the HTTP API.
func (api *API) RegisterPrometheusAPI() {
	api.mux.HandleFunc(prometheusMetricsPath, api.getPrometheusMetrics)
}

func (api *API) getPrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	snap := observability.Default().Metrics.Snapshot(time.Now().UTC())
	var b strings.Builder
	for _, counter := range snap.Counters {
		name := counter.Name
		fmt.Fprintf(&b, "# HELP %s %s\n", name, name)
		fmt.Fprintf(&b, "# TYPE %s counter\n", name)
		fmt.Fprintf(&b, "%s%s %d\n", name, prometheusLabels(counter.Labels), counter.Value)
	}
	for _, g := range snap.Gauges {
		name := g.Name
		fmt.Fprintf(&b, "# HELP %s %s\n", name, name)
		fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
		fmt.Fprintf(&b, "%s%s %d\n", name, prometheusLabels(g.Labels), g.Value)
	}
	for _, h := range snap.Histograms {
		name := h.Name
		fmt.Fprintf(&b, "# HELP %s %s\n", name, name)
		fmt.Fprintf(&b, "# TYPE %s histogram\n", name)
		labels := prometheusLabels(h.Labels)
		for _, bucket := range h.Buckets {
			fmt.Fprintf(&b, "%s_bucket%s %d\n", name, prometheusBucketLabels(labels, bucket.Le), bucket.Count)
		}
		fmt.Fprintf(&b, "%s_sum%s %s\n", name, labels, strconv.FormatFloat(h.Sum, 'g', -1, 64))
		fmt.Fprintf(&b, "%s_count%s %d\n", name, labels, h.Count)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// prometheusLabels renders a sorted label set in exposition format
// ({k="v",...}); empty label sets render as "" (no braces).
func prometheusLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(labels[k]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// prometheusBucketLabels appends the le label to the series labels for a
// histogram bucket.
func prometheusBucketLabels(labels string, le float64) string {
	leValue := strconv.FormatFloat(le, 'g', -1, 64)
	if math.IsInf(le, 1) {
		leValue = "+Inf"
	}
	if labels == "" {
		return fmt.Sprintf(`{le="%s"}`, leValue)
	}
	return fmt.Sprintf(`%s,le="%s"}`, strings.TrimSuffix(labels, "}"), leValue)
}

// escapeLabelValue escapes \ " and newline per the Prometheus exposition
// format.
func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}
