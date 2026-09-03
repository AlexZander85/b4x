package handler

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// Run artifacts (§83 GET /api/dns/v1/artifacts/{run_id}, §87 standard
// report). Reports are built from the same manager snapshot as status and
// metrics; raw qnames/endpoints are never included without explicit local
// diagnostic export.

const dnsArtifactStoreLimit = 64

// DNSRunArtifact is the persisted summary of one diagnosis run.
type DNSRunArtifact struct {
	RunID     string               `json:"run_id"`
	StartedAt time.Time            `json:"started_at"`
	Result    *DNSDiagnoseResult   `json:"result"`
	Status    map[string]any       `json:"status"`
	Trace     []dnspath.TraceEvent `json:"trace"`
}

var (
	dnsArtifacts   = map[string]DNSRunArtifact{}
	dnsArtifactSeq []string
	dnsArtifactsMu sync.Mutex
)

func storeDNSArtifact(a DNSRunArtifact) {
	dnsArtifactsMu.Lock()
	defer dnsArtifactsMu.Unlock()
	dnsArtifacts[a.RunID] = a
	dnsArtifactSeq = append(dnsArtifactSeq, a.RunID)
	for len(dnsArtifactSeq) > dnsArtifactStoreLimit {
		delete(dnsArtifacts, dnsArtifactSeq[0])
		dnsArtifactSeq = dnsArtifactSeq[1:]
	}
}

func newDNSRunID() string {
	return fmt.Sprintf("dnsrun-%d", time.Now().UnixNano())
}

// handleDNSArtifact serves one stored diagnosis run report.
func (api *API) handleDNSArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	runID := r.PathValue("run_id")
	dnsArtifactsMu.Lock()
	a, ok := dnsArtifacts[runID]
	dnsArtifactsMu.Unlock()
	if !ok {
		http.Error(w, `{"error":"artifact not found"}`, http.StatusNotFound)
		return
	}
	writeDNSJSON(w, a)
}
