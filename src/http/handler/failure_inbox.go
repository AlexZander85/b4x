package handler

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/diagnostics"
)

var failureInbox atomic.Pointer[diagnostics.FailureInbox]

func init() {
	failureInbox.Store(diagnostics.Default())
}

func SetFailureInbox(inbox *diagnostics.FailureInbox) {
	if inbox == nil {
		failureInbox.Store(diagnostics.Default())
		return
	}
	failureInbox.Store(inbox)
}

func (api *API) RegisterFailureInboxAPI() {
	api.mux.HandleFunc("/api/diagnostics/failures", api.handleFailureCandidates)
}

type failureCandidatesResponse struct {
	Success     bool                           `json:"success"`
	GeneratedAt time.Time                      `json:"generated_at"`
	Candidates  []diagnostics.FailureCandidate `json:"candidates"`
}

func (api *API) handleFailureCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	limit := 128
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 128 {
			writeJsonError(w, http.StatusBadRequest, "limit must be between 1 and 128")
			return
		}
		limit = parsed
	}
	sendResponse(w, failureCandidatesResponse{Success: true, GeneratedAt: time.Now(), Candidates: failureInbox.Load().List(limit)})
}
