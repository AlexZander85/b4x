package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/crossservice"
)

func (api *API) handleClassifierIsolationValidation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input crossservice.ValidationInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid cross-service validation report: "+err.Error())
		return
	}
	report := crossservice.Default().ValidateAndStore(input, time.Now().UTC())
	sendResponse(w, report)
}
