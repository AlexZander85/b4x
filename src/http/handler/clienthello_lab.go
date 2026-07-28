package handler

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/lab"
)

var clientHelloCatalog atomic.Pointer[lab.MemoryRetention]

func init() {
	clientHelloCatalog.Store(lab.NewMemoryRetention(64))
}

func SetClientHelloCatalog(catalog *lab.MemoryRetention) {
	if catalog == nil {
		clientHelloCatalog.Store(lab.NewMemoryRetention(64))
		return
	}
	clientHelloCatalog.Store(catalog)
}

func (api *API) RegisterClientHelloLabAPI() {
	api.mux.HandleFunc("/api/lab/clienthello", api.handleClientHelloProfiles)
}

type clientHelloProfilesResponse struct {
	Success     bool                     `json:"success"`
	GeneratedAt time.Time                `json:"generated_at"`
	Profiles    []lab.ClientHelloProfile `json:"profiles"`
}

func (api *API) handleClientHelloProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sendResponse(w, clientHelloProfilesResponse{Success: true, GeneratedAt: time.Now(), Profiles: clientHelloCatalog.Load().List()})
}
