package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/discovery"
	"github.com/daniellavrushin/b4/lab"
	"github.com/daniellavrushin/b4/nfq"
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

var clientHelloSession atomic.Pointer[lab.SessionController]

// fakeProfileCatalog is the explicit catalog of compiled fake profiles. It is
// nil until wired by the process bootstrap (server.go). Compiled profiles are
// only added through the compile endpoint with explicit license review, and
// are never auto-promoted: the compiler always returns Active=false and the
// catalog itself never flips Active.
var fakeProfileCatalog atomic.Pointer[discovery.FakeProfileCatalog]

// SetFakeProfileCatalog binds the process-wide fake profile catalog used by
// the lab compile workflow.
func SetFakeProfileCatalog(catalog *discovery.FakeProfileCatalog) {
	if catalog == nil {
		fakeProfileCatalog.Store(nil)
		return
	}
	fakeProfileCatalog.Store(catalog)
}

// FakeProfileCatalog exposes the bound fake profile catalog for read-only
// process lifecycle access. Returns nil when not wired.
func FakeProfileCatalog() *discovery.FakeProfileCatalog {
	return fakeProfileCatalog.Load()
}

// SetClientHelloSessionController binds the lab session controller owned by
// the HTTP/process bootstrap. The controller attaches the production sink only
// while an authorized capture session is running.
func SetClientHelloSessionController(controller *lab.SessionController) {
	if controller == nil {
		clientHelloSession.Store(nil)
		return
	}
	clientHelloSession.Store(controller)
}

// ClientHelloSessionController exposes the bound lab session controller for
// process lifecycle hooks (e.g. stopping an active capture on shutdown).
func ClientHelloSessionController() *lab.SessionController {
	return clientHelloSession.Load()
}

func (api *API) RegisterClientHelloLabAPI() {
	api.mux.HandleFunc("/api/lab/clienthello", api.handleClientHelloProfiles)
	api.mux.HandleFunc("/api/lab/clienthello/start", api.handleClientHelloStart)
	api.mux.HandleFunc("/api/lab/clienthello/stop", api.handleClientHelloStop)
	api.mux.HandleFunc("/api/lab/clienthello/status", api.handleClientHelloStatus)
	api.mux.HandleFunc("/api/lab/clienthello/compile", api.handleClientHelloCompile)
	api.mux.HandleFunc("/api/lab/clienthello/compiled", api.handleCompiledProfiles)
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

type clientHelloStartRequest struct {
	ClientIP        string `json:"client_ip"`
	ClientMAC       string `json:"client_mac"`
	DurationSeconds int    `json:"duration_seconds"`
	SourceApp       string `json:"source_app"`
}

type clientHelloStartResponse struct {
	Success   bool   `json:"success"`
	SessionID string `json:"session_id"`
	State     string `json:"state"`
}

func (api *API) handleClientHelloStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	controller := clientHelloSession.Load()
	if controller == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "clienthello lab session controller is not available")
		return
	}
	var req clientHelloStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	filter, err := buildHelloFilterFromRequest(req)
	if err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	cfg := api.getCfg()
	base := config.DefaultClassifierRuntimeConfig.ClientHelloLab
	if cfg != nil {
		base = cfg.System.Classifier.Runtime.ClientHelloLab
	}
	capture := lab.DefaultCaptureRequest()
	capture.Filter = filter
	capture.SourceApp = req.SourceApp
	if req.DurationSeconds > 0 {
		capture.Duration = time.Duration(req.DurationSeconds) * time.Second
	} else if base.CaptureDurationSeconds > 0 {
		capture.Duration = time.Duration(base.CaptureDurationSeconds) * time.Second
	}
	capture.MaxFlows = base.MaxFlows
	capture.MaxProfiles = base.MaxProfiles
	capture.MaxBytesPerFlow = base.MaxBytesPerFlow
	capture.MaxBytesTotal = base.MaxBytesTotal
	capture.MaxSegmentsPerFlow = base.MaxSegmentsPerFlow
	capture.Source = "lab-api"
	capture.Interface = "nfqueue"
	capture.ConfigGeneration = nfq.ConfigGeneration(api.getCfg())
	capture.Retention = clientHelloCatalog.Load()

	sessionID, err := controller.Start(capture)
	if err != nil {
		if err == lab.ErrSessionActive {
			writeJsonError(w, http.StatusConflict, "a clienthello capture session is already active")
			return
		}
		writeJsonError(w, http.StatusBadRequest, "cannot start capture session: "+err.Error())
		return
	}
	sendResponse(w, clientHelloStartResponse{Success: true, SessionID: sessionID, State: string(lab.SessionRunning)})
}

type clientHelloStatusResponse struct {
	Success bool        `json:"success"`
	Status  interface{} `json:"status"`
}

func (api *API) handleClientHelloStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	controller := clientHelloSession.Load()
	if controller == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "clienthello lab session controller is unavailable")
		return
	}
	controller.Stop()
	sendResponse(w, clientHelloStatusResponse{Success: true, Status: controller.Status()})
}

func (api *API) handleClientHelloStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	controller := clientHelloSession.Load()
	if controller == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "clienthello lab session controller is unavailable")
		return
	}
	sendResponse(w, clientHelloStatusResponse{Success: true, Status: controller.Status()})
}

// InvalidateLabSessionForConfig stops any active lab capture session whose
// generation differs from the newly applied config. Called on config reload
// and runtime transactions so capture artifacts never mix across generations.
func InvalidateLabSessionForConfig(cfg *config.Config) {
	controller := clientHelloSession.Load()
	if controller == nil {
		return
	}
	controller.InvalidateGeneration(nfq.ConfigGeneration(cfg))
}

func buildHelloFilterFromRequest(req clientHelloStartRequest) (lab.ClientFilter, error) {
	filter := lab.ClientFilter{}
	if req.ClientIP != "" {
		ip := net.ParseIP(req.ClientIP)
		if ip == nil {
			return lab.ClientFilter{}, errors.New("invalid client_ip")
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !addr.Is4() && !addr.Is6() {
			return lab.ClientFilter{}, errors.New("client_ip must be an IPv4 or IPv6 address")
		}
		filter.IP = addr.Unmap()
		filter.Client = classifier.ClientKey{SourceIP: filter.IP}
	}
	if req.ClientMAC != "" {
		parsed, err := net.ParseMAC(req.ClientMAC)
		if err != nil || len(parsed) != 6 {
			return lab.ClientFilter{}, errors.New("invalid client_mac (expected 6-byte EUI-48)")
		}
		copy(filter.MAC[:], parsed)
		filter.HasMAC = true
	}
	if err := filter.Validate(); err != nil {
		return lab.ClientFilter{}, err
	}
	return filter, nil
}

// clientHelloCompileRequest is the explicit lab compile workflow input. The
// source ClientHello is provided as raw bytes by the operator (base64) — the
// capture retention is privacy-safe and intentionally never stores raw bytes,
// so compiling from a captured profile is not possible by design. The request
// is never stored; only the compile result (ChangeReport + metadata) and, on
// explicit commit, the catalog registration.
type clientHelloCompileRequest struct {
	// SourceArtifactID is an optional human reference (e.g. a captured
	// profile ID) recorded in provenance. It does not need to exist.
	SourceArtifactID string `json:"source_artifact_id,omitempty"`
	// RawHello is the base64-encoded raw ClientHello (TLS record framing
	// included, as produced by capture). Bounded by the metadata parser cap.
	RawHello string `json:"raw_hello"`
	// Mode is one of lab.CompileMode values.
	Mode string `json:"mode"`
	// ReplacementSNI, when set, is written into the compiled hello.
	ReplacementSNI string `json:"replacement_sni,omitempty"`
	// MTU estimator inputs. Family defaults to the artifact source family.
	MTU            int    `json:"mtu,omitempty"`
	TCPOptionsSize int    `json:"tcp_options_size,omitempty"`
	IPFamily       string `json:"ip_family,omitempty"`
	Seed           int64  `json:"seed,omitempty"`
	Provenance     string `json:"provenance,omitempty"`
	// Commit fields: when CommitToCatalog is true the compiled artifact is
	// registered in the fake profile catalog. This requires an explicit
	// license review; the catalog never auto-promotes (Active stays false).
	CommitToCatalog bool   `json:"commit_to_catalog,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Source          string `json:"source,omitempty"`
	License         string `json:"license,omitempty"`
	LicenseReviewed bool   `json:"license_reviewed,omitempty"`
}

type clientHelloCompileResponse struct {
	Success      bool                `json:"success"`
	Profile      lab.CompiledProfile `json:"profile"`
	ChangeReport lab.ChangeReport    `json:"change_report"`
	Committed    bool                `json:"committed"`
}

func (api *API) handleClientHelloCompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req clientHelloCompileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.RawHello)
	if err != nil || len(raw) == 0 {
		writeJsonError(w, http.StatusBadRequest, "raw_hello must be valid base64 of the raw ClientHello")
		return
	}
	defer clear(raw)

	// Build the explicit source artifact boundary; the compiler copies the
	// input and validates it with the production TLS metadata parser.
	source := lab.CapturedHelloProfile{
		ID:        limitString(req.SourceArtifactID, 96),
		IPFamily:  strings.ToLower(req.IPFamily),
		SourceApp: "lab-compile-api",
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	source.HelloHash = hash
	source.SHA256 = hash
	sourceID := limitString(req.SourceArtifactID, 96)
	if sourceID == "" {
		// The artifact ID is part of the compiled profile identity; derive a
		// stable opaque default from the raw hash when the operator did not
		// provide a reference.
		sourceID = "lab-compile-" + hash[:16]
	}
	artifact, err := lab.NewRawClientHelloArtifact(sourceID, source, raw, "lab-compile-api")
	if err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid source ClientHello: "+err.Error())
		return
	}

	mtu := lab.MTUEstimator{Family: req.IPFamily, MTU: req.MTU, TCPOptionsBytes: req.TCPOptionsSize}
	if mtu.Family == "" {
		mtu.Family = "ipv4"
	}
	compileRequest := lab.CompileRequest{
		Source:         artifact,
		Mode:           lab.CompileMode(req.Mode),
		ReplacementSNI: req.ReplacementSNI,
		MTU:            mtu,
		Seed:           req.Seed,
		Provenance:     limitString(req.Provenance, 128),
	}
	compiled, err := lab.CompileFakeProfile(compileRequest)
	if err != nil {
		if errors.Is(err, lab.ErrSNIAbsent) || errors.Is(err, lab.ErrInvalidReplacementSNI) || errors.Is(err, lab.ErrMTUExceeded) || errors.Is(err, lab.ErrMultiPacketDisabled) {
			writeJsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJsonError(w, http.StatusBadRequest, "compile failed: "+err.Error())
		return
	}
	if err := compiled.Validate(); err != nil {
		writeJsonError(w, http.StatusInternalServerError, "compiled artifact failed schema validation: "+err.Error())
		return
	}

	response := clientHelloCompileResponse{Success: true, Profile: compiled.Profile, ChangeReport: compiled.Profile.ChangeReport}

	if req.CommitToCatalog {
		catalog := fakeProfileCatalog.Load()
		if catalog == nil {
			writeJsonError(w, http.StatusServiceUnavailable, "fake profile catalog is not available")
			return
		}
		kind := discovery.FakeProfileKind(strings.TrimSpace(req.Kind))
		if kind == "" {
			kind = discovery.ProfileGeneratedNeutral
		}
		registration := discovery.ProfileRegistration{
			ID:              compiled.Profile.ID,
			Kind:            kind,
			Source:          limitString(req.Source, 128),
			Provenance:      limitString(req.Provenance, 256),
			License:         limitString(req.License, 128),
			LicenseReviewed: req.LicenseReviewed,
		}
		if err := catalog.AddCompiled(registration, compiled); err != nil {
			if errors.Is(err, discovery.ErrProfileLicense) {
				writeJsonError(w, http.StatusBadRequest, "license review is required to commit a compiled profile")
				return
			}
			writeJsonError(w, http.StatusBadRequest, "catalog commit failed: "+err.Error())
			return
		}
		response.Committed = true
	}
	sendResponse(w, response)
}

type compiledProfilesResponse struct {
	Success  bool                       `json:"success"`
	Profiles []discovery.CatalogProfile `json:"profiles"`
	Count    int                        `json:"count"`
}

// limitString bounds metadata strings at API boundaries. The catalog itself
// applies stricter limits; this only prevents unbounded request inputs.
func limitString(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}

func (api *API) handleCompiledProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	catalog := fakeProfileCatalog.Load()
	if catalog == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "fake profile catalog is not available")
		return
	}
	profiles := catalog.Profiles()
	sendResponse(w, compiledProfilesResponse{Success: true, Profiles: profiles, Count: len(profiles)})
}
