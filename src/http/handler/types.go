package handler

import (
	"net/http"
	"sync/atomic"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/discovery"
	"github.com/daniellavrushin/b4/geodat"
	"github.com/daniellavrushin/b4/runtimecontrol"
)

type API struct {
	cfgPtr          *atomic.Pointer[config.Config]
	mux             *http.ServeMux
	geodataManager  *geodat.GeodataManager
	discoveryRT     *discovery.Runtime
	asnStore        *config.AsnStore
	runtimeControl  atomic.Pointer[runtimecontrol.Manager]
	ppeCapabilities PPECapabilityProvider
	ppeStatus       PPEStatusProvider

	overrideServiceManager func() string
}

func (a *API) SetPPEStatusProvider(provider PPEStatusProvider) {
	if a != nil {
		a.ppeStatus = provider
	}
}

func (a *API) SetRuntimeControlManager(manager *runtimecontrol.Manager) {
	if a != nil {
		a.runtimeControl.Store(manager)
	}
}

func (a *API) getRuntimeControlManager() *runtimecontrol.Manager {
	if a == nil {
		return nil
	}
	manager := a.runtimeControl.Load()
	if manager != nil {
		if cfg := a.getCfg(); cfg != nil {
			manager.SetEnabled(cfg.System.Classifier.Flags.TransactionalApplyEnabled)
		}
	}
	return manager
}

func (a *API) getCfg() *config.Config {
	if a == nil || a.cfgPtr == nil {
		return nil
	}
	return a.cfgPtr.Load()
}
