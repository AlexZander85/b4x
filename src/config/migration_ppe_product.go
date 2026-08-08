package config

import (
	"reflect"

	"github.com/daniellavrushin/b4/log"
)

// migrateV52to53 productizes the PPE configuration already introduced in v52.
// Existing installations remain in monitoring mode; per-flow exclusion still
// requires an explicit authenticated operator action.
func migrateV52to53(c *Config, _ map[string]interface{}) error {
	return migratePPEProductDefaults(c)
}

func migratePPEProductDefaults(c *Config) error {
	if c == nil {
		return nil
	}
	log.Tracef("Migration v52 PPE productization: preserving monitoring mode and adding safe defaults")
	capture := &c.System.Classifier.Runtime.Capture
	defaults := DefaultClassifierRuntimeConfig.Capture
	// Any config that reaches this migration comes from an existing
	// installation on disk (FB-21 owner decision 2026-08-03): auto-enable of
	// per-flow exclusion applies only to fresh installs that never produced a
	// config file. Mark the value as user-chosen so start-time integration
	// never flips an existing deployment into exclusion automatically.
	capture.OffloadPolicyUserChosen = true
	if capture.OffloadPolicy == "" {
		capture.OffloadPolicy = OffloadPolicyDetect
	}
	if reflect.DeepEqual(capture.PPE, PPEOffloadConfig{}) {
		capture.PPE = defaults.PPE
	}
	// Never migrate an existing installation into automatic exclusion or a
	// global offload change. Operators must enable per-flow exclusion explicitly.
	if capture.OffloadPolicy == OffloadPolicyDisableGlobal {
		capture.OffloadPolicy = OffloadPolicyDetect
	}
	return nil
}
