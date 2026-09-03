// Fabricated device profile and the Proton anti-abuse challenge frame
// (design §1.3, port of Nova ProtonApi.kt:228-243 + ProtonProfileStore.kt
// buildDeviceProfile).
//
// The frame keys are taken from the LIVE Nova code, not from the design
// doc's illustrative JSON: the field-verified v1.31 client sends
//
//	{"Payload": {"vpn-android-v4-challenge-0": {
//	  "v","appLang","timezone","deviceName","regionCode","timezoneOffset",
//	  "isJailbreak","preferredContentSize","storageCapacity","isDarkmodeOn",
//	  "keyboards"}}}
//
// i.e. the wire keys are `deviceName` (carrying the hash value) and
// `storageCapacity` (carrying the byte count); the design doc's
// deviceNameHash/storageBytes spellings are the STRUCT field names, not the
// wire keys. Owner verified this exact frame live.
//
// Values are FABRICATED ONCE per install and persisted in the identity
// (Nova ProtonApi.kt:192-200 rationale: real Build values would be a device
// fingerprint handed to a third party for nothing, and per-call random
// values look worse to the anti-abuse layer than one constant set).
// Rotation space: 5 models x 5 locales x 3 storage sizes; deviceNameHash in
// [1e12, 9e15).
package proton

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ChallengeFrameKey is the frame key Proton's android client v4 uses.
const ChallengeFrameKey = "vpn-android-v4-challenge-0"

// ChallengeFrameVersion is the frame version Nova v1.31 sends.
const ChallengeFrameVersion = "2.0.7"

// deviceModel and deviceLocale mirror the Nova rotation tables
// (ProtonProfileStore.kt buildDeviceProfile).
type deviceModel struct{ Model, AndroidVersion string }

var deviceModels = []deviceModel{
	{"Pixel 7", "13"},
	{"SM-A536B", "13"},
	{"SM-S911B", "14"},
	{"Redmi Note 12", "13"},
	{"moto g84 5G", "14"},
}

type deviceLocale struct {
	Language, RegionCode, Timezone string
	Offset                         int
}

var deviceLocales = []deviceLocale{
	{"fr", "FR", "Europe/Paris", -60},
	{"de", "DE", "Europe/Berlin", -60},
	{"en", "GB", "Europe/London", 0},
	{"nl", "NL", "Europe/Amsterdam", -60},
	{"es", "ES", "Europe/Madrid", -60},
}

var deviceStorages = []float64{6.4e10, 1.28e11, 2.56e11}

// GenerateDeviceProfile fabricates one install-stable device profile from r
// (production: crypto/rand; tests: a deterministic reader). The same
// distribution as Nova: uniform model x locale x storage, deviceNameHash
// uniform in [1e12, 9e15).
func GenerateDeviceProfile(r io.Reader) (DeviceProfile, error) {
	if r == nil {
		r = rand.Reader
	}
	draw := func(n int) (uint32, error) {
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint32(b[:]) % uint32(n), nil
	}
	mi, err := draw(len(deviceModels))
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("proton: device profile: %w", err)
	}
	li, err := draw(len(deviceLocales))
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("proton: device profile: %w", err)
	}
	si, err := draw(len(deviceStorages))
	if err != nil {
		return DeviceProfile{}, fmt.Errorf("proton: device profile: %w", err)
	}
	var raw [8]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return DeviceProfile{}, fmt.Errorf("proton: device profile: %w", err)
	}
	const (
		hashMin uint64 = 1_000_000_000_000
		hashMax uint64 = 9_000_000_000_000_000 // exclusive
	)
	nameHash := hashMin + binary.LittleEndian.Uint64(raw[:])%(hashMax-hashMin)

	return DeviceProfile{
		Model:          deviceModels[mi].Model,
		AndroidVersion: deviceModels[mi].AndroidVersion,
		Language:       deviceLocales[li].Language,
		RegionCode:     deviceLocales[li].RegionCode,
		Timezone:       deviceLocales[li].Timezone,
		TimezoneOffset: deviceLocales[li].Offset,
		StorageBytes:   deviceStorages[si],
		DeviceNameHash: int64(nameHash),
		Keyboards:      []string{"com.google.android.inputmethod.latin"},
	}, nil
}

// UserAgent renders the Nova header shape
// "ProtonVPN/<ver> (Android <ver>; <model>)" (ProtonApi.kt:57-58).
func (p DeviceProfile) UserAgent(appVersion string) string {
	return "ProtonVPN/" + appVersion + " (Android " + p.AndroidVersion + "; " + p.Model + ")"
}

// ChallengeFrame builds the anti-abuse frame exactly as the live Nova client
// does (ProtonApi.kt:230-243): one map under ChallengeFrameKey inside
// Payload. Deterministic for a given profile — the stability test pins it.
func (p DeviceProfile) ChallengeFrame() map[string]any {
	keyboards := append([]string(nil), p.Keyboards...)
	sort.Strings(keyboards) // stable output order
	return map[string]any{
		"v":                    ChallengeFrameVersion,
		"appLang":              p.Language,
		"timezone":             p.Timezone,
		"deviceName":           p.DeviceNameHash,
		"regionCode":           p.RegionCode,
		"timezoneOffset":       p.TimezoneOffset,
		"isJailbreak":          false,
		"preferredContentSize": "1.0",
		"storageCapacity":      p.StorageBytes,
		"isDarkmodeOn":         true,
		"keyboards":            keyboards,
	}
}

// ChallengeBody wraps the frame into the POST body:
// {"Payload": {"<key>": {...frame...}}}.
func (p DeviceProfile) ChallengeBody() map[string]any {
	return map[string]any{
		"Payload": map[string]any{
			ChallengeFrameKey: p.ChallengeFrame(),
		},
	}
}

// Validate performs the config-side sanity checks of a loaded profile (a
// corrupted identity must fail loudly, not produce an absurd frame).
func (p DeviceProfile) Validate() error {
	if strings.TrimSpace(p.Model) == "" {
		return fmt.Errorf("%w: device profile model empty", ErrIdentityInvalid)
	}
	if p.DeviceNameHash < 1_000_000_000_000 || p.DeviceNameHash >= 9_000_000_000_000_000 {
		return fmt.Errorf("%w: device_name_hash out of range", ErrIdentityInvalid)
	}
	if p.StorageBytes <= 0 {
		return fmt.Errorf("%w: storage_bytes non-positive", ErrIdentityInvalid)
	}
	if p.Timezone == "" || p.Language == "" || p.RegionCode == "" {
		return fmt.Errorf("%w: device profile locale incomplete", ErrIdentityInvalid)
	}
	return nil
}
