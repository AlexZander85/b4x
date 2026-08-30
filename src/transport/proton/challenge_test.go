package proton

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// deterministicProfileReader feeds GenerateDeviceProfile so the profile is
// reproducible in tests (production uses crypto/rand).
func deterministicProfileReader(b byte) *bytes.Reader {
	return bytes.NewReader([]byte{
		b, 0, 0, 0, // model index
		b + 1, 0, 0, 0, // locale index
		b + 2, 0, 0, 0, // storage index
		0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, // name hash
	})
}

func TestGenerateDeviceProfileDeterministic(t *testing.T) {
	p1, err := GenerateDeviceProfile(deterministicProfileReader(0))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	p2, err := GenerateDeviceProfile(deterministicProfileReader(0))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !reflect.DeepEqual(p1, p2) {
		t.Fatalf("profile generation not deterministic: %+v != %+v", p1, p2)
	}
	if err := p1.Validate(); err != nil {
		t.Fatalf("generated profile invalid: %v", err)
	}
}

func TestGenerateDeviceProfileSpace(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		p, err := GenerateDeviceProfile(deterministicProfileReader(byte(i)))
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if p.DeviceNameHash < 1_000_000_000_000 || p.DeviceNameHash >= 9_000_000_000_000_000 {
			t.Fatalf("deviceNameHash out of range: %d", p.DeviceNameHash)
		}
		if p.StorageBytes <= 0 {
			t.Fatalf("storage non-positive: %v", p.StorageBytes)
		}
		blob, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(blob)] = true
	}
	// The rotation space is 5x5x3; 64 deterministic draws must land on more
	// than one point.
	if len(seen) < 2 {
		t.Fatal("profile rotation space collapsed")
	}
}

// TestChallengeFrameShape pins the frame against the LIVE Nova client
// (ProtonApi.kt:230-243): the wire keys are deviceName (hash value) and
// storageCapacity (bytes); v is "2.0.7"; isJailbreak false;
// preferredContentSize "1.0"; isDarkmodeOn true.
func TestChallengeFrameShape(t *testing.T) {
	p := DeviceProfile{
		Model:          "Pixel 7",
		AndroidVersion: "13",
		Language:       "fr",
		RegionCode:     "FR",
		Timezone:       "Europe/Paris",
		TimezoneOffset: -60,
		StorageBytes:   6.4e10,
		DeviceNameHash: 3746281946382741,
		Keyboards:      []string{"com.google.android.inputmethod.latin"},
	}
	frame := p.ChallengeFrame()

	if got := frame["v"]; got != "2.0.7" {
		t.Fatalf("frame v = %v want 2.0.7", got)
	}
	if got := frame["appLang"]; got != "fr" {
		t.Fatalf("appLang = %v", got)
	}
	if got := frame["timezone"]; got != "Europe/Paris" {
		t.Fatalf("timezone = %v", got)
	}
	if got, ok := frame["deviceName"].(int64); !ok || got != 3746281946382741 {
		t.Fatalf("deviceName = %v (%T) want hash int64", frame["deviceName"], frame["deviceName"])
	}
	if got := frame["regionCode"]; got != "FR" {
		t.Fatalf("regionCode = %v", got)
	}
	if got := frame["timezoneOffset"]; got != -60 {
		t.Fatalf("timezoneOffset = %v", got)
	}
	if got := frame["isJailbreak"]; got != false {
		t.Fatalf("isJailbreak = %v", got)
	}
	if got := frame["preferredContentSize"]; got != "1.0" {
		t.Fatalf("preferredContentSize = %v", got)
	}
	if got, ok := frame["storageCapacity"].(float64); !ok || got != 6.4e10 {
		t.Fatalf("storageCapacity = %v (%T)", frame["storageCapacity"], frame["storageCapacity"])
	}
	if got := frame["isDarkmodeOn"]; got != true {
		t.Fatalf("isDarkmodeOn = %v", got)
	}
	kb, ok := frame["keyboards"].([]string)
	if !ok || len(kb) != 1 || kb[0] != "com.google.android.inputmethod.latin" {
		t.Fatalf("keyboards = %v", frame["keyboards"])
	}

	// No legacy design-doc key spellings on the wire.
	for _, legacy := range []string{"deviceNameHash", "storageBytes"} {
		if _, present := frame[legacy]; present {
			t.Fatalf("legacy wire key %q must not be present", legacy)
		}
	}
}

// TestChallengeFrameStable pins the one-profile-one-frame rule: the JSON
// serialization of the frame for a given profile is byte-stable (the
// anti-abuse layer must see one constant profile, not churn).
func TestChallengeFrameStable(t *testing.T) {
	p := DeviceProfile{
		Model: "SM-S911B", AndroidVersion: "14", Language: "de", RegionCode: "DE",
		Timezone: "Europe/Berlin", TimezoneOffset: -60, StorageBytes: 1.28e11,
		DeviceNameHash: 1234567890123, Keyboards: []string{"com.google.android.inputmethod.latin"},
	}
	a, err := json.Marshal(p.ChallengeBody())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p.ChallengeBody())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("frame unstable:\n%s\n%s", a, b)
	}

	// The body wraps the frame under the fixed key inside Payload.
	var body map[string]map[string]map[string]any
	if err := json.Unmarshal(a, &body); err != nil {
		t.Fatalf("body shape: %v", err)
	}
	payload, ok := body["Payload"]
	if !ok {
		t.Fatal("missing Payload wrapper")
	}
	if _, ok := payload[ChallengeFrameKey]; !ok {
		t.Fatalf("missing frame key %s", ChallengeFrameKey)
	}
}

func TestDeviceProfileValidate(t *testing.T) {
	valid := DeviceProfile{Model: "Pixel 7", Language: "fr", RegionCode: "FR",
		Timezone: "Europe/Paris", StorageBytes: 6.4e10, DeviceNameHash: 3746281946382741}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	lowHash := valid
	lowHash.DeviceNameHash = 999
	if err := lowHash.Validate(); err == nil {
		t.Fatal("out-of-range hash accepted")
	}
	noModel := valid
	noModel.Model = ""
	if err := noModel.Validate(); err == nil {
		t.Fatal("empty model accepted")
	}
}
