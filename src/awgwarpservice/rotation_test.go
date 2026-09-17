package awgwarpservice

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// TestEndpointRotation is the bd b4x-wh6 acceptance: an UNPINNED config keeps
// the whole seed pool and rotates on every loss (a dead endpoint is not
// terminal); an explicit endpoint is a PIN and never rotates.
func TestEndpointRotation(t *testing.T) {
	dir := t.TempDir()

	// Unpinned: the config resolves the seed-pool head and keeps the pool.
	c := config.NewConfig()
	c.System.Warp.AWG = config.WarpAWGConfig{
		Enabled:      true,
		IdentityPath: filepath.Join(dir, "slot.json"),
	}
	rt, err := Build(&c, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := twg.FieldVerifiedEndpoints()
	if len(rt.endpoints) != len(want) {
		t.Fatalf("unpinned pool = %d endpoints, want %d", len(rt.endpoints), len(want))
	}
	if got := rt.currentEndpoint(); got != want[0] {
		t.Fatalf("unpinned default = %s, want pool head %s", got, want[0])
	}
	if !rt.rotateEndpoint() {
		t.Fatal("unpinned runtime must rotate on loss")
	}
	if got := rt.currentEndpoint(); got != want[1] {
		t.Fatalf("after one rotation = %s, want %s", got, want[1])
	}
	for i := 0; i < len(want)-1; i++ {
		rt.rotateEndpoint()
	}
	if got := rt.currentEndpoint(); got != want[0] {
		t.Fatalf("after a full pass = %s, want back at the head %s", got, want[0])
	}

	// Pinned: an explicit endpoint must never rotate.
	const pin = "162.159.193.11:4500"
	c2 := config.NewConfig()
	c2.System.Warp.AWG = config.WarpAWGConfig{
		Enabled:      true,
		IdentityPath: filepath.Join(dir, "slot2.json"),
		Endpoint:     pin,
	}
	rt2, err := Build(&c2, Options{Now: time.Now})
	if err != nil {
		t.Fatalf("build pinned: %v", err)
	}
	if len(rt2.endpoints) != 0 {
		t.Fatalf("pinned runtime kept a pool of %d", len(rt2.endpoints))
	}
	if rt2.rotateEndpoint() {
		t.Fatal("a pinned endpoint must not rotate")
	}
	if got := rt2.currentEndpoint().String(); got != pin {
		t.Fatalf("pinned endpoint = %s, want %s", got, pin)
	}
}
