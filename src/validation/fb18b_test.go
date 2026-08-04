package validation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestFB18BCrosswalkStatuses is the executable core of FB-18B: every PASS
// entry must reference existing tests in the actual source tree (AST scan),
// every BLOCKED entry must name the open Beads task owning the gap, and
// NOT_APPLICABLE entries must carry the owner-documented reason. The registry
// is fail-closed: a missing evidence test fails the suite, it never
// self-heals into PASS.
func TestFB18BCrosswalkStatuses(t *testing.T) {
	entries := FB18BEntries()
	if len(entries) != 61 {
		t.Fatalf("ожидалось 61 требование (40 clauses + 17 invariants + 4 hold/replay), получено %d", len(entries))
	}
	violations := ValidateFB18BCrosswalk(entries)
	if len(violations) > 0 {
		for _, v := range violations {
			t.Errorf("FB-18B violation: %s", v)
		}
		t.Fatalf("реестр FB-18B невалиден: %d нарушений", len(violations))
	}
}

// TestFB18BCrosswalkCounts locks the aggregate status distribution so a
// false-green regression (e.g. PASS inserted without evidence) is caught.
func TestFB18BCrosswalkCounts(t *testing.T) {
	entries := FB18BEntries()
	var pass, blocked, na int
	for _, e := range entries {
		switch e.Status {
		case FB18BPass:
			pass++
		case FB18BBlocked:
			blocked++
		case FB18BNotApplicable:
			na++
		}
	}
	t.Logf("FB-18B statuses: PASS=%d BLOCKED=%d NOT_APPLICABLE=%d total=%d", pass, blocked, na, len(entries))
	if pass == 0 {
		t.Fatal("0 PASS: реестр не должен быть полностью заблокирован")
	}
	if blocked == 0 {
		t.Fatal("0 BLOCKED: все gaps должны быть зарегистрированы, пока открыты Beads-задачи")
	}
	for _, e := range entries {
		if e.Status == FB18BBlocked {
			id := e.BlockedBy.BeadsID
			if !strings.HasPrefix(id, "b4x-") {
				t.Errorf("%s: BlockedBy.BeadsID должен быть Beads id (b4x-*), получено %q", e.ID, id)
			}
		}
	}
}

// TestFB18BCrosswalkClauseIds checks that all 40 consolidated clauses
// 106..145 are present exactly once (mirrors the FB-18A extraction rule).
func TestFB18BCrosswalkClauseIds(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range FB18BEntries() {
		if e.Kind == "clause" {
			id := strings.TrimPrefix(e.ID, "ARCH-")
			if id == e.ID {
				t.Errorf("%s: clause id должен иметь вид ARCH-NNN", e.ID)
				continue
			}
			if seen[id] {
				t.Errorf("дубль clause ARCH-%s", id)
			}
			seen[id] = true
		}
	}
	for arch := 106; arch <= 145; arch++ {
		if !seen[strconv.Itoa(arch)] {
			t.Errorf("отсутствует clause ARCH-%d", arch)
		}
	}
}

// TestFB18BCrosswalkArtifact verifies (and optionally regenerates) the
// machine-readable crosswalk JSON artifact tied to the current document
// hashes. Run `go test -run TestFB18BCrosswalkArtifact -update` to
// regenerate B4X_FB18B_CROSSWALK.json after repository changes.
func TestFB18BCrosswalkArtifact(t *testing.T) {
	entries := SortFB18BEntries(FB18BEntries())
	data, err := FB18BCrosswalkReportJSON(entries, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// Репозиторий монтируется целиком (docker run -v D:/b4x:/b4x -w /b4x/src),
	// поэтому validation/../.. указывает на корень репо.
	artifact := filepath.Join(filepath.Dir(thisFile), "..", "..", "B4X_FB18B_CROSSWALK.json")
	if os.Getenv("UPDATE") != "" {
		if werr := os.WriteFile(artifact, data, 0o644); werr != nil {
			t.Fatal(werr)
		}
		t.Logf("artifact regenerated: %s", artifact)
		return
	}
	cur, rerr := os.ReadFile(artifact)
	if rerr != nil {
		t.Fatalf("artifact отсутствует: %v (запусти с UPDATE=1, если это первая генерация)", rerr)
	}
	// generated_at меняется при каждой генерации — сравниваем содержимое без времени.
	var dataObj, curObj map[string]any
	if jerr := json.Unmarshal(data, &dataObj); jerr != nil {
		t.Fatal(jerr)
	}
	if jerr := json.Unmarshal(cur, &curObj); jerr != nil {
		t.Fatal(jerr)
	}
	delete(dataObj, "generated_at")
	delete(curObj, "generated_at")
	if !reflect.DeepEqual(dataObj, curObj) {
		t.Fatalf("artifact устарел: запусти `UPDATE=1 go test -run TestFB18BCrosswalkArtifact ./validation/` в src/")
	}
}
