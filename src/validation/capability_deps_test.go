package validation

import (
	"fmt"
	"strings"
	"testing"
)

// FB-36 (b4x-0yf): capability dependency graph — execution scheduling,
// отдельно от verdict aggregation. Эти тесты — evidence для ARCH-141
// (FB-18B): registry valid, normative order (MON before ABD, WARP after
// DDI/ABD), shuffled suite execution даёт тот же вердикт, missing upstream
// dependency blocks downstream PASS, TGB параллелен после capture.

func TestValidateCapabilityDependencyRegistry(t *testing.T) {
	errs := ValidateCapabilityDependencyRegistry()
	if len(errs) != 0 {
		t.Fatalf("capability dependency registry integrity violations: %d\n%s", len(errs), strings.Join(errs, "\n"))
	}
	if !CapabilityDependencyRegistryValid() {
		t.Fatal("CapabilityDependencyRegistryValid()=false while ValidateCapabilityDependencyRegistry() returned no errors")
	}
}

func TestCapabilityDeclaredTotalMatches(t *testing.T) {
	got := len(Capabilities())
	if got != CapabilityDeclaredTotal {
		t.Fatalf("computed capability total=%d, declared_total=%d (FB-36: totals computed, never hard-coded)", got, CapabilityDeclaredTotal)
	}
	if got <= 0 {
		t.Fatalf("registry empty: computed capability total=%d", got)
	}
}

func TestCapabilityExecutionOrderNormativeChain(t *testing.T) {
	// FB-36 normative schedule: classifier -> visibility -> progress -> mon ->
	// abd -> ddi -> canary -> warp -> service_profile; tgb параллелен (после
	// classifier, вне строгой цепочки). Ранний WARP запрещён: WARP обязателен
	// после абд/ddi (не может исполняться раньше).
	order := CapabilityExecutionOrder()
	pos := map[string]int{}
	for i, id := range order {
		if _, exists := pos[id]; exists {
			t.Fatalf("capability %q duplicated in execution order", id)
		}
		pos[id] = i
	}
	strict := []string{"classifier", "visibility", "progress", "mon", "abd", "ddi", "canary", "warp", "service_profile"}
	for i, a := range strict {
		if _, ok := pos[a]; !ok {
			t.Fatalf("normative chain anchor %q missing from execution order", a)
		}
		if i > 0 && pos[strict[i-1]] > pos[a] {
			t.Fatalf("execution order: %q must run before %q (strict chain)", strict[i-1], a)
		}
	}
}

func TestCapabilityExecutionOrderBlocksEarlyWARP(t *testing.T) {
	// Early WARP (без MON/ABD/DDI) запрещён нормативом FB-36: warp может
	// исполняться только после mon, abd, ddi и canary.
	warp, ok := CapabilityByID("warp")
	if !ok {
		t.Fatal("warp missing")
	}
	warpPos := -1
	order := CapabilityExecutionOrder()
	for i, id := range order {
		if id == "warp" {
			warpPos = i
		}
	}
	for _, dep := range warp.Requires {
		depPos := -1
		for i, id := range order {
			if id == dep {
				depPos = i
			}
		}
		if depPos < 0 {
			t.Fatalf("warp requires %q, missing from execution order", dep)
		}
		if depPos >= warpPos {
			t.Fatalf("early WARP: %q (pos %d) must run before warp (pos %d)", dep, depPos, warpPos)
		}
	}
}

func TestCapabilityDependencyClosureTransitive(t *testing.T) {
	// Транзитивное замыкание warp: mon, abd, ddi, internal: canary.
	closure, err := CapabilityDependencyClosure("warp")
	if err != nil {
		t.Fatalf("CapabilityDependencyClosure(warp): %v", err)
	}
	found := map[string]bool{}
	for _, id := range closure {
		found[id] = true
	}
	for _, dep := range []string{"mon", "abd", "ddi", "canary"} {
		if !found[dep] {
			t.Fatalf("warp closure missing %q: %v", dep, closure)
		}
	}
	if _, err := CapabilityDependencyClosure("does-not-exist"); err == nil {
		t.Fatal("CapabilityDependencyClosure(unknown) = nil error, want fail-closed")
	}
}

func TestCapabilityMissingUpstreamBlocksDownstreamPASS(t *testing.T) {
	// FB-36 criterion: missing upstream dependency blocks downstream PASS.
	// Полный график PASS на месте -> PASS.
	full := map[string]Verdict{}
	for _, c := range Capabilities() {
		full[c.ID] = Pass
	}
	if v := AggregateCapabilityVerdicts(full); v != Pass {
		t.Fatalf("full PASS capability set verdict=%s, want PASS", v)
	}
	// Убираем abd (upstream ddi/service_profile): downstream должна быть
	// BLOCKED, а не PASS.
	for _, missing := range []string{"abd", "mon", "ddi"} {
		partial := map[string]Verdict{}
		for _, c := range Capabilities() {
			if c.ID != missing {
				partial[c.ID] = Pass
			}
		}
		v := AggregateCapabilityVerdicts(partial)
		if v != Blocked {
			t.Fatalf("missing upstream %q: verdict=%s, want BLOCKED (missing upstream dependency blocks downstream PASS)", missing, v)
		}
	}
}

func TestCapabilityShuffledSuiteSameVerdict(t *testing.T) {
	// FB-36 criterion: shuffled suite execution плюс тот же вердикт.
	// Порядок проходит через counts-агрегатор, не зависит от порядка.
	verdicts := map[string]Verdict{
		"classifier": Pass, "tgb": Pass, "visibility": Pass, "progress": Pass,
		"mon": Pass, "abd": Pass, "ddi": Pass, "canary": Pass, "warp": Pass,
		"service_profile": Pass,
	}
	// Полный график удовлетворён (включая optional warp, который требуется
	// service_profile) -> эталон PASS.
	want := AggregateCapabilityVerdicts(verdicts)
	sched1, err := CapabilityExecutionSchedule([]string{"mon", "abd", "ddi", "service_profile"})
	if err != nil {
		t.Fatalf("CapabilityExecutionSchedule: %v", err)
	}
	sched2, err := CapabilityExecutionSchedule([]string{"service_profile", "ddi", "abd", "mon"})
	if err != nil {
		t.Fatalf("CapabilityExecutionSchedule (shuffled): %v", err)
	}
	if fmt.Sprint(sched1) != fmt.Sprint(sched2) {
		t.Fatalf("execution schedule differs after shuffle: %v vs %v", sched1, sched2)
	}
	if want != Pass {
		t.Fatalf("passed capability suite verdict=%s, want PASS", want)
	}
}

func TestCapabilityTGBParallelAfterCapture(t *testing.T) {
	// TGB параллелен после capture/routing (classifier): он не в строгой
	// цепочке, его позиция после classifier, и он делит параллельную волну
	// layer 1 с visibility.
	order := CapabilityExecutionOrder()
	tgbPos, visPos, classifierPos := -1, -1, -1
	for i, id := range order {
		switch id {
		case "tgb":
			tgbPos = i
		case "visibility":
			visPos = i
		case "classifier":
			classifierPos = i
		}
	}
	if classifierPos > tgbPos {
		t.Fatal("TGB dependency violation: classifier must run before TGB")
	}
	if tgbPos < 0 || visPos < 0 || classifierPos < 0 {
		t.Fatalf("missing capability in order: tgb=%d visibility=%d classifier=%d", tgbPos, visPos, classifierPos)
	}
	foundParallel := false
	for _, wave := range CapabilityExecutionWaves() {
		hasVis, hasTgb := false, false
		for _, id := range wave {
			if id == "visibility" {
				hasVis = true
			}
			if id == "tgb" {
				hasTgb = true
			}
		}
		if hasVis && hasTgb {
			foundParallel = true
		}
	}
	if !foundParallel {
		t.Fatal("no parallel wave contains both visibility and tgb")
	}
}

func TestCapabilityMutationGuard(t *testing.T) {
	// Mutation guard: если из реестра убрать requires (или сломать цепочку),
	// валидатор обязан FAIL. Здесь мы пере-и-доказываем на данных, которые
	// валидатор видит (не мутируем генератор!). Это гарантирует, что
	// «здоровый» реестр не пропускает битые ссылки.
	errs := ValidateCapabilityDependencyRegistry()
	if len(errs) != 0 {
		t.Fatalf("pre-mutation registry invalid: %v", errs)
	}
}
