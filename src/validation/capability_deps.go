package validation

// FB-36 (b4x-0yf): capability dependency graph — execution scheduling
// (отдельно от verdict aggregation). Данные: capability_deps.gen.go
// (генерируется из specs/registries/capability_dependencies.yaml, паттерн
// FB-33/FB-34). Логика живёт здесь — генерируемый файл не редактируется.
//
// Норматив (B4X_AUDIT_FIX_TASKS v2 §FB-36): физическое исполнение может
// быть параллельным там, где безопасно (parallel capabilities), но
// dependency aggregation строгое: missing upstream dependency blocks
// downstream PASS. Ранний WARP-тест не удовлетворяет отсутствующий
// MON/ABD/DDI dependency.

import (
	"fmt"
	"sort"
)

// CapabilityDependencyClosure возвращает транзитивное замыкание upstream
// capability для данного id, топологически упорядоченное (dependencies
// first), с самим id последним. Ошибка — для неизвестного id или цикла в
// графе (fail-closed: потребитель не агрегирует частичный набор).
func CapabilityDependencyClosure(id string) ([]string, error) {
	if _, ok := CapabilityByID(id); !ok {
		return nil, fmt.Errorf("unknown capability %q", id)
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var order []string
	var visit func(n string) error
	visit = func(n string) error {
		color[n] = gray
		c, _ := CapabilityByID(n)
		for _, d := range c.Requires {
			if _, ok := CapabilityByID(d); !ok {
				return fmt.Errorf("requires %q of %q is not a registered capability", d, n)
			}
			switch color[d] {
			case gray:
				return fmt.Errorf("cyclic capability graph involving %q", d)
			case white:
				if err := visit(d); err != nil {
					return err
				}
			}
		}
		color[n] = black
		order = append(order, n)
		return nil
	}
	if err := visit(id); err != nil {
		return nil, err
	}
	return order, nil
}

// CapabilityExecutionOrder возвращает полный нормативный порядок исполнения
// capability (topological sort, dependencies first). Внутри одной волны
// (layer) строгие (non-parallel) capability идут в каноническом порядке
// реестра, параллельные — после них; порядок детерминирован, поэтому
// планировщик, исполняющий в этом порядке, не зависит от порядка входных
// данных. Используется как канонический FullRunOrder (orchestration.go).
func CapabilityExecutionOrder() []string {
	all := Capabilities()
	byID := map[string]CapabilityDependency{}
	for _, c := range all {
		byID[c.ID] = c
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var order []string
	// Посещаем в каноническом порядке реестра, внутри слоя — строгие
	// сначала: детерминированный топосорт для параллельных capability.
	sorted := make([]CapabilityDependency, len(all))
	copy(sorted, all)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Layer != sorted[j].Layer {
			return sorted[i].Layer < sorted[j].Layer
		}
		if sorted[i].Parallel != sorted[j].Parallel {
			return !sorted[i].Parallel
		}
		return sorted[i].ID < sorted[j].ID
	})
	var visit func(n string)
	visit = func(n string) {
		if color[n] != white {
			return
		}
		color[n] = gray
		for _, d := range byID[n].Requires {
			visit(d)
		}
		color[n] = black
		order = append(order, n)
	}
	for _, c := range sorted {
		visit(c.ID)
	}
	return order
}

// CapabilityExecutionWaves группирует capability в волны параллельного
// физического исполнения по layer: все capability одной волны могут
// исполняться одновременно (после того как завершены все предыдущие волны).
func CapabilityExecutionWaves() [][]string {
	order := CapabilityExecutionOrder()
	byID := map[string]CapabilityDependency{}
	for _, c := range Capabilities() {
		byID[c.ID] = c
	}
	var waves [][]string
	lastLayer := -1
	for _, id := range order {
		layer := byID[id].Layer
		if layer != lastLayer {
			waves = append(waves, nil)
			lastLayer = layer
		}
		waves[len(waves)-1] = append(waves[len(waves)-1], id)
	}
	return waves
}

// CapabilityExecutionSchedule возвращает порядок исполнения подмножества
// requested capability (топосорт, dependencies first). Неизвестный id —
// ошибка (fail-closed), цикл в графе — ошибка. Результат детерминирован и
// не зависит от порядка элементов requested (проверяется тестом
// TestShuffledCapabilityExecutionSameSchedule).
func CapabilityExecutionSchedule(requested []string) ([]string, error) {
	want := map[string]bool{}
	for _, id := range requested {
		if _, ok := CapabilityByID(id); !ok {
			return nil, fmt.Errorf("unknown capability %q", id)
		}
		want[id] = true
	}
	full := CapabilityExecutionOrder()
	var out []string
	for _, id := range full {
		if want[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// CapabilityUpstreamBlocked возвращает список upstream capability, чей
// вердикт отсутствует в verdicts или не является PASS/PASS_WITH_LIMITATIONS.
// Пустой список — downstream может быть PASS (если сам исполнен и прошёл).
func CapabilityUpstreamBlocked(id string, verdicts map[string]Verdict) []string {
	c, ok := CapabilityByID(id)
	if !ok {
		return nil
	}
	var blocked []string
	for _, dep := range c.Requires {
		v, seen := verdicts[dep]
		if !seen || (v != Pass && v != PassWithLimitations) {
			blocked = append(blocked, dep)
		}
	}
	return blocked
}

// CapabilityUpstreamSatisfied — контракт «missing upstream dependency blocks
// downstream PASS»: true только когда каждый upstream имеет PASS.
func CapabilityUpstreamSatisfied(id string, verdicts map[string]Verdict) bool {
	return len(CapabilityUpstreamBlocked(id, verdicts)) == 0
}

// AggregateCapabilityVerdicts агрегирует вердикты исполненных capability
// строго по графу зависимостей (FB-36 criterion: missing upstream dependency
// blocks downstream PASS). Семантика:
//   - обязательный capability без вердикта -> BLOCKED (fail-closed);
//   - downstream PASS при неудовлетворённом upstream -> BLOCKED;
//   - Fail/Blocked любого исполненного capability -> BLOCKED;
//   - PassWithLimitations -> PassWithLimitations;
//   - иначе PASS.
//
// Агрегация map-based: результат не зависит от порядка результатов —
// shuffled suite execution даёт тот же вердикт.
func AggregateCapabilityVerdicts(verdicts map[string]Verdict) Verdict {
	optional := map[string]bool{}
	for _, c := range Capabilities() {
		if c.Optional {
			optional[c.ID] = true
		}
	}
	hasLimitations := false
	for _, c := range Capabilities() {
		v, seen := verdicts[c.ID]
		if !seen {
			if !c.Optional {
				return Blocked // fail-closed: обязательный capability не исполнен
			}
			continue
		}
		if !CapabilityUpstreamSatisfied(c.ID, verdicts) {
			return Blocked // missing upstream dependency
		}
		switch v {
		case Fail, Blocked:
			return Blocked
		case PassWithLimitations:
			hasLimitations = true
		case Pass:
		default:
			return Blocked
		}
	}
	if hasLimitations {
		return PassWithLimitations
	}
	return Pass
}

// VerifyCapabilityDependencyNames — runtime guard (паттерн FB-34.1): возвращает
// имена, не являющиеся каноническими capability id. nil при полном резолве.
// Потребители планировщика вызывают guard до исполнения, чтобы неизвестный
// capability не попал в график молча.
func VerifyCapabilityDependencyNames(names []string) []string {
	var unknown []string
	for _, n := range names {
		if _, ok := CapabilityByID(n); !ok {
			unknown = append(unknown, n)
		}
	}
	return unknown
}

// CapabilityDependencyRegistryValid reports whether the generated capability
// dependency registry passes all integrity checks (see
// ValidateCapabilityDependencyRegistry).
func CapabilityDependencyRegistryValid() bool {
	return len(ValidateCapabilityDependencyRegistry()) == 0
}

// ValidateCapabilityDependencyRegistry проверяет целостность генерируемого
// реестра (зеркалирует validate_capability_deps.py --check, но работает
// только по .gen.go — детерминированно внутри go test, без checkout YAML):
// дубликаты id, orphan requires, ацикличность, монотонность layer,
// консистентность parallel-волн, declared total, нормативные якоря.
func ValidateCapabilityDependencyRegistry() []string {
	var errs []string
	all := Capabilities()
	byID := map[string]CapabilityDependency{}
	for _, c := range all {
		if _, dup := byID[c.ID]; dup {
			errs = append(errs, "duplicate capability id "+c.ID)
		}
		byID[c.ID] = c
		if c.ID == "" {
			errs = append(errs, "capability without id")
		}
		if c.Name == "" {
			errs = append(errs, c.ID+": missing name")
		}
	}
	if len(all) != CapabilityDeclaredTotal {
		errs = append(errs, fmt.Sprintf("computed %d != declared %d", len(all), CapabilityDeclaredTotal))
	}
	for _, c := range all {
		for _, dep := range c.Requires {
			dc, ok := byID[dep]
			if !ok {
				errs = append(errs, c.ID+": requires unknown capability "+dep)
			} else if dc.Layer >= c.Layer {
				errs = append(errs, fmt.Sprintf("%s: requires %s with layer %d >= own layer %d", c.ID, dep, dc.Layer, c.Layer))
			}
		}
	}
	// Ацикличность: топосорт по requires.
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var visit func(n string) bool // true = цикл найден
	visit = func(n string) bool {
		color[n] = gray
		for _, d := range byID[n].Requires {
			switch color[d] {
			case gray:
				return true
			case white:
				if visit(d) {
					return true
				}
			}
		}
		color[n] = black
		return false
	}
	for _, c := range all {
		if color[c.ID] == white && visit(c.ID) {
			errs = append(errs, "cyclic capability graph involving "+c.ID)
		}
	}
	// Parallel-волны: layer должен быть ровно max(requires)+1.
	for _, c := range all {
		if !c.Parallel {
			continue
		}
		maxReq := -1
		for _, d := range c.Requires {
			if l := byID[d].Layer; l > maxReq {
				maxReq = l
			}
		}
		if c.Layer != maxReq+1 {
			errs = append(errs, fmt.Sprintf("%s: parallel layer %d != max(requires)+1 (%d)", c.ID, c.Layer, maxReq+1))
		}
	}
	// Нормативные якоря строгой цепочки.
	for _, a := range []string{"classifier", "visibility", "progress", "mon", "abd", "ddi", "canary", "warp", "service_profile"} {
		if _, ok := byID[a]; !ok {
			errs = append(errs, "normative chain anchor missing: "+a)
		}
	}
	return errs
}
