# PPE — Field Handbook (находки и решения на реальном Keenetic)

> Практический справочник по подсистеме per-flow PPE exclusion (b4). Дополняет
> дизайн-спеки: [B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md](B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md),
> [docs/audit/PPE_IMPLEMENTATION_AUDIT.md](docs/audit/PPE_IMPLEMENTATION_AUDIT.md),
> [docs/reports/ppe/](docs/reports/ppe/). Здесь — что реально найдено на железе
> (iptables 1.4.21, Keenetic NDM), какие баги исправлены и как диагностировать.
> Сессия: 2026-08-17, ветка `agent/classifier-v2.3-capture-envelope`, коммит `8583f511`.

---

## 1. Текущее состояние (проверено на роутере 192.168.1.1/.152)

- Правила `B4_PPE_PRE`/`B4_PPE_FWD` установлены и живут (reassert 55 с): tcp:443 + udp:443,
  `connskip 30`, `match-set b4_managed_devices src`, `-j PPE`; owned-jumps первые в
  PREROUTING/FORWARD. Счётчики растут — трафик реально матчится.
- Visibility: `mode=complete`, `last_verdict=PASS_WITH_LIMITATIONS`, `production_ready=true`
  (reason: «complete bidirectional visibility proven; limited apply permitted by configuration»).
- Audit (`issue-bundle`): `apply success=true`, `self-test success=true automatic:PASS_WITH_LIMITATIONS`.
- Процесс: S99b4, `b4 --config=/opt/etc/b4/b4.json`.

## 2. Ключевые файлы кода

| Файл | Роль |
|---|---|
| `src/config/classifier_v23.go` | `PPESelfTestConfig`: `mode`, `controlled_endpoint`, `health_endpoint`, `timeout_ms` |
| `src/config/ppe_validation.go` | валидация URL-ов selftest (health_endpoint — http/https) |
| `src/capture/ppe/compiler_types.go` | `Compile()`: желаемое состояние, generation, intersection портов, scopeArgs (`-m set --match-set <set> src`) |
| `src/capture/ppe/compiler_family.go` | `compileFamily()`/`compileRules()`: формат правил, **guard ipv6+managed-scope**, restore-скрипт |
| `src/capture/ppe/transaction.go` | Apply: на семейство Install(:154) → Verify(:156); reconcile-обёртка `reconcile apply at family %s` |
| `src/capture/ppe/backend_iptables_apply.go` | Install (chains, jumps, rules) и Verify (сравнение с desired) — **`equalRules` order-insensitive** |
| `src/capture/ppe/backend_iptables_core.go` | Snapshot через `iptables -S`, owned-jumps (`isOwnedJump`) |
| `src/capture/ppe/backend_iptables_helpers.go` | `list`/`run` (`-w -t mangle`), `desiredChainRules`, `equalRules`, `sortedCopy` |
| `src/capture/ppe/backend_parse.go` | `splitRuleLine` (снимает кавычки/экранирование), `isOwnedJump`, `hasArgPair` |
| `src/capture/ppe/selftest_isolation.go` | A/B-изоляция: `BeginBypass` (RETURN-правила по sport), `safeRunID` (лимит 128) |
| `src/capture/ppe/selftest_controller_core.go` | запуск probe, health-check, вердикты |
| `src/capture/ppe/selftest_verdict.go` | вердикты PASS / PASS_WITH_LIMITATIONS / INCONCLUSIVE и т.д. |
| `src/capture/ppe/visibility_gate_state.go` | гейт: `VisibilityComplete` + `provenForGeneration` |
| `src/capture/ppe/product_service.go` | `ApplyConfig`, `automaticSelfTestRequest` (startup-and-change), `maybeRunAutomaticSelfTest` (single-flight, RunID `auto-<generation>`), `selectProbeSourcePort` |
| `src/capture/ppe/product_bundle.go` | `issue-bundle`: audit-трейл, visibility, правила (redact) |
| `src/capture/ppe/counters.go` | счётчики `ipv4/B4_PPE_PRE/{tcp,udp}` из `-L -v -x` |
| `src/cmd/ppe-probe/main.go` | probe CLI: A/B probe, tun-источник, регистрация в managed-set (`--managed-set`) |

## 3. Поток исполнения (важно для отладки)

1. `ApplyConfig` (product_service.go:390) → `Compile` → `transactions.Apply(desired)` →
   на каждое активное семейство: **Install → Verify** (transaction.go:154-156).
   Любая ошибка → audit `apply success=false reason=...` и активной генерации НЕТ.
2. Успех → `VisibilityGate.EnsureRequired(generation)` → `maybeRunAutomaticSelfTest()`:
   нужен mode `startup-and-change` + `controlled_endpoint` + активная генерация +
   generation не proven. RunID автотеста = `auto-<64hex generation>` (69 символов).
3. Selftest: `BeginBypass` (A/B RETURN-правила `b4:ppe:selftest:<run_id>:tcp|quic` по sport,
   вставляются в начало B4_PPE_PRE/FWD) → probe (tun) шлёт трафик на controlled endpoint →
   observer собирает evidence (порт 443) → вердикт → gate: complete/not.

**Без активной генерации selftest не запускается**: API `POST self-test` → `per-flow
exclusion must be active before running the controlled self-test`. Поэтому сначала чин
apply, потом selftest.

## 4. Модель правил (что реально стоит)

```
# chain: B4_PPE_PRE / B4_PPE_FWD
-A B4_PPE_PRE -m set --match-set b4_managed_devices src -p tcp -m multiport --dports 443 \
   -m connskip --connskip 30 -m comment --comment b4:ppe:v1:tcp -j PPE
# jumps (добавляются -I 1):
-A PREROUTING -m comment --comment b4:ppe:v1:jump:pre -j B4_PPE_PRE
-A FORWARD   -m comment --comment b4:ppe:v1:jump:fwd -j B4_PPE_FWD
```

- Константы: `compiler_types.go` — ChainPre/ChainFwd, CommentJumpPre/Fwd, CommentTCP/QUIC.
- `scopeArgs` (managed-devices) добавляются ПЕРЕД `-p tcp` — но iptables 1.4.21 в `-S`
  печатает `-p tcp` ПЕРВЫМ, а comment — в кавычках. См. находку #1.

## 5. Находки на реальном железе и исправления

### #1 (главный баг) Verify: «owned PPE rules differ from desired generation»
- Симптом: audit `startup-apply`/`apply` `success=false`, reason
  `reconcile apply at family ipv4: owned PPE rules differ from desired generation`;
  цепочки B4_PPE_* не создаются/не живут; selftest не идёт.
- Причина: `equalRules` сравнивал аргументы правил ПОРЯДКО-ЗАВИСИМО
  (`strings.Join(args, "\x00")`). iptables v1.4.21 в выводе `-S` ПЕРЕСТАВЛЯЕТ
  `-p tcp` перед `-m set --match-set ... src` (компилятор генерирует scope первым).
  Воспроизведено вручную на роутере: `-A ... -m set ... src -p tcp ...` → `-S` даёт
  `-A ... -p tcp -m set ... src ...`. Install ставил правило корректно, но Verify
  считал его чужим → откат.
- Фикс: `equalRules` — сравнение **отсортированных** копий аргументов (`sortedCopy`),
  `backend_iptables_helpers.go`. Порядок опций семантически неважен; сортировка не
  ослабляет защиту (другое число правил/порт/target по-прежнему ловятся).
- Тест: `backend_iptables_helpers_test.go`.
- Сигнал для будущих: если снова «differ» — сравнить `iptables -t mangle -S B4_PPE_PRE`
  с plan.Rules (формат из compiler_family.go).

### #2 Кавычки в `-S` — не баг
- `iptables -S` печатает comment в кавычках: `--comment "b4:ppe:v1:tcp"`.
  `splitRuleLine` (backend_parse.go) корректно снимает кавычки и `\`-экранирование —
  это НЕ расхождение. Проблема была только в порядке (#1).

### #3 ipv6 + managed-devices scope несовместимы
- Симптом: после фикса #1 ipv4 прошёл, ipv6 упал на install:
  `ip6tables: The protocol family of set b4_managed_devices is IPv4, which is not applicable`.
- Причина: `b4_managed_devices` — `hash:ip family inet` (**IPv4-only**; проверено
  `ipset list b4_managed_devices -t`). v6-набора нет и наполнять нечем (probe
  регистрирует только IPv4 tun-IP).
- Фикс: guard в `compileFamily` (compiler_family.go): ipv6 + set-scope → в режиме
  `auto` семейство выключается (Reason `managed-devices scope is IPv4-only; IPv6 PPE
  disabled in auto mode`), в режиме `on` — `ErrFamilyRequiredUnsupported`.
- Тест: `TestCompileIPv6ManagedScopeDisabledInAuto` (compiler_test.go).
- Если понадобится IPv6 со scope: нужен отдельный inet6-ipset + его наполнение.

### #4 safeRunID: лимит 64 → 128
- Симптом: автоselftest сразу INCONCLUSIVE: `failure_stage=phase_a_isolation`,
  evidence `invalid self-test run_id`.
- Причина: RunID автотеста = `auto-` + 64-hex generation = **69 символов** > 64.
- Фикс: `safeRunID` (selftest_isolation.go): max 128 (iptables comment вмещает 255).
- Тест: `selftest_isolation_test.go`.

### #5 Retransmission-контраст (выбор controlled endpoint)
- А/Б-контраст требует, чтобы endpoint НЕ ACK'ал payload → наблюдаются ретрансмиссии.
- Проверенный вариант: `https://77.88.8.8/health` (77.88.8.8:443) — контраст работает
  (в итоговом прогоне `outgoing_retrans_seen: true`, `tcp_bidirectional_complete: true`).
- Health-проверка selftest'а — на ОТДЕЛЬНОМ `health_endpoint`: не должен быть тем же
  контролируемым endpoint'ом.

### #6 health_endpoint и порт 443
- Пассивный observer классифицирует пакеты по порту 443 (источник/назначение);
  probe-трафик идёт на 443. Health-сервер должен слушать **порт 443**, иначе его
  ответы не попадут в наблюдение: `http://192.168.1.40:443/health` (Python
  `http.server` на Windows, PID держать живым). GET/HEAD → 200
  `{"protocol":"b4-ppe-self-test/v1","healthy":true}`.
- Источник probe (sport) НЕ должен входить в PPE-порты (`selectProbeSourcePort`).

### #7 allow_limited_apply → PASS_WITH_LIMITATIONS → production_ready
- Если А/Б не показал offload-зависимого контраста, но видимость полная
  (bidirectional complete), вердикт `PASS_WITH_LIMITATIONS`; `production_ready=true`
  ТОЛЬКО при `config.PPESelfTestConfig.AllowLimitedApply`. Иначе гейт остаётся
  `unknown` с reason `active runtime requires controlled PPE visibility proof`.

### #8 run_id результата автотеста
- Результат автотеста ищется по `run_id=auto-<generation>` (НЕ `auto`):
  `GET /api/v1/capture/offload/self-test/result?run_id=auto-66e68556...`.

## 6. Диагностика на роутере (по порядку)

```sh
ps w | grep -E 'bin/b4' | grep -v grep        # процесс (pgrep -x b4 НЕНАДЁЖЕН)
curl -s http://127.0.0.1:7000/api/v1/capture/offload/status       # state/effective_mode/visibility
curl -s http://127.0.0.1:7000/api/v1/capture/offload/issue-bundle # audit: reasons ошибок apply/selftest
G=$(curl -s http://127.0.0.1:7000/api/v1/capture/offload/status | grep -oE '"generation":"[a-f0-9]{64}"' | head -1 | cut -d'"' -f4)
curl -s "http://127.0.0.1:7000/api/v1/capture/offload/self-test/result?run_id=auto-$G"  # вердикт+evidence
iptables -t mangle -L B4_PPE_PRE B4_PPE_FWD -v -n -x --line-numbers  # правила и счётчики
iptables -t mangle -S B4_PPE_PRE              # фактический формат после нормализации
ipset list b4_managed_devices -t              # тип набора (должен быть hash:ip inet)
```

Первое, что смотреть при проблемах: **audit в issue-bundle** (там точная причина
каждого провала apply/selftest) и наличие активной генерации (status → visibility).

## 7. Деплой (проверенный путь)

- `/opt/sbin/b4` → symlink → `/tmp/mnt/37fdc502-d92b-dd01-3075-c402d92bdd01/bin/b4`
  (uuid каталога может отличаться — искать через `readlink /opt/sbin/b4`).
- S99b4: `b4 --config=/opt/etc/b4/b4.json`; бэкапы перед заменой: `bin/b4.prev`,
  `/opt/etc/b4/b4.json.bak`.
- Сборка: docker, `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '-s -w'`.
- Передача на роутер: HTTP-сервер (например `python -m http.server 8000` на хосте) →
  `curl -fsS -o b4.new http://192.168.1.40:8000/b4-arm64` →
  **обязательно `chmod +x`** (curl даёт 644, иначе «Permission denied» при старте) →
  `mv -f b4.new bin/b4` → `/opt/etc/init.d/S99b4 start` (после `stop`).
- Single-instance lock: второй запуск → `Error: another b4 instance is already
  running (pid N)` — сначала убить старый процесс.
- `S99b4 stop` убивает только процессы с именем `b4`: исторический ручной
  `b4.t9` оставался живым и держал порт/правила — искать через `ps w | grep b4`.
- Логи: без `--log-dir` stderr → `/tmp/log/b4/errors.log` (при S99b4 — /dev/null),
  ручной запуск `nohup /opt/sbin/b4 --config=/opt/etc/b4/b4.json --verbose trace
  > /tmp/b4.log 2>&1 &`; время роутера UTC+5, логи b4 — UTC.
- Health-сервер selftest (Windows, PID 9996, `b4_health.py` на 0.0.0.0:443) —
  держать живым, пока в конфиге указан `health_endpoint`.

## 8. Питфоллы (симптом → причина → фикс)

1. `apply success=false ... owned PPE rules differ from desired generation` →
   iptables 1.4.21 переставляет аргументы в `-S` → сравнение order-insensitive (#1).
2. `install rule ... ip6tables: protocol family of set ... is IPv4` → managed-scope
   IPv4-only → ipv6 auto off / on=ошибка (#3).
3. `INCONCLUSIVE, phase_a_isolation, invalid self-test run_id` → run_id > 64 →
   лимит 128 (#4).
4. S99b4 stop не убивает процесс → другое имя процесса (b4.t9) → kill вручную.
5. `Permission denied` при старте → бинарник 644 после curl → `chmod +x`.
6. `self-test result not found` → неверный run_id: автотест = `auto-<generation>` (#8).
7. selftest не запускается вообще → нет активной генерации (упал apply) →
   чинить apply по audit, а не selftest.
8. `No chain/target/match` в счётчиках/правилах → правила не установлены →
   смотреть audit apply (обычно #1).

## 9. Ограничения и нерешённое

- IPv6 PPE отключён при `source_scope: managed-devices` (нет inet6-ipset).
- QUIC: udp:443 правила стоят, но реального QUIC-трафика от managed devices на
  роутере не было (счётчик udp 0); selftest-контраст по QUIC прошёл через probe.
- Health-сервер — временный (Windows python); для продакшена — на роутере/хосте.
- Полный `go test ./...`: 3 pre-existing инфраструктурных фейла (cmd/b4-validate —
  нет `artifacts/`; validation — нет `B4X_FB18B_CROSSWALK.json` и findValidationDir);
  новые регрессии отсутствуют.
- Конфиг на роутере: `allow_limited_apply: true`, `self_test: {mode:
  startup-and-change, controlled_endpoint: https://77.88.8.8/health, health_endpoint:
  http://192.168.1.40:443/health, timeout_ms: 5000}`.

## 10. Проверка изменений (локально)

```sh
docker run --rm -v D:\b4x\src:/src -v gocache:/go -w /src golang:1.25-alpine sh -c \
  "go build ./... && go vet ./capture/ppe/ && go test ./capture/ppe/"
```
