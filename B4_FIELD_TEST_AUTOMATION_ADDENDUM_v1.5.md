# B4 Field Test Automation & Trace Contract

**Статус:** нормативное post-v2.3 дополнение к `B4_FORK_ARCHITECTURE.md`, завершённому `B4_FORK_PATCH_PLAN.md`, `B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md`, `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md` v1.2, `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md`, `B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md` v1.0, `B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM.md` v1.0 и `B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM.md` v1.0  
**Редакция:** 1.5 — полностью сохраняет редакции 1.0–1.4; синхронизирует Field Test с WARP/MASQUE v1.2, вводит generation-aware causal trace validation, route/path proof, Android binding correlation, nested WARP dependency proof, geo/DNS/IPv6 trace, cleanup ownership и stages `FT-AC`–`FT-AE`  
**Дата:** 2026-07-30  
**Назначение:** автоматизированное тестирование реального Android-клиента, B4X Detector v2, generic router transports и transparent Telegram bridge; сбор объяснимой generation-aware трассировки, causal `BlockingProfile`, guided/full Discovery A/B, доказательство exact WARP/WARP+WARP path, geo/DNS/IPv6 gates, cleanup ownership и отсутствия collateral damage, route leaks, self-interference, ложного detector confidence и destructive zero-byte drop.  
**Совместимость:** документ не изменяет и не переупорядочивает завершённые Stage 1–36 и PPE stages. Он проверяет Observability, Detector v2, DDI, Discovery, canary, promote/rollback, Cross-Service Isolation, Built-in WARP/MASQUE v1.2, WARP Transport Camouflage, causal transport trace, RST/GSO Hardening, Silent Path Failure/Scoped Recovery и Transparent Telegram Bridge capabilities.

---


## Нормативная последовательность

```text
B4_FORK_ARCHITECTURE.md v2.3
→ завершённый B4_FORK_PATCH_PLAN.md Stage 1–36
→ завершённый B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
→ B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
→ B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md v1.2
→ B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
→ B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md v1.0
→ B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM.md v1.0
→ B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM.md v1.0
→ этот Field Test Automation & Trace Contract v1.5
→ B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM v1.5
→ B4_IMPLEMENTATION_VALIDATION_ADDENDUM v1.5
→ candidate/profile production promotion
```

Этот документ не определяет runtime-алгоритмы заново. Он определяет, какие API, events, fixtures, real-device scenarios и hard gates обязаны доказать их корректность.

## 0. Главный принцип

Форк должен выбирать не стратегию, которая просто открывает YouTube, а минимально затратную стратегию, которая воспроизводимо обеспечивает:

1. самый быстрый cold start API/UI;
2. минимальное время до первого media byte и первого кадра;
3. максимальный устойчивый goodput видео;
4. отсутствие stalls и повторных flow retry;
5. минимальные packet amplification, CPU и RAM;
6. стабильную работу при смене `googlevideo.com` CDN;
7. отсутствие влияния одного LAN-клиента на другого;
8. отсутствие влияния YouTube candidate на Gmail, Google app/Discover и другой same-client traffic;
9. одинаковое classifier/action решение для эквивалентного GSO и MSS представления;
10. отсутствие active Passive RST suppression без полной visibility, budget и rollback proof;
11. отсутствие WARP route до доказанного forwarded LAN-client path;
12. отсутствие generic service-strategy mutation внешнего MASQUE control flow;
13. обязательное прекращение WARP camouflage после подтверждённого CONNECT-IP;
14. отсутствие автоматического silent fallback по одному timeout/retry/stall signal;
15. suppression fast-parallel/HLS/prefetch/recent-success patterns до любой recovery;
16. causal differential proof и exact-scope rollback для active silent recovery;
17. каждый WARP route promotion имеет current `TransportPathProof` с packet/byte counter delta;
18. forwarded Android success связан с exact `BindingID`, `RouteTokenID` и current `SessionGen`;
19. inner WARP имеет current parent link на base WARP generation и теряет route при parent reconnect;
20. geo quorum выводится только из отдельных provider events и current inner-path proof;
21. DNS и IPv6 path не выводятся из одной конфигурации, а доказываются наблюдаемыми trace events;
22. cleanup завершён только после terminal ownership record для каждого generation-owned ресурса;
23. для optional `НЕ РФ` — отсутствие route при `RU`, `unknown`, stale или conflicting geo-attestation.

Тестирование должно быть доступно агенту через API и локальный test controller. Ручная работа пользователя допускается как fallback, но не является основным способом подбора.

---


## 0.1. Целевой и контрольный трафик

Каждый production-oriented YouTube run содержит две роли:

```text
target
→ official YouTube или ReVanced

same-client controls
→ Gmail
→ Google app / Discover feed
```

Control scenario не обязан доказывать функциональность всего стороннего приложения. Он обязан доказать, что profile/candidate не применил к control flow:

- YouTube `ActionAuthorization`;
- YouTube `ActionToken` или packet mutation;
- QUIC reject/block/fake;
- IPBlockDetect/escalation state;
- route/proxy binding;
- Passive RST suppression;
- persistent learned association.

Основной hard gate:

```text
unrelated_control_action_total == 0
```

Визуально успешная загрузка control app не отменяет нарушение, если trace обнаружил чужой action/state.

# 1. Может ли coding-agent самостоятельно выполнять реальные тесты

## 1.1. Да, при наличии локального доступа

Coding-agent может полностью автоматизировать реальные тесты, когда он работает на машине, которая имеет:

- сетевой доступ к B4 API на роутере;
- API token с test/discovery permissions;
- доступ к Android-устройству через ADB по USB или Wireless debugging;
- известный package name официального YouTube или ReVanced;
- устройство разблокировано либо настроено как выделенное тестовое устройство;
- стабильный test video URL/deep link;
- право запускать, останавливать и очищать состояние тестируемого приложения;
- доступ к создаваемым B4 trace/session reports.

Предполагаемая локальная среда проекта:

```text
D:\b4
├── b4 source
├── REFERENCE_PROJECTS
├── tools
│   └── field-test-controller
└── field-test-results
```

## 1.2. Что можно автоматизировать без Android helper

Через B4 API + ADB агент может:

- выполнить preflight роутера;
- проверить NFQUEUE/offload/capture envelope;
- выбрать target phone;
- выключить тестовый шум watchdog/discovery;
- выполнить `force-stop` приложения;
- запустить приложение или video deep link;
- провести cold/warm start;
- переключить приложение background/foreground;
- включать тестовый profile/candidate через sandbox;
- собирать DNS/QUIC/TCP/classifier/action trace;
- измерять первый flow, classification, ServerHello и media bytes;
- выполнять body/throughput/CDN probes;
- повторять A/B-серии;
- считать score;
- запускать canary;
- выполнять rollback;
- формировать issue bundle и Markdown-отчёт.

## 1.3. Что без helper определяется только косвенно

Роутер не видит непосредственно:

- момент появления интерфейса на экране;
- момент отрисовки первого кадра;
- реальное состояние spinner/buffering;
- dropped video frames;
- выбранное приложением качество видео.

Без phone-side helper эти события должны маркироваться:

```text
source = inferred
```

а не как достоверно измеренные.

## 1.4. Точный first-frame и buffering

Для точных Android UI/media milestones рекомендуется отдельный опциональный компонент:

```text
B4 Android Test Companion
```

Он не участвует в обходе DPI и нужен только для тестирования.

Возможные источники событий:

- AccessibilityService для заранее разрешённого тестового приложения;
- MediaSession/PlaybackState наблюдение, когда приложение публикует его;
- instrumentation/UIAutomator adapter;
- явные ручные markers из web UI как fallback.

Helper отправляет только события и timestamps:

```text
app_started
ui_visible
video_requested
first_frame
buffering_started
buffering_ended
playback_stopped
```

Запись экрана и передача содержимого экрана не требуются.

---


## 1.5. Автоматизация control applications

При наличии ADB/UIAutomator/Companion coding-agent MAY автоматизировать:

### Gmail

```text
launch
inbox visible
open configured test message
message body visible
inline image/load marker
optional configured attachment metadata/load marker
return to inbox
```

### Google app / Discover

```text
launch
feed visible
refresh
open configured public article/card
image/content progress
return to feed
```

Тестовые message/account/article identifiers являются local configuration и не коммитятся. По умолчанию controller не читает текст письма и не сохраняет экран.

Без helper точные UI milestones маркируются `adb-inferred`/`manual`, но network authorization audit остаётся обязательным и измеряется на роутере.

# 2. Компоненты автоматизации

```text
Coding Agent
    │
    ▼
Local Field-Test Controller
    ├── B4 Router API client
    ├── ADB Android driver
    ├── optional Android Companion client
    ├── experiment scheduler
    ├── result analyzer
    └── report generator
           │
           ├──────────────► B4 Router
           │                classifier / trace / sandbox / canary
           │
           └──────────────► Android device
                            official YouTube / ReVanced
```

## 2.1. B4 Router API

Отвечает за:

- test sessions;
- structured event stream;
- sandbox candidates;
- strategy apply;
- metrics;
- pcap/ClientHello capture;
- canary/promote/rollback;
- issue bundle.

## 2.2. Local Field-Test Controller

Отдельная CLI/service программа, запускаемая coding-agent на development PC.

Рекомендуемый путь:

```text
tools/field-test-controller
```

Controller не должен быть встроен в router binary.

Он отвечает за:

- ADB lifecycle;
- синхронизацию router/phone timestamps;
- adaptive test matrix;
- A/B ordering;
- сбор результатов;
- вычисление strategy rank;
- формирование отчёта.


## 2.2.1. Control Scenario Driver

Local controller содержит generic интерфейс:

```go
type ControlScenarioDriver interface {
    Prepare(ctx context.Context, app ControlAppConfig) error
    Run(ctx context.Context, scenario ControlScenario) (ControlRunResult, error)
    CollectMilestones(ctx context.Context) (<-chan AndroidMilestone, error)
    SnapshotDiagnostics(ctx context.Context) (AndroidDiagnostics, error)
}
```

Он не содержит service-specific packet logic. Scenario adapter определяет только device-side действия и expected milestones. Router trace остаётся источником истины для classification/action isolation.

## 2.3. Android Driver

Интерфейс:

```go
type AndroidDriver interface {
    Preflight(ctx context.Context) (DeviceCapabilities, error)
    ForceStop(ctx context.Context, packageName string) error
    ClearAppState(ctx context.Context, packageName string, mode ClearMode) error
    LaunchApp(ctx context.Context, packageName string) (LaunchResult, error)
    OpenDeepLink(ctx context.Context, packageName, url string) (LaunchResult, error)
    Background(ctx context.Context, packageName string) error
    Foreground(ctx context.Context, packageName string) error
    CollectMilestones(ctx context.Context) (<-chan AndroidMilestone, error)
    SnapshotDiagnostics(ctx context.Context) (AndroidDiagnostics, error)
}
```

Adapters:

```text
adb-basic
uiautomator
android-companion
manual-marker
```

---


## 2.4. Router authorization auditor

В controller analyzer входит отдельный модуль:

```text
flow inventory
→ identify target/control roles
→ correlate evidence/candidate/authorization/action/state events
→ assert allowed component ownership
→ count unrelated actions
→ emit proof table
```

Auditor MUST работать по pseudonymous flow/client IDs и config generation, а не по одному destination IP.

## 2.5. GSO/RST validation adapters

Controller поддерживает generic suites:

- GSO shadow/parity — сравнение решений full GSO skb и нормализованного MSS/reassembly path;
- normalizer lifecycle — queue readiness, token consume/expiry, rollback;
- Passive RST observe — signal/baseline/scoring без изменения verdict;
- Passive RST active isolated run — suppression budget, reconnect monitor и automatic rollback.

Эти suites не запускаются скрытно внутри обычного quick profile.

# 3. TestSession API

API version:

```text
/api/v1
```

Все mutating requests должны поддерживать:

```text
Idempotency-Key
X-B4-Client
X-B4-Request-ID
```

## 3.1. Capabilities

```http
GET /api/v1/capabilities
```

Возвращает:

- B4 commit/version;
- API/schema versions;
- NFQUEUE support;
- capture envelope;
- offload visibility;
- pcap availability;
- Android test API support;
- sandbox capacity;
- current resource budget;
- supported transports/strategies.


### Дополнительные capabilities редакции 1.1

`GET /api/v1/capabilities` также возвращает:

```text
cross_service_isolation_version
effective_domain_policy_modes
capture_candidate_action_authorization_split
reassembled_sni_authoritative
negative_sni_override
legacy_learned_ip_role
scoped_failure_state
scoped_route_binding
same_client_control_audit

nfqueue_gso_supported
nfqueue_gso_mode
nfqa_cap_len_available
nfqa_skb_info_available
offload_metadata_schema
normalizer_queue_ready
gso_token_store_ready
gso_direct_techniques

passive_rst_supported
passive_rst_mode
incoming_visibility_complete
rst_baseline_state
rst_suppression_budget
rst_rollback_monitor_ready
```


### Дополнительные capabilities редакции 1.3

`GET /api/v1/capabilities` также возвращает:

```text
silent_path_failure_supported
silent_path_failure_version
silent_path_failure_modes
silent_progress_unique_range_accounting
silent_protocol_milestones_supported
silent_visibility_gate
silent_gso_parity_state
silent_ppe_visibility_state
silent_suppression_catalog_version
silent_differential_probe_supported
silent_scoped_recovery_supported
silent_warp_fallback_supported
silent_false_positive_budget_supported
silent_user_revert_supported
silent_active_mode_promotion_state
```

Для каждого active-sensitive capability обязательны `state`, `validated_at`, `validation_hash`, `degraded_reason` и `target_scope`. `supported=true` без доказанного effective mode не разрешает active suite.

Capabilities MUST включать version/hash и degraded reason. Test controller отклоняет suite, если требуемая capability не доказана, а не помечает её как strategy failure.

## 3.2. Создание тестовой сессии

```http
POST /api/v1/test-sessions
```

Пример:

```json
{
  "client": {
    "id": "android-main",
    "ip": "192.168.1.152"
  },
  "app": {
    "variant": "revanced",
    "package": "configured-by-controller"
  },
  "start_type": "cold",
  "quic_mode": "client-enabled-b4-reject",
  "ip_family": "auto",
  "resolver_mode": "observed",
  "trace_profile": "field-detailed",
  "duration_limit_sec": 120
}
```


Редакция 1.1 расширяет request:

```json
{
  "client": {
    "id": "android-main",
    "ip": "192.168.1.152"
  },
  "target_app": {
    "id": "youtube",
    "variant": "revanced",
    "package": "configured-by-controller"
  },
  "control_apps": [
    {
      "id": "gmail",
      "package": "configured-by-controller",
      "scenarios": ["inbox", "message-body", "inline-images", "attachment"]
    },
    {
      "id": "google-feed",
      "package": "configured-by-controller",
      "scenarios": ["feed-load", "refresh", "article-open", "image-load"]
    }
  ],
  "isolation_policy": {
    "require_zero_unrelated_actions": true,
    "require_negative_sni_override": true
  },
  "gso_suite": "inherit",
  "passive_rst_suite": "observe-only"
}
```

Старое поле `app` сохраняется как compatibility alias для `target_app`. Control apps optional для diagnostic quick run, но обязательны для production promotion validation YouTube profile.


Редакция 1.3 расширяет request:

```json
{
  "silent_path_suite": {
    "mode": "observe",
    "scenarios": [
      "handshake-silence",
      "early-body-stall",
      "midstream-stall",
      "fast-parallel-control",
      "recent-success-control"
    ],
    "require_unique_progress": true,
    "require_bidirectional_visibility": true,
    "require_two_independent_evidence_families": true,
    "require_differential_for_active": true,
    "require_same_client_controls": true,
    "allow_warp_candidate": false,
    "promotion_allowed": false
  }
}
```

`promotion_allowed=false` является default. TestSession не может скрытно перевести global/profile policy из `observe` в `auto-canary`.

Response:

```json
{
  "session_id": "s-20260727-0001",
  "config_generation": 418,
  "event_stream": "/api/v1/test-sessions/s-20260727-0001/events",
  "status": "ready"
}
```

## 3.3. Session marker

```http
POST /api/v1/test-sessions/{session_id}/markers
```

```json
{
  "marker": "first_frame",
  "source": "android-companion",
  "device_monotonic_ns": 49200123382
}
```

Допустимые markers:

```text
app_launch
ui_visible
video_tap
first_media_render
first_frame
buffering_start
buffering_end
background
foreground
test_end
```

## 3.4. Event stream

```http
GET /api/v1/test-sessions/{session_id}/events
Accept: text/event-stream
```

SSE предпочтительнее обязательного WebSocket:

- проще реализовать на слабом роутере;
- однонаправленный stream достаточен;
- автоматическое reconnect;
- легко сохранять как JSON Lines.

## 3.5. Завершение

```http
POST /api/v1/test-sessions/{session_id}/stop
```

## 3.6. Итоговый отчёт

```http
GET /api/v1/test-sessions/{session_id}/report
```

Formats:

```text
application/json
text/markdown
application/zip
```

ZIP может включать:

- `session.json`;
- `events.jsonl`;
- `summary.md`;
- `metrics.json`;
- redacted config;
- optional pcap;
- optional captured ClientHello;
- router diagnostics;
- Android diagnostics.

---


## 3.7. Authorization audit endpoint

```http
GET /api/v1/test-sessions/{session_id}/authorization-audit
```

Возвращает:

```json
{
  "target_flow_count": 24,
  "control_flow_count": 17,
  "target_actions": 8,
  "unrelated_control_action_total": 0,
  "destination_only_state_total": 0,
  "negative_sni_override_failures": 0,
  "violations": []
}
```

Каждая violation содержит redacted/pseudonymous:

```text
flow_id
client_id
role
selected set/component
evidence source
candidate reason
authorization result
action/state type
config generation
```

## 3.8. Capability-specific reports

```http
GET /api/v1/test-sessions/{session_id}/gso-report
GET /api/v1/test-sessions/{session_id}/rst-report
```

Endpoints MAY вернуть `not-run`/`blocked-capability`, но не `pass`, если suite не выполнялась.

# 4. Discovery API

## 4.1. Запуск эксперимента

```http
POST /api/v1/discovery/runs
```

```json
{
  "target_client_id": "android-main",
  "mode": "android-real",
  "profile": "standard",
  "promotion_mode": "report-only",
  "variants": {
    "strategies": ["current", "candidate-a", "candidate-b"],
    "fake_profiles": ["current", "captured-compact"],
    "resolvers": ["observed"],
    "ip_families": ["auto"],
    "tls_profiles": ["android-observed"]
  },
  "android": {
    "package": "configured-by-controller",
    "test_video_url": "configured-secret",
    "runs_quick": 3,
    "runs_validate": 5,
    "runs_promote": 10
  }
}
```


### Расширение discovery request редакции 1.1

```json
{
  "controls": {
    "required": ["gmail", "google-feed"],
    "concurrent_run": true,
    "require_zero_unrelated_actions": true
  },
  "representation_matrix": {
    "gso": ["off", "observe", "classify"],
    "mss_baseline": true
  },
  "passive_rst": {
    "mode": "observe",
    "active_isolated": false
  }
}
```

Обычный optimizer не включает `aggressive` RST и не включает GSO `full`. Active isolated RST/GSO normalization suites создаются отдельным explicit experiment definition.

## 4.2. Status

```http
GET /api/v1/discovery/runs/{run_id}
```

## 4.3. Cancel

```http
POST /api/v1/discovery/runs/{run_id}/cancel
```

## 4.4. Result

```http
GET /api/v1/discovery/runs/{run_id}/report
```

## 4.5. Canary

```http
POST /api/v1/candidates/{candidate_id}/canary
```

```json
{
  "client_ids": ["android-main"],
  "flow_percent": 10,
  "duration_sec": 600,
  "automatic_rollback": true
}
```

## 4.6. Promote

```http
POST /api/v1/candidates/{candidate_id}/promote
```

По умолчанию endpoint требует отдельный scope:

```text
strategy:promote
```

## 4.7. Rollback

```http
POST /api/v1/runtime/rollback
```

---

# 5. Controller API и CLI

B4 Router API не должен напрямую исполнять ADB.

Local controller предоставляет coding-agent безопасный интерфейс.

## 5.1. CLI

```text
b4-field-test preflight
b4-field-test run --profile quick
b4-field-test run --profile standard --app revanced
b4-field-test compare candidate-a candidate-b
b4-field-test validate candidate-a --runs 5
b4-field-test canary candidate-a
b4-field-test rollback
b4-field-test export RUN_ID
```

## 5.2. Local API

Опционально:

```http
POST http://127.0.0.1:47841/controller/v1/runs
GET  http://127.0.0.1:47841/controller/v1/runs/{id}
POST http://127.0.0.1:47841/controller/v1/runs/{id}/cancel
```

Controller MUST bind to loopback by default.

## 5.3. Environment

```text
B4_BASE_URL
B4_API_TOKEN
B4_CLIENT_ID
ADB_SERIAL
ANDROID_PACKAGE_OFFICIAL
ANDROID_PACKAGE_REVANCED
B4_TEST_VIDEO_URL_SHORT
B4_TEST_VIDEO_URL_LONG
B4_RESULTS_DIR
```

Secrets and test URLs MUST NOT be committed.

---


## 5.4. Дополнительная environment configuration

```text
ANDROID_PACKAGE_GMAIL
ANDROID_PACKAGE_GOOGLE_APP
B4_CONTROL_GMAIL_SCENARIO
B4_CONTROL_GOOGLE_FEED_SCENARIO
B4_GSO_SUITE_MODE
B4_RST_SUITE_MODE
B4_REQUIRE_ZERO_UNRELATED_ACTIONS
```

Account/message/article identifiers хранятся вне repository и redact-ятся из reports. Controller MUST поддерживать запуск control network audit даже без точного UI helper.

# 6. Automated real-device run state machine

```text
CREATED
→ PREFLIGHT
→ ROUTER_BASELINE
→ ANDROID_PREPARE
→ SESSION_START
→ APP_LAUNCH
→ API_UI_OBSERVE
→ VIDEO_OPEN
→ MEDIA_OBSERVE
→ OPTIONAL_CDN_SWITCH
→ SESSION_STOP
→ COOLDOWN
→ ANALYZE
→ NEXT_VARIANT
→ VALIDATE
→ CANARY
→ REPORT
```

### Расширенная production state machine редакции 1.1

```text
CREATED
→ PREFLIGHT
→ CONTROL_BASELINE
→ YOUTUBE_BASELINE
→ CANDIDATE_APPLY
→ TARGET_APP_PREPARE
→ TARGET_API_UI_RUN
→ TARGET_VIDEO_RUN
→ SAME_CLIENT_CONTROL_RUN
→ OPTIONAL_CONCURRENT_RUN
→ OPTIONAL_CDN_SWITCH
→ GSO_PARITY_RUN_IF_ENABLED
→ PASSIVE_RST_OBSERVE_RUN
→ ACTIVE_RST_ISOLATED_RUN_IF_EXPLICIT
→ SESSION_STOP
→ COOLDOWN
→ AUTHORIZATION_AUDIT
→ ANALYZE
→ NEXT_VARIANT
→ VALIDATE
→ CANARY
→ REPORT
```

`CONTROL_BASELINE` выполняется минимум для baseline-none и baseline-production. Candidate не сравнивается только с собственным успешным target run; он сравнивается с control health и authorization audit.

## 6.1. Preflight

MUST verify:

- router API reachable;
- correct build commit;
- expected config generation;
- target client present;
- no mark conflict;
- NFQUEUE drops zero;
- capture envelope complete;
- offload visibility acceptable;
- ADB device online;
- device clock sample available;
- package installed;
- device unlocked/test-ready;
- no other Discovery run;
- router resource thresholds satisfied.


Дополнительный preflight MUST проверить:

- Cross-Service Isolation capability version/hash;
- effective DomainOnly mode для target components;
- authoritative reassembled-SNI capability;
- scoped failure/escalation/route state;
- control packages/scenarios либо допустимый network-only fallback;
- authorization audit event completeness;
- GSO metadata/normalizer/token readiness для запрошенного suite;
- incoming visibility и RST rollback readiness для запрошенного active mode;
- stale validation incompatibility после config/capability/topology change.

## 6.2. Android prepare

For cold start:

```text
force-stop
optional cache clear according to test policy
wait
launch app/deep link
```

Full application data clearing MUST NOT be used by default because it changes login and application state. Separate modes:

```text
force-stop-only
clear-runtime-cache
clear-all-data
```

Default:

```text
force-stop-only
```


## 6.2.1. Control app prepare

Control app по умолчанию использует:

```text
force-stop-only
```

Запрещено по умолчанию:

- очищать Gmail/Google account data;
- удалять login/session;
- открывать произвольное private content;
- сохранять screenshots/message body;
- автоматически отправлять/удалять письма;
- менять персональные Discover preferences.

Controller использует заранее локально настроенный безопасный test message/public card или manual marker fallback.

## 6.3. Video selection

Use configured stable video deep links.

At least two profiles:

```text
short-startup-video
long-throughput-video
```

The URL is user-controlled configuration and excluded from public issue bundles unless explicitly allowed.

---


## 6.4. Same-client control sequence

Минимальная последовательность после каждого candidate target run:

```text
Gmail launch
→ inbox progress
→ configured message body progress
→ optional inline image/attachment metadata progress

Google app launch
→ feed progress
→ refresh
→ configured public article/card progress
```

Concurrent variant:

```text
YouTube playback remains active
+ Gmail message open
+ Google Feed refresh
```

Router auditor маркирует flows ролями по session window, package/device markers и observed domains. Domain identity MUST строиться из classifier evidence, а не из destination IP alone.

# 7. Trace and event schema

Every event MUST include:

```json
{
  "schema": 1,
  "session_id": "s-...",
  "event_seq": 417,
  "flow_id": "f-...",
  "flow_event_seq": 12,
  "ts": "2026-07-27T20:42:17.521Z",
  "t_rel_us": 184223,
  "event": "classification_decision"
}
```

Required common fields:

```text
schema
session_id
event_seq
timestamp UTC
monotonic relative timestamp
event type
config generation
client pseudonym
optional flow ID
```

## 7.1. Session/environment events

```text
session_start
controller_connected
clock_sync_sample
user_or_companion_marker
router_resource_sample
wan_background_sample
session_end
```

## 7.2. DNS/QUIC evidence events

```text
dns_query_seen
dns_answer_seen
dns_evidence_added
dns_visibility_changed
quic_initial_seen
quic_sni_parsed
quic_evidence_added
evidence_expired
evidence_conflict
```

## 7.3. TCP/FSM events

```text
flow_open
syn_seen
syn_ack_seen
tcp_established
clienthello_partial
clienthello_reassembly_progress
clienthello_complete
clienthello_abort
server_ack_progress
server_hello_seen
application_progress
flow_close
```

## 7.4. Classification events

```text
classification_started
classification_candidate
classification_decision
classification_changed
classification_final
```

## 7.5. Action events

```text
action_plan_created
action_plan_rejected
action_started
packet_injected
original_verdict
action_completed
action_suppressed
real_only_replay
amplification_budget_exceeded
```

## 7.6. Capture/kernel events

```text
capture_envelope_opened
capture_envelope_closed
packet_visibility_gap
processed_mark_verified
processed_packet_reentry
offload_bypass_suspected
nfqueue_drop
nfqueue_user_drop
trace_event_drop
```

---


## 7.7. Cross-service authorization events

```text
capture_candidate_created
capture_candidate_rejected
classification_candidate_revoked
action_authorization_granted
action_authorization_denied
negative_sni_override
reassembled_sni_selected
shared_ip_ambiguity
legacy_learned_ip_ignored
scoped_block_cache_hit
scoped_escalation_created
route_binding_created
route_binding_rejected_scope
control_flow_identified
unrelated_control_action_violation
authorization_audit_complete
```

Required fields where applicable:

```text
flow role: target/control/background
candidate source
candidate SetID/ComponentID
authorizing evidence source
DomainOnly mode/result
negative evidence source
scope hash
state/action owner
config generation
```

## 7.8. GSO/offload events

```text
nfqueue_gso_packet
nfqueue_cap_len_observed
nfqueue_packet_truncated
nfqueue_checksum_not_ready
nfqueue_checksum_not_verified
gso_shadow_decision
gso_mss_parity_result
gso_action_direct
gso_normalization_requested
gso_pass_token_created
gso_pass_token_consumed
gso_pass_token_expired
gso_secondary_pass_rejected
normalizer_queue_ready
normalizer_queue_failure
gso_topology_rollback
```

`gso_mss_parity_result` содержит decision/set/action-plan hashes, но не raw ClientHello.

## 7.9. Passive RST events

```text
rst_observed
rst_baseline_sample
rst_baseline_updated
rst_baseline_insufficient
rst_suspicion_scored
rst_suppression_allowed
rst_suppression_denied
rst_suppressed
rst_budget_exhausted
rst_visibility_downgrade
rst_reconnect_monitor_sample
rst_reconnect_regression
rst_automatic_rollback
rst_mode_changed
```

Observe mode MUST emit observation/scoring events without changing packet verdict.


## 7.10. Silent path failure and recovery events

```text
silent_observation_started
silent_progress_milestone
silent_suspicion_created
silent_suspicion_suppressed
silent_correlation_reached
silent_differential_started
silent_differential_completed
silent_recovery_lease_created
silent_recovery_activated
silent_recovery_validated
silent_recovery_rolled_back
silent_false_positive_reported
silent_policy_auto_degraded
silent_policy_promotion_revoked
```

Field report MUST correlate:

```text
exact flow/scope pseudonymous IDs
+ ConfigGen
+ current/candidate binding IDs
+ positive evidence families
+ suppression evidence
+ visibility/GSO/PPE state
+ differential proof ID
+ lease/rollback ID
```

Raw hostname, MAC, token, email content and private WARP material MUST NOT appear in labels or exported event names.

# 8. TCP packet trace level

Default field trace MUST NOT include full payload.

Required summary:

```text
direction
flags
SEQ
ACK
payload length
TCP options summary
relative stream range
retransmission class
packet provenance
NFQUEUE verdict
```

Payload capture modes:

```text
none
clienthello-only
bounded-first-flight
pcap
```

Default:

```text
none
```

`clienthello-only` and `pcap` require explicit session permission and privacy warning.

---


Дополнительные packet/offload summary fields:

```text
captured length
original/cap length
GSO flag
checksum-not-ready / not-verified
truncated flag
packet representation
normalizer pass
GSOPassToken ID/hash
ActionAuthorization ID/hash
flow role
set/component owner
```

Для RST packets:

```text
direction
TTL/hop baseline quality
SEQ/ACK validity class
flags/options consistency
signal strength
suppression verdict/reason
remaining budget
```

# 9. Startup milestone model

```text
T0  controller/app launch
T1  first network flow
T2  first classification resolved
T3  first action completed
T4  first server progress
T5  first API body
T6  UI visible
T7  video requested
T8  first googlevideo flow
T9  first media byte
T10 first media render/first frame
```

Derived metrics:

```text
app_to_first_flow
first_flow_to_classification
classification_to_server_progress
app_to_api_progress
app_to_ui_visible
video_request_to_media_byte
video_request_to_first_frame
```

Every UI/media metric MUST include source:

```text
router-inferred
adb-inferred
uiautomator
android-companion
manual
```

---

# 10. Video performance model

For each `googlevideo.com` media flow:

```text
time_to_first_media_byte
bytes_first_1s
bytes_first_3s
bytes_first_5s

goodput_1s_peak
goodput_5s_p10
goodput_5s_median
goodput_5s_p90
goodput_30s_average

largest_receive_gap
stall_gap_count
flow_retry_count
cdn_switch_count
cdn_switch_success
```

Overhead:

```text
original_bytes
real_replayed_bytes
fake_bytes
retransmitted_bytes
dropped_bytes
injected_packets
packet_amplification
```

Goodput MUST count useful inbound media bytes, not all interface traffic.

---


# 10A. Same-client cross-service control model

## 10A.1. Gmail

Сценарии:

```text
inbox-list
message-body
inline-images
attachment-metadata-or-bounded-load
background-sync-observation
```

Metrics:

```text
launch_to_first_network_progress
launch_to_inbox_progress
message_open_to_body_progress
inline_image_progress
attachment_progress
flow_retry_count
reset_count
control_action_count
foreign_route_state_count
```

## 10A.2. Google app / Discover

Сценарии:

```text
feed-load
feed-refresh
article-open
image/content-progress
background-foreground
```

Metrics аналогичны UI/API control flow и не требуют чтения персонального контента.

## 10A.3. Control success

Control считается успешным только если одновременно:

```text
functional/network progress meets baseline threshold
AND unrelated_control_action_total == 0
AND destination_only_state_total == 0
AND negative_sni_override_failures == 0
```

# 10B. GSO parity model

Для одного logical ClientHello/flow сравниваются:

```text
full GSO capture
MSS segmentation
out-of-order/retransmission variants
conditional normalized second pass
```

Обязательная parity:

```text
ClassificationDecision hash
selected SetID/ComponentID
confidence/phase class
ActionAuthorization result
ActionPlan semantic hash
single ActionToken behavior
```

# 10C. Passive RST validation model

Observe suite измеряет:

```text
baseline sample count/quality
signal distribution
suspected vs benign RST
false-positive candidates
visibility completeness
resource usage
```

Active isolated suite дополнительно измеряет:

```text
suppressed RST count
budget use
reconnect success/failure
collateral control failures
automatic rollback latency
post-rollback recovery
```


# 10D. Silent Path Failure false-positive control model

Field Test MUST treat a silent-path observation as a classification problem with asymmetric cost:

```text
false negative
→ service may remain stalled

false positive active fallback
→ working flow may be rerouted or strategy rotated
```

Therefore active result requires all of:

```text
unique reverse-progress deficit
+ at least two independent evidence families
+ retry or application-level corroboration
+ no suppressing evidence
+ complete bidirectional visibility
+ GSO/MSS parity PASS
+ PPE visibility PASS
+ bounded differential candidate success
+ target improves while controls do not regress
+ defined rollback target
```

Mandatory false-positive fixtures:

- browser preconnect and cancellation;
- HLS/DASH parallel segment fetches;
- image/prefetch burst;
- HTTP/2 connection coalescing and idle reuse;
- QUIC success while TCP retry exists;
- app background/Doze and Wi-Fi/WAN transition;
- explicit FIN/RST/TLS Alert/HTTP error;
- origin/CDN slowness affecting target and controls;
- NFQUEUE drops, queue pressure, GSO mismatch and PPE visibility loss.

A fixture is PASS only when observation remains non-mutating or the suspicion is explicitly suppressed with the expected reason code.

# 11. Separate optimization objectives

## 11.1. YouTube API

Rank:

1. first-flow success;
2. `app_to_api_progress` maximum/p90;
3. median `app_to_api_progress`;
4. flow retries;
5. added B4 delay;
6. amplification/CPU.

## 11.2. YouTube UI

Rank:

1. successful UI load;
2. `app_to_ui_visible`;
3. failed parallel UI flows;
4. retries;
5. CPU/amplification.

## 11.3. YouTube VIDEO

Rank:

1. playback success without stalls;
2. `video_request_to_first_frame`;
3. `goodput_5s_p10`;
4. median goodput;
5. CDN-switch success;
6. largest receive gap;
7. router overhead.

A single universal strategy score MUST NOT replace separate API/UI/VIDEO rankings.

---

# 12. Candidate selection algorithm

## 12.1. Hard gates

Reject candidate when any condition is true:

```text
cold-start success below threshold
cross-client evidence leakage
NFQUEUE drops
capture envelope incomplete for required mode
unbounded or exceeded amplification
repeated stalls
runtime/config inconsistency
CPU/RAM budget exceeded
rollback failure
```


Дополнительные hard gates редакции 1.1:

```text
unrelated_control_action_total > 0
same_client_cross_service_evidence_leakage > 0
Gmail control regression above threshold
Google Feed control regression above threshold
destination-only block/escalation/route state detected
clear/reassembled non-target SNI failed to revoke target candidate
reassembled-SNI decision mismatch
GSO/MSS decision or ActionPlan mismatch
GSO pass token leak/duplicate consume
normalizer required but unavailable/drop observed
Passive RST suppression with incomplete visibility
Passive RST suppression budget exceeded
control flow RST suppression without target authorization
reconnect regression after suppression
automatic RST rollback failure
stale safety validation reused after topology/capability change
```

Любой hard gate имеет приоритет над target performance score.

## 12.2. Lexicographic ranking

API/UI:

```text
success
→ worst startup
→ median startup
→ retries
→ overhead
```

VIDEO:

```text
no stalls
→ time to first frame
→ p10 sustained goodput
→ median goodput
→ CDN switch
→ overhead
```

## 12.3. Test counts

```text
quick shortlist: 3 runs
candidate validation: 5 runs
promotion validation: 10 runs
```

For fewer than 10 samples report:

```text
median + maximum
```

For 10 or more:

```text
median + p90/p95
```

## 12.4. Alternating A/B order

Close candidates MUST be tested in interleaved order:

```text
A → B → A → B
```

or randomized balanced blocks.

Do not run all A tests before all B tests.

## 12.5. Adaptive matrix

Do not execute a full Cartesian product by default.

Suggested search:

```text
baseline
→ strategy family shortlist
→ fake-profile shortlist
→ resolver/IP-family differential only on failure
→ TLS/size shadow probes only on ambiguous failure
→ candidate validation
```

---


## 12.6. Multi-objective candidate eligibility

Candidate проходит к ranking только после трёх независимых verdicts:

```text
target_verdict = pass
control_isolation_verdict = pass
infrastructure_capability_verdict = pass
```

После этого применяется существующий per-component lexicographic ranking. Улучшение YouTube не компенсирует control/infrastructure failure.

## 12.7. Representation and defense matrices

GSO matrix:

```text
gso_mode: off / observe / classify
ClientHello: ~2 KiB / 4 KiB / 16 KiB / configured max
layout: GSO / MSS / out-of-order / retransmission / truncated
ActionPlan: accept-only / normal-TCP-required / certified-GSO-direct
```

Passive RST matrix:

```text
off
observe
conservative (isolated explicit only)
aggressive (manual engineering validation only; never optimizer)
```

# 13. Resource policy

Default:

```text
max active Discovery runs: 1
max parallel probes: 1
absolute maximum: 2
```

Second worker allowed only when:

```text
RAM > 256 MiB
CPU cores >= 4
NFQUEUE drops = 0
router load below threshold
```

Profiles:

## Quick

```text
parallelism: 1
body cap: 128 KiB
throughput: off
CDN switch: off
pause: 500 ms
```

## Standard

```text
parallelism: 1
body cap: 512 KiB
throughput window: <= 3 sec
one CDN-switch test
pause: 750 ms
```

## Deep

```text
parallelism: 1–2
body cap: 2 MiB
full differential matrix
optional pcap
manual or explicit agent request only
```

Stop conditions:

```text
free RAM < 32 MiB
load average > 1.5 × CPU count
NFQUEUE queue_drop > 0
NFQUEUE user_drop > 0
held-packet usage > 50%
another run active
```

---


Дополнительные stop conditions:

```text
normalizer queue drop > 0
GSO token store > configured budget
GSO token expired while packet held
NFQA truncation above suite threshold
offload metadata unavailable for requested mode
RST suppression budget exhausted
incoming visibility becomes incomplete
reconnect regression threshold crossed
control application/network failure detected
unrelated control action detected
```

При control violation current candidate немедленно снимается, control state сохраняется в report, config откатывается к baseline/last-good согласно session mode.

# 14. Autonomous promotion policy

## 14.1. Default

```text
promotion_mode = report-only
```

Agent may test, rank and recommend, but does not promote production config.

## 14.2. Canary auto mode

Explicit opt-in:

```text
promotion_mode = canary-auto
```

Agent may:

1. create candidate;
2. apply to selected test client only;
3. run bounded canary;
4. monitor hard gates;
5. rollback automatically on failure;
6. prepare promotion recommendation.

## 14.3. Full auto promotion

Allowed only when configured:

```text
promotion_mode = full-auto
```

Required guards:

- dedicated target client;
- last-good exists;
- rollback health verified;
- minimum 10 successful validation runs;
- no hard-gate violations;
- canary duration completed;
- API token has `strategy:promote`;
- candidate/config hashes recorded.

Full-auto MUST remain disabled by default.

---


## 14.4. Дополнительные promotion guards

Для любой production promotion YouTube candidate обязательны:

- same-client controls в текущей safety generation;
- zero unrelated actions во всех promotion runs;
- no destination-only side effects;
- GSO/MSS parity, если effective GSO mode выше observe/off;
- normalizer rollback proof, если normalization используется;
- Passive RST mode-specific validation;
- observe-only default при отсутствии explicit active opt-in;
- automatic rollback readiness;
- control health после rollback.

`full-auto` не может повысить Passive RST mode или GSO topology. Эти изменения являются отдельной explicit runtime operation.

# 15. Security

B4 test API:

- disabled or read-only by default;
- binds to configured LAN/admin interface only;
- bearer token with scopes;
- optional mTLS;
- rate limits;
- audit log;
- no secrets in trace;
- no unauthenticated promote/rollback;
- CSRF protection for browser UI;
- idempotency for mutations.

Scopes:

```text
trace:read
trace:write
discovery:run
capture:clienthello
capture:pcap
strategy:canary
strategy:promote
strategy:rollback
```

Local controller:

- binds to `127.0.0.1`;
- never exposes ADB remotely by default;
- credentials stored outside repository;
- redacts API tokens and device serials from reports.

---


## 15.1. Privacy controls для control scenarios

Reports MUST NOT включать по умолчанию:

- Gmail message subject/body/sender;
- attachment filename/content;
- Google Feed personalized titles/URLs;
- screenshots;
- raw authorization domains без configured redaction policy;
- full ClientHello/pcap без explicit permission.

Допустимы pseudonymous identifiers, timing, byte/progress markers, domain hashes и redacted classification/action evidence.

# 16. Agent execution contract

Coding-agent receives:

```text
B4 base URL
API token
ADB serial
test client ID
package name
test video URLs
allowed promotion mode
resource profile
```

Agent MUST:

1. run preflight;
2. record build/config hashes;
3. establish clock correlation;
4. execute baseline-none and baseline-production where applicable;
5. run adaptive candidates;
6. preserve every session report;
7. stop on hard-gate failure;
8. never hide infrastructure failure as strategy failure;
9. distinguish inferred and measured Android milestones;
10. produce a reproducible report;
11. execute same-client control baseline and candidate runs for production-oriented YouTube validation;
12. audit every control flow for foreign authorization/action/state;
13. compare GSO and MSS decisions when GSO suite is enabled;
14. keep Passive RST in observe unless an isolated active suite was explicitly requested;
15. trigger and verify rollback on control, normalizer or reconnect regression.


Agent additionally records:

```text
CONTROL_BASELINE_REPORT.json
AUTHORIZATION_AUDIT.json
GSO_PARITY_REPORT.json          # when run
PASSIVE_RST_REPORT.json         # when run
ROLLBACK_VERIFICATION.json
```

Output:

```text
field-test-results/<run-id>/
├── RUN_MANIFEST.json
├── AUTOMATED_FIELD_TEST_REPORT.md
├── CANDIDATE_COMPARISON.json
├── sessions/
├── issue-bundles/
└── recommendation.json
```

Recommendation example:

```json
{
  "candidate_id": "youtube-video-candidate-7",
  "verdict": "canary-eligible",
  "api_rank": "not-applicable",
  "video": {
    "first_frame_median_ms": 590,
    "first_frame_max_ms": 720,
    "goodput_5s_p10_mbps": 31.4,
    "stall_count": 0
  },
  "overhead": {
    "packet_amplification": 1.16,
    "router_cpu_peak_pct": 27
  },
  "promotion": {
    "allowed": false,
    "reason": "report-only mode"
  }
}
```

---

# 17. Integration with patch plan v2.3

This addendum does not add mandatory reordering.

Apply requirements when the agent reaches existing areas:

```text
Observability / issue bundle
→ TestSession schema and event stream

Discovery sandbox
→ baseline-none / production / candidate API

Structured ProbeOutcome
→ startup, goodput and failure signatures

ClientHello laboratory
→ API-controlled capture and profile provenance

Canary/promote/rollback
→ autonomous policy and scopes

UI/API
→ session controls, report export, manual markers
```

Earlier completed stages need modification only when their public interfaces cannot emit required events or identifiers. Such change must be a small compatibility patch, not a restart of the plan.

---


## 17.1. Integration with Cross-Service Isolation

Apply CSI requirements to:

```text
TestSession roles
→ target/control/background

Trace
→ CaptureCandidate / ActionAuthorization / revocation / scoped side effects

Analyzer
→ unrelated action and destination-only state audit

Discovery/canary
→ mandatory same-client control hard gate
```

## 17.2. Integration with RST/GSO Hardening

Apply H requirements to:

```text
Capabilities
→ offload metadata / queue topology / technique matrix / visibility

Trace
→ GSO passes/tokens/parity and RST observation/suppression

Suites
→ GSO/MSS parity / normalizer lifecycle / RST observe / isolated active rollback

Promotion
→ mode-specific gates and stale-validation invalidation
```

Earlier FT stages остаются действительными. Их public schemas расширяются additively; существующие clients могут игнорировать неизвестные fields/events.


## 17.3. Integration with Built-in WARP/MASQUE v1.2

Field Test Controller MUST различать следующие независимые объекты:

```text
service target flow
WARP base transport data flow
WARP outer MASQUE control flow
WARP inner MASQUE control flow
WARP enrollment flow
router-origin health probe
forwarded LAN-client proof flow
geo-attestation flow
DNS path used by tunneled client
```

Один flow не может использовать identifiers, marks, authorizations или verdict другого.

### Уровни transport proof

```text
W0 — bundled engine/process identity
W1 — expected TUN exists, address/MTU/link verified
W2 — CONNECT-IP accepted and transport event current
W3 — router-origin interface-bound probe succeeds
W4 — real forwarded LAN-client path succeeds through scoped PBR/NAT/MSS/DNS
```

Production routing MUST require `W4`. `W3` alone является diagnostic evidence и не разрешает promotion.

### WARP camouflage proof

Camouflage run обязан доказать:

```text
exact TransportControlAuthorization
→ exact outer/inner instance
→ bounded SYN/ClientHello mutation only
→ CONNECT-IP success
→ deterministic cutoff
→ established payload bypass
→ stability window
→ forwarded LAN path
```

Generic service `ActionAuthorization` не является transport-control authorization.

### Optional `НЕ РФ` proof

Experimental nested path считается usable только пока выполнены одновременно:

```text
inner-path provenance proven
+ at least two independent geo providers agree on the same country
+ country != RU
+ no provider reports RU
+ attestation fresh
+ direct WAN IP not observed
+ DNS path through selected transport
+ IPv6 disabled or separately validated
```

Availability of a non-RU egress is not guaranteed. Safety gate guarantees only, что B4 не активирует strict route при неподтверждённом результате.

### Causal transport trace proof

Field Test MUST consume the WARP v1.2 `TransportTraceEnvelope` and independently reconstruct the effective transport state. Required correlation chain:

```text
TestSessionID
→ ClientKey / service component
→ BindingID
→ RouteTokenID
→ TransportPathProof
→ current ConfigGen / RouteGen / SessionGen
→ base or inner WARP instance
→ application milestone
```

For nested WARP the controller MUST additionally prove:

```text
inner SessionGen
→ current parent base SessionGen
→ current parent route token
→ parent path proof
→ inner CONNECT-IP
→ provider-level geo evidence
→ quorum decision
→ kernel non-RU route gate
```

Trace completeness is blocking. A missing required event, invalid generation, zero route-counter delta, trace/runtime state mismatch or incomplete cleanup yields `BLOCKED_TRACE_COMPLETENESS`, never a degraded PASS.

Required release verdict:

```text
WARP_CAUSAL_TRACE_READY
```


## 17.4. Integration with Silent Path Failure and Scoped Recovery v1.0

Field Test MUST distinguish:

```text
observation
suspicion
correlated suspicion
causally validated differential failure
recommendation
recovery lease
cohort promotion
rollback/false-positive
```

No earlier state may be reported as a later one. In particular:

```text
stall != DPI proof
retry != failure proof
alternate path success != causal proof by itself
single successful lease != cohort promotion
```

Required runtime dependency coverage:

```text
SPF-1…SPF-10
```

Required suites:

```text
silent-observe
silent-false-positive-controls
silent-differential
silent-scoped-recovery
silent-warp-fallback
silent-long-run
```

For active runs the controller MUST prove exact `ActionAuthorization`, `ClientKey`, `FlowKey`/component scope and `ConfigGen`. Destination-only state, cross-service recovery or reuse of a stale lease is a blocking failure.

# 18. Suggested implementation addendum stages

These are companion tasks, not renumbering of v2.3.

## FT-A — TestSession and trace schema

- session IDs;
- monotonic timestamps;
- event sequence numbers;
- JSONL/SSE;
- report export.

## FT-B — Router test/discovery API

- capabilities;
- sessions;
- discovery runs;
- reports;
- cancellation;
- canary/rollback scopes.

## FT-C — Local field-test controller

- B4 API client;
- ADB driver;
- result storage;
- CLI;
- clock sync.

## FT-D — Android real-run automation

- force-stop;
- app launch;
- deep link;
- background/foreground;
- diagnostics;
- manual marker fallback.

## FT-E — Optional Android Test Companion

- accurate UI/first-frame/buffering events;
- local authenticated marker transport;
- no screen content collection.

## FT-F — Adaptive optimizer

- hard gates;
- A/B blocks;
- separate API/UI/video ranking;
- resource-aware scheduling.

## FT-G — Canary automation

- report-only default;
- canary-auto opt-in;
- verified rollback;
- full-auto protected by explicit scope.

---


## FT-H — Same-client control automation

- target/control role schema;
- Gmail and Google Feed adapters;
- network-only fallback;
- baseline/candidate/concurrent sequence;
- privacy-safe milestones.

## FT-I — Authorization and scoped-state auditor

- correlate candidate/decision/authorization/action;
- identify foreign set/component owner;
- detect destination-only block/escalation/route state;
- `unrelated_control_action_total`;
- proof table/report/API.

## FT-J — GSO parity and normalizer lifecycle suite

- offload metadata capability preflight;
- GSO vs MSS fixtures;
- decision/action-plan parity;
- token single-consume/expiry;
- queue readiness/rollback;
- truncation/checksum cases.

## FT-K — Passive RST safety suite

- observe baseline/scoring;
- controlled benign/suspicious fixtures;
- incomplete visibility downgrade;
- isolated conservative suppression;
- budget/reconnect monitor;
- automatic rollback and post-rollback controls.

## FT-L — Unified production promotion gate

- target performance verdict;
- same-client control verdict;
- capability/representation verdict;
- mode-specific RST verdict;
- safety hash and config generation;
- report-only/canary/full-auto enforcement.


## FT-M — Base WARP lifecycle and forwarded-flow suite

Scope:

- bundled `b4-warpd` identity/version/hash and no external package dependency;
- session/enrollment state presence without secret disclosure;
- stable TUN ownership, assigned address, MTU `1280`, link and NDM read-back;
- exact direct-WAN control route and recursive-route negative fixtures;
- W0–W4 proof ladder;
- forwarded LAN TCP, UDP and DNS tests;
- NAT/MSS owner verification;
- firewall reload, idle wake, WAN flap, daemon restart and reboot recovery;
- route removal when W4 becomes stale or fails according to configured failure policy;
- complete process/TUN/TCP/TLS/H2/CONNECT-IP/packet-pump lifecycle for current `SessionGen`;
- `TransportPathProof` with positive packet/byte counter delta for router and forwarded paths;
- exact Android `TestSessionID → BindingID → RouteTokenID → SessionGen` correlation;
- cleanup ownership closure after restart, rollback and uninstall.

Required output:

```text
FT-M_WARP_BASE_REPORT.md
FT-M_WARP_BASE_RESULTS.json
FT-M_FORWARDED_PATH_PROOF.json
```

A router-origin `curl --interface` result without forwarded proof cannot produce `PASS`.

## FT-N — WARP Transport Camouflage suite

Scope:

- candidate catalog `C0`–`C6` capability projection;
- canonical SNI, validated cover SNI and explicit-user SNI paths;
- exact `TransportControlAuthorization` and destination-only rejection;
- SYN/ClientHello-only mutation budgets;
- endpoint public-key pin preservation;
- CONNECT-IP lifecycle event and fallback cutoff budgets;
- no established HTTP/2/MASQUE payload mutation;
- auto-selection of the least aggressive stable candidate;
- pinning to WAN/endpoint/capability/config generation;
- invalidation after WAN, endpoint, engine, strategy or topology change;
- outer/inner instance isolation;
- Passive RST observe and exact-flow bounded enforcement fixtures;
- authorization-to-action-to-CONNECT-IP-to-cutoff event chain;
- current generation validation for delayed/duplicate lifecycle events;
- `post_cutoff_mutations == 0` proven from trace and packet fixtures.

Mandatory candidate comparison:

```text
C0 direct canonical
C1 cover-SNI only
C2 deterministic ClientHello split
C3 bounded multisplit
C4 bounded fake + split
C5 SYN/preopen shaping
C6 bounded disorder, experimental last resort
```

Production winner MUST be the lowest-complexity candidate satisfying all health and stability gates.

## FT-O — Experimental nested `НЕ РФ` suite

Scope:

- isolated second WARP instance using namespace/veth or declared safe fallback backend;
- exact inner control socket route through base WARP;
- no outer/inner address, mark, state or token collision;
- geo-attestation quorum and provenance;
- positive non-RU fixture;
- RU result fixture;
- `unknown`, timeout, stale and provider-disagreement fixtures;
- direct-WAN IP detection;
- DNS leak and IPv6 leak fixtures;
- target-service geo observation when configured;
- strict scoped fail-closed and optional explicit fail-open behavior;
- bounded reconnect/rotation attempts and cooldown;
- no claim of selectable or guaranteed country;
- `TunnelDependencyLink` from inner session to current healthy base generation;
- parent reconnect invalidation and child route revocation;
- provider-level geo events and independently recomputed quorum;
- current route-counter proof for each geo probe;
- observed DNS-inner path and IPv6 disable/validation proof;
- namespace/veth/NAT/mark/token cleanup terminal events.

Required verdicts:

```text
NONRU_VERIFIED
NONRU_UNAVAILABLE
NONRU_RU_OBSERVED
NONRU_CONFLICTING_ATTESTATION
NONRU_STALE
NONRU_PATH_UNPROVEN
NONRU_BLOCKED_CAPABILITY
```

Only `NONRU_VERIFIED` may authorize the strict nested route.

## FT-P — WARP fault, leak and performance suite

Fault matrix:

- missing/corrupt engine;
- architecture mismatch;
- invalid session, expired enrollment and registration throttling;
- endpoint TLS/pin failure;
- endpoint blocked before CONNECT-IP;
- CONNECT-IP accepted but no payload passes;
- TUN absent, wrong address, MTU drift and link down;
- mark/table collision;
- NDM refusal and iproute2 fallback;
- NAT absent/double NAT;
- firewall/PPE/WAN reload;
- lost connect/disconnect/cutoff event;
- supervisor crash and orphan helper;
- read-only/full state filesystem;
- inner namespace unavailable;
- inner session loss during active strict route;
- geo providers unreachable or malicious/conflicting fixture;
- missing/reordered/duplicate old-generation trace events;
- trace buffer/storage pressure and required-event drop attempt;
- runtime/trace state divergence;
- orphan namespace/veth/rule/NAT/token after crash or rollback.

Performance matrix records separately for base and nested modes:

```text
CPU
RSS
packet rate
TCP goodput
UDP loss/jitter
startup latency
reconnect latency
packet amplification
probe traffic
flash writes
```

Nested mode MUST NOT inherit base-mode performance claims.

## FT-Q — Unified WARP-aware promotion gate

The aggregate gate consumes FT-M…FT-P, FT-AC…FT-AE and existing FT-H…FT-L results.

Base WARP production-ready requires:

```text
W0–W4 PASS
+ zero route recursion
+ scoped ActionAuthorization proof
+ NAT/MSS/DNS proof
+ target/control isolation
+ fault recovery and rollback
+ privacy-safe evidence
```

WARP camouflage production-ready requires:

```text
base WARP production-ready
+ exact control authorization
+ endpoint pin preserved
+ cutoff PASS
+ established payload mutation total == 0
+ stability window PASS
+ target-router validation
```

`НЕ РФ` may be exposed only as experimental when:

```text
nested safety suite PASS
+ strict leak gates PASS
+ UI wording PASS
+ no country guarantee claim
```

FT-Q MUST produce separate verdicts; base WARP success cannot hide camouflage or non-RU failure.

Full WARP v1.2 claim additionally requires:

```text
FT-AC PASS
+ FT-AD PASS
+ FT-AE PASS
+ WARP_CAUSAL_TRACE_READY
```

A connectivity-only result cannot substitute for causal trace completeness.


## FT-R — Silent observation and unique-progress suite

Scope:

- unique TCP range accounting for both directions;
- retransmission/overlap/GSO coalescing parity;
- SYN-ACK, ServerHello, TLS/application-data and FIN/RST milestones;
- observe mode zero-verdict/zero-routing side effects;
- complete/incomplete visibility downgrade behavior;
- deterministic assessment and expiry.

Required output:

```text
FT-R_SILENT_OBSERVE_REPORT.md
FT-R_PROGRESS_PARITY_RESULTS.json
```

## FT-S — False-positive suppression suite

Scope:

- fast parallel connections, HLS/DASH chunks, prefetch and preconnect;
- fresh same-binding and compatible TCP/QUIC success bypass;
- explicit server close/error classification;
- background/Doze/network transition;
- origin/CDN/control-wide degradation;
- queue pressure, PPE visibility and GSO parity suppressors;
- adaptive baseline cold-start and insufficient-sample behavior.

Hard requirement:

```text
all mandatory benign fixtures
→ no active recovery
→ expected suppression reason present
```

## FT-T — Differential causal-proof suite

Scope:

- bounded current-vs-candidate A/B ordering;
- same target request semantics and time window;
- target improvement plus negative-control stability;
- candidate timeout/attempt/resource budgets;
- ambiguous, both-fail and both-pass outcomes;
- causal proof invalidation on WAN/config/profile/capability change.

A candidate success alone cannot produce PASS unless the current path failure was observed in the same valid comparison window.

## FT-U — Scoped recovery, WARP fallback and rollback suite

Scope:

- exact authorized component recovery;
- direct next/last-good candidate ordering;
- optional base-WARP candidate only when profile allows it;
- no recursive WARP fallback;
- strict non-RU constraints preserved when applicable;
- lease TTL/cooldown/max-attempt bounds;
- same-client Gmail/Google controls;
- user false-positive report and immediate rollback;
- automatic rollback on control regression or progress loss.

Required output:

```text
FT-U_RECOVERY_LEASE_REPORT.md
FT-U_ROLLBACK_RESULTS.json
FT-U_CONTROL_AUDIT.json
```

## FT-V — Silent recovery long-run and promotion gate

Scope:

- observe → recommend → auto-canary promotion ladder;
- target cohort hash and validation freshness;
- false-positive budget and automatic demotion;
- reboot/WAN flap/firewall reload/config hot-apply behavior;
- long-run HLS/QUIC/TCP mixed workload;
- lease cleanup and state-store bounds;
- separate verdicts for observe, recommend, auto-canary and promoted cohort.

Required verdicts:

```text
SILENT_OBSERVE_READY
SILENT_RECOMMEND_READY
SILENT_AUTO_CANARY_READY
SILENT_COHORT_PROMOTED
```

A later verdict requires all preceding verdicts. Absence of target evidence yields `BLOCKED_TARGET_VALIDATION`, never optimistic PASS.

# 19. Acceptance criteria

1. Agent can create and complete a router test session through API.
2. Agent can launch official YouTube or ReVanced on the real Android device through ADB.
3. Every Android run maps to one B4 session and config generation.
4. Trace explains DNS/QUIC/TCP/classification/action decisions.
5. Startup latency is decomposed by stage.
6. Video goodput excludes fake/retransmitted overhead.
7. UI/first-frame metrics declare measured vs inferred source.
8. Candidate tests use isolated baselines.
9. A/B runs are interleaved.
10. Strategy ranking is separate for API/UI/VIDEO.
11. Router resource limits stop unsafe tests.
12. Canary automatically rolls back on hard-gate failure.
13. Default mode never promotes without explicit authorization.
14. A single command produces a complete reproducible result bundle.
15. User does not need to manually tune strategy parameters for normal test cycles.

---


### Дополнительные acceptance criteria редакции 1.1

16. Production-oriented YouTube run содержит target и same-client control roles.
17. Gmail и Google Feed имеют baseline-none и baseline-production results.
18. Ни один control flow не получает YouTube ActionAuthorization/ActionToken/action.
19. `unrelated_control_action_total == 0` во всех candidate validation/promotion runs.
20. Shared-IP fixture завершается correct component resolution либо ambiguity/fail-open, но не чужой mutation.
21. Clear/reassembled non-YouTube SNI отменяет provisional YouTube candidate.
22. Destination-only IPBlockDetect/escalation/route state обнаруживается как hard failure.
23. Reassembled SNI участвует в authoritative decision и trace.
24. Эквивалентные GSO/MSS inputs дают одинаковые classification/authorization/action-plan semantics.
25. GSO token потребляется один раз и не остаётся после timeout/shutdown/rollback.
26. Normalizer topology apply/rollback проверена transactionally.
27. Passive RST observe не изменяет packet verdict.
28. Active RST suppression невозможен при incomplete visibility или без budget.
29. Control-flow RST suppression без target authorization является hard failure.
30. Reconnect regression вызывает automatic rollback/observe downgrade.
31. После rollback Gmail/Google controls и target baseline восстанавливаются.
32. Stale report не используется после safety hash/config/capability/topology change.
33. Reports сохраняют privacy: без message body, personalized feed content и raw secrets по умолчанию.
34. Coding-agent выдаёт отдельные authorization, GSO и RST reports, если suites запускались.



### Дополнительные acceptance criteria редакции 1.2

35. B4 reports bundled WARP engine source commit, patch hash, binary hash and effective runtime version.
36. Absence of external `usque`/`usque-keenetic` package is a valid and expected installation state.
37. Base WARP route is never active before a current W4 forwarded LAN proof.
38. Router-origin W3 success cannot mask failed PREROUTING, mark, rule, NAT, MSS or DNS behavior.
39. WARP endpoint/control socket never receives an ordinary service strategy by destination-only matching.
40. Every camouflage action references exact `TransportControlAuthorization`, instance and config generation.
41. Camouflage is bounded to SYN/ClientHello phases and stops after CONNECT-IP or fallback budget exhaustion.
42. `masque_established_payload_mutation_total == 0` in all production-oriented runs.
43. Endpoint public-key pin failure is never accepted and `insecure` mode is never used.
44. Auto-selection promotes the least aggressive stable camouflage candidate.
45. Outer and inner WARP instances cannot consume each other's marks, tokens, authorization or cutoff events.
46. `НЕ РФ` route is inactive for RU, unknown, stale, conflicting or path-unproven attestation.
47. Strict non-RU mode never falls back directly for the selected scope.
48. DNS and IPv6 leak checks are included in every strict non-RU promotion sample.
49. Geo result is presented as observed and time-bounded, never as guaranteed selectable country.
50. WARP faults do not cause unbounded restart, registration, endpoint rotation or candidate retry storms.
51. Base and nested resource/performance claims are reported separately.
52. Issue bundles redact private key, license, access token, device identity and complete session config.
53. `FT-M`–`FT-Q` each produce machine-readable results and a stage validation report.
54. Missing required router/Android/network capability yields `BLOCKED_CAPABILITY` or `BLOCKED_TARGET_VALIDATION`, never `PASS`.


### Дополнительные acceptance criteria редакции 1.3

55. `FT-R`–`FT-V` each produce machine-readable results and a stage validation report.
56. Observe mode changes no packet verdict, route, strategy, failure cache or transport binding.
57. Unique progress is sequence/range based and equivalent for GSO and MSS representations.
58. One timeout, retry, retransmission burst or repeated ClientHello never authorizes active fallback.
59. Active recovery requires at least two independent evidence families and causal differential proof.
60. Every mandatory suppressor is evaluated before recommendation or recovery.
61. Fast parallel/HLS/prefetch/preconnect fixtures produce zero active recovery.
62. Fresh compatible success suppresses stale or contradictory retry evidence.
63. Incomplete bidirectional/PPE/GSO visibility degrades effective mode to observe.
64. Explicit FIN/RST/TLS Alert/application error is not misclassified as silent DPI failure.
65. Recovery state is exact client/service/component/config-generation scoped.
66. Destination-only, cross-client, cross-service, cross-component and cross-generation recovery totals remain zero.
67. WARP candidate is used only when authorized by profile and never recursively.
68. Every active lease has a known rollback target, TTL, cooldown and bounded attempt budget.
69. Gmail/Google controls remain action- and regression-free during target recovery.
70. User false-positive report triggers immediate rollback and budget accounting.
71. False-positive budget breach automatically demotes or disables active mode.
72. Observe/recommend/auto-canary/cohort verdicts are independent and cannot be collapsed into one PASS.

# 20. Final decision

Автономные реальные тесты coding-agent через API технически реализуемы.

Минимальный рабочий вариант:

```text
B4 TestSession API
+ Local Controller
+ ADB
+ structured trace/report
```

Он автоматизирует cold start, network classification, media start, throughput, retries, CDN switch и strategy comparison.

Для точного измерения `ui_visible`, `first_frame` и buffering необходим phone-side signal:

```text
Android Test Companion
или instrumentation/UIAutomator adapter
```

Без него агент всё равно сможет подбирать стратегии, но часть пользовательских milestones будет сетевой эвристикой, а не точным измерением UI.


---

# 21. Итог редакции 1.1

Автоматизация считается production-grade не тогда, когда она нашла быстрый YouTube candidate, а когда воспроизводимо доказала:

```text
YouTube target success
+ Gmail/Google same-client isolation
+ zero unrelated actions and scoped-state leaks
+ packet-representation parity
+ defensive-mode safety and rollback
+ reproducible privacy-safe evidence
```

Невыполненный capability-dependent suite получает `BLOCKED_CAPABILITY` или `NOT_RUN`, но никогда не считается `PASS`.


---

# 22. Итог редакции 1.2

Редакция 1.2 расширяет исходный direct-strategy test contract до generic alternative transport validation.

Production-grade доказательство теперь имеет два независимых результата:

```text
direct strategy safety/performance
и
built-in WARP/MASQUE transport safety/performance
```

Для WARP недостаточно увидеть `process running`, `TUN exists`, `Connected to MASQUE server` или `warp=on` из router-origin probe. Обязательная цепочка:

```text
bundled engine identity
→ exact control path
→ TUN/NDM/NAT/MSS/DNS readiness
→ CONNECT-IP
→ forwarded LAN-client proof
→ scoped target/control audit
→ fault/recovery evidence
→ deterministic verdict
```

Camouflage и `НЕ РФ` остаются отдельными capabilities. Их failure не отменяет корректность базового WARP, но базовый WARP не позволяет объявить их готовыми.


---

# 23. Итог редакции 1.3

Field Test v1.3 adds an explicit proof boundary between detecting a stalled flow and changing production routing or strategy.

Normative chain:

```text
unique progress observation
→ suppressor evaluation
→ independent evidence correlation
→ bounded differential proof
→ exact-scope recovery lease
→ target/control validation
→ rollback monitor
→ mode/cohort verdict
```

No single timeout, retry or apparent blackhole may skip this chain. The default remains `observe`; active recovery is a separately validated and revocable capability.

---

# 24. Интеграция с Detector v2, DDI и Telegram Bridge Hardening — редакция 1.4

Редакция 1.4 добавляет реальный доказательный контур для двух последних addenda. Field Test Controller MUST проверять не только то, что Detector выводит правдоподобный текст, но полную цепочку:

```text
user-selected service/domain targets
→ clean native/direct probe path
→ independent DNS/TCP/TLS/HTTP/QUIC/L4 evidence
→ controls and suppressors
→ immutable BlockingProfile
→ DDI network-context/freshness validation
→ guided Discovery priors
→ unchanged baseline-none and baseline-production
→ bounded full-search fallback
→ target/control validation
→ canary/promote/rollback
```

Для transparent Telegram bridge проверяется отдельная цепочка:

```text
accepted original-destination flow
→ bounded pending-first-data state
→ zero/partial/full prefix accounting
→ structured BridgeOutcome
→ prefix-preserving WS/DC/worker/direct route ladder
→ recursion protection
→ Android/Keenetic validation
→ deterministic cleanup
```

`BlockingProfile` не является `ActionAuthorization`, а успешный bridge accept не является доказательством успешного MTProto handoff.

## 24.1. Обязательные роли target plan

Каждый Detector v2 run MUST материализовать и сохранить роли:

```text
primary targets
service-component targets
same-service controls
same-provider / same-AS controls
unrelated controls
negative DNS controls
optional dynamic infrastructure controls
```

Для YouTube минимальный план включает API/UI/media components и same-client Gmail/Google Feed controls. Для Telegram отдельно проверяются service reachability и transparent bridge lifecycle; detector evidence не может автоматически включить bridge routing.

## 24.2. Clean-path и self-interference proof

Перед диагностикой controller MUST доказать, что измеряется заявленный `ProbePathMode`:

- `native-direct` исключает production strategy, WARP, proxy, silent-recovery lease и transparent bridge;
- `production-comparison` явно маркируется и никогда не заменяет native baseline;
- capture/PPE/GSO visibility входит в evidence provenance;
- stale mark/rule/TUN state приводит к `BLOCKED_CLEAN_BASELINE`;
- failure controls проверяют, что B4X не диагностирует собственную обработку как блокировку провайдера.

## 24.3. Новые trace/event families

Field trace schema расширяется минимум следующими событиями:

```text
detector.target_plan.compiled
detector.probe.started
detector.probe.progress
detector.probe.completed
detector.control.completed
detector.hypothesis.updated
detector.blocking_profile.compiled
detector.profile.rejected
ddi.profile.selected
ddi.profile.revalidated
ddi.prior.compiled
discovery.guided.started
discovery.guided.exhausted
discovery.full_fallback.started
discovery.guided_ab.completed
mtproto.pending.created
mtproto.pending.soft_deadline
mtproto.pending.hard_deadline
mtproto.prefix.handoff
mtproto.bridge.outcome
mtproto.route.attempt
mtproto.route.completed
mtproto.pending.cleaned
```

Каждое событие MUST содержать bounded reason code, config generation, redacted target/component identity и correlation IDs. Raw domain lists, MTProto secrets, WARP credentials и complete packet payloads не экспортируются по умолчанию.

# 25. Дополнительные Field Test stages редакции 1.5

## FT-W — Detector compatibility, target-plan and clean-baseline suite

Проверяет:

- отсутствие регрессий текущих DNS/domains/TCP/SNI/Telegram tests;
- custom domains и service-profile target plan;
- bounds, normalization, deduplication и component ownership;
- native-direct/production-comparison separation;
- stale network context, dirty marks, active WARP/proxy и incomplete visibility;
- quick/deep modes и resource budgets.

Выходные verdicts:

```text
ABD_TARGET_PLAN_READY
ABD_CLEAN_BASELINE_READY
```

## FT-X — Multi-protocol detector evidence suite

Проверяет synthetic и target-side матрицы:

- DNS resolver consensus, spoof/interception/fake NXDOMAIN/DoH bootstrap;
- TLS 1.2/1.3, verified/unverified pairs и browser/Android fingerprints;
- HTTP redirect/block-page/origin-error suppressors;
- QUIC Initial/Retry/VN/handshake/HTTP3 и TCP comparison;
- отдельные wire-packet и unique-byte threshold sweeps;
- GSO-to-wire packet accounting;
- retransmission non-progress;
- multiple independent origins and healthy controls.

Выходные verdicts:

```text
ABD_DNS_EVIDENCE_READY
ABD_TLS_HTTP_EVIDENCE_READY
ABD_QUIC_EVIDENCE_READY
ABD_L4_PROFILER_READY
```

## FT-Y — Dynamic controls, evidence graph and BlockingProfile suite

Проверяет:

- bounded dynamic target provider и cache freshness;
- host liveness/ownership validation;
- evidence-family independence;
- contradiction precedence;
- confidence downgrade;
- immutable profile compile;
- provenance and network-context binding;
- absence of direct action authorization or production write;
- privacy-safe persistence and issue bundle.

Выходные verdicts:

```text
ABD_DYNAMIC_CONTROLS_READY
ABD_EVIDENCE_GRAPH_READY
ABD_BLOCKING_PROFILE_READY
```

## FT-Z — DDI adapter and guided/full Discovery A/B suite

Проверяет:

- deterministic `BlockingProfile → NetworkDiagnosticProfile → DiscoverySearchPrior` adapter;
- freshness, revalidation, conflict and cross-WAN rejection;
- unchanged baseline-none and baseline-production ordering;
- priorities/budgets only, never candidate elimination without ordinary proof;
- full bounded fallback after ineffective priors;
- target/component controls and ActionAuthorization;
- truthful savings report: probes, wall time, winning-rank and final quality;
- guided result not worse than bounded full-search winner beyond declared tolerance.

Выходные verdicts:

```text
ABD_DDI_ADAPTER_READY
DDI_SCHEMA_READY
DDI_REVALIDATION_READY
DDI_HINT_PLANNER_READY
DDI_TARGET_VALIDATED
DDI_PRODUCTION_READY
```

## FT-AA — Transparent Telegram bridge delayed-first-data suite

Проверяет минимум следующие fixtures:

```text
0 bytes before soft deadline, then valid header
0 bytes until hard deadline
1–3 bytes, then delayed remainder
4–63 bytes, then delayed remainder
64-byte valid obfuscated header
reserved/non-obfuscated prefix
primary WS failure
DC fallback failure
worker fail-open
pending overflow
config reload
shutdown with pending sockets
IPv4 and IPv6 original destination
```

Обязательные доказательства:

- zero-byte soft timeout не возвращает destructive `handled=true`;
- каждый прочитанный byte передаётся fallback ровно один раз;
- global/per-client limits действуют;
- route ladder не рекурсирует в TPROXY;
- original destination сохраняется;
- cleanup не оставляет socket/goroutine/lease state;
- explicit MTProto proxy control и transparent Android scenario различаются в отчёте.

Выходные verdicts:

```text
TGB_STATE_MACHINE_READY
TGB_PENDING_BUDGET_READY
TGB_PREFIX_HANDOFF_READY
TGB_ANDROID_VALIDATED
TGB_PRODUCTION_READY
ISSUE_277_RESOLVED
```

## FT-AB — Unified detector-guided and bridge release gate

Stage выполняет объединённый long-run на реальном Keenetic и Android и выдаёт только раздельные, доказанные claims:

```text
ABD_PRODUCTION_READY
DETECTOR_GUIDED_STRATEGY_SEARCH_READY
ISSUE_278_RESOLVED
TGB_PRODUCTION_READY
ISSUE_277_RESOLVED
```

Ни один verdict не выводится транзитивно из другого. В частности:

- `ABD_PRODUCTION_READY` не означает `DDI_PRODUCTION_READY`;
- `DDI_PRODUCTION_READY` без target A/B не означает `ISSUE_278_RESOLVED`;
- изменённый timeout без delayed-first-byte/prefix proof не означает `ISSUE_277_RESOLVED`;
- Detector-guided PASS не означает production promotion конкретной service strategy.



## FT-AC — WARP causal envelope and event-order suite

Scope:

- validate `TransportTraceEnvelope` schema version and compatibility;
- require `EventID`, `TraceID`, `Sequence`, wall and monotonic time;
- require `BootIDHash`, `ProcessStartID`, `ConfigGen`, `RouteGen` and `SessionGen`;
- verify `ParentEventID`, `InstanceID`, `ParentInstanceID`, role and tunnel depth;
- reconstruct lifecycle independently from events;
- compare trace-derived and runtime/API state;
- reject retired-generation, duplicate, reordered and impossible transitions;
- verify required-event durability under ring-buffer, disk-full and process-restart fixtures;
- verify privacy/redaction and bounded metric labels.

Mandatory mutants:

```text
old-generation masque_connected arrives after reconnect
CONNECT-IP response appears before request
cutoff event omitted
packet-pump started event omitted
sequence gap in required P0 events
wall clock moves backwards
duplicate event mutates state twice
trace-derived ACTIVE while runtime is DEGRADED
required event dropped under storage pressure
```

Required outputs:

```text
FT-AC_WARP_TRACE_COMPLETENESS.json
FT-AC_WARP_EVENT_ORDER_REPORT.md
FT-AC_WARP_TRACE_RUNTIME_CONSISTENCY.json
```

## FT-AD — WARP route/path proof and forwarded-client correlation suite

Scope:

- validate `TransportPathProof` against actual rules, tables, marks, interfaces and namespaces;
- require packet and byte counters before/after each proof;
- prove router-origin and forwarded-client paths separately;
- bind Android `TestSessionID`, `ClientKey`, profile/component, `BindingID` and `RouteTokenID`;
- prove current `ConfigGen`, `RouteGen` and `SessionGen` at the application milestone;
- detect direct fallback, recursive route and stale token;
- verify same-client controls do not inherit target binding;
- revoke W4 when trace/path proof becomes stale or contradictory.

Blocking fixtures:

```text
route exists but counters do not change
counters change on wrong table/interface
router-origin success reported as forwarded success
Android milestone lacks BindingID
BindingID belongs to retired generation
direct fallback occurs without trace
control application uses target RouteTokenID
```

Required outputs:

```text
FT-AD_WARP_FORWARDED_CAUSAL_PROOF.json
FT-AD_WARP_ROUTE_PATH_PROOF.json
FT-AD_WARP_ANDROID_BINDING_REPORT.md
```

## FT-AE — Nested WARP, geo, DNS/IPv6 and cleanup causal suite

Scope:

- validate current `TunnelDependencyLink` from inner to base session;
- prove inner control enters current base path and never direct WAN;
- invalidate child dependency after parent reconnect or route-token replacement;
- validate per-provider geo events, route proof and independently recomputed quorum;
- compare quorum result with actual non-RU route gate and fail-closed state;
- invalidate attestation after public-IP, DNS path, IPv6 policy or generation change;
- prove DNS resolver path through inner binding;
- prove IPv6 disabled for exact strict scope or independently validated;
- trace ownership and terminal cleanup of process, TUN, NDM object, namespace, veth, route/rule/table, NAT/MSS, marks, listeners, tokens and attestation leases;
- inject crash/restart/rollback while nested route is active.

Mandatory negative cases:

```text
missing parent link
parent generation mismatch
stale parent token
inner control direct leak
geo quorum without provider events
geo probe without route-counter delta
provider disagreement but route gate open
public IP changed without attestation refresh
DNS direct while strict non-RU route active
unvalidated IPv6 egress
namespace/veth/rule remains after cleanup
foreign resource is removed
```

Required outputs:

```text
FT-AE_WARP_NESTED_DEPENDENCY_PROOF.json
FT-AE_WARP_GEO_QUORUM_TRACE.json
FT-AE_WARP_DNS_IPV6_PATH_PROOF.json
FT-AE_WARP_CLEANUP_OWNERSHIP.json
WARP_CAUSAL_TRACE_FIELD_REPORT.md
```

Release verdict:

```text
WARP_CAUSAL_TRACE_READY
```

requires `FT-AC`, `FT-AD` and `FT-AE` PASS, all applicable WARP v1.2 hard gates zero, real Keenetic path-counter proof and real Android forwarded-flow correlation.

# 26. Field hard gates редакции 1.5

Field Test Controller MUST fail active/release claim при ненулевом значении любого применимого счётчика. Отсутствующий, непрочитанный или не произведённый required gate не трактуется как zero.

```text
detector_single_probe_confirmed_total == 0
detector_exception_string_only_confirmed_total == 0
detector_static_target_only_high_confidence_total == 0
detector_self_interference_total == 0
detector_control_failure_ignored_total == 0
detector_unverified_mitm_verdict_total == 0
detector_quic_single_target_global_udp_verdict_total == 0
detector_packet_threshold_reported_as_byte_threshold_total == 0
detector_byte_threshold_reported_as_packet_threshold_total == 0
detector_gso_skb_count_as_wire_packet_total == 0
blocking_profile_direct_action_authorization_total == 0
blocking_profile_direct_production_write_total == 0
guided_search_skipped_baseline_total == 0
guided_search_disabled_full_fallback_total == 0
guided_search_target_unvalidated_promotion_total == 0
guided_search_cross_service_action_total == 0
discovery_profile_cross_wan_use_total == 0
discovery_profile_hint_overrode_current_baseline_total == 0
mtproto_bridge_zero_byte_handled_drop_total == 0
mtproto_bridge_fixed_5s_destructive_timeout_total == 0
mtproto_bridge_unbounded_pending_total == 0
mtproto_bridge_prefix_loss_total == 0
mtproto_bridge_prefix_duplicate_total == 0
mtproto_bridge_route_recursion_total == 0
mtproto_bridge_primary_failure_silent_drop_total == 0
mtproto_bridge_shutdown_leak_total == 0
warp_secret_leak_total == 0
warp_foreign_interface_modified_total == 0
warp_recursive_control_route_total == 0
warp_mark_collision_total == 0
warp_route_without_liveness_total == 0
warp_destination_set_partial_apply_total == 0
warp_unbounded_restart_total == 0
warp_unbounded_registration_total == 0
warp_unrelated_control_action_total == 0
warp_rollback_failure_total == 0
nonru_route_active_without_fresh_attestation == 0
nonru_route_active_while_any_provider_ru == 0
nonru_route_active_with_provider_disagreement == 0
nonru_route_active_with_direct_dns == 0
nonru_route_active_with_unvalidated_ipv6 == 0
nonru_route_active_after_attestation_expiry == 0
nonru_strict_direct_fallback_total == 0
nonru_identity_creation_budget_exceeded == 0
masque_camouflage_without_control_authorization_total == 0
masque_camouflage_destination_only_authorization_total == 0
masque_established_payload_mutation_total == 0
masque_camouflage_cutoff_failure_total == 0
masque_control_route_recursion_total == 0
masque_camouflage_cross_instance_total == 0
masque_strategy_promoted_without_forwarded_probe_total == 0
masque_strategy_promoted_without_stability_window_total == 0
masque_insecure_tls_total == 0
masque_endpoint_pin_failure_accepted_total == 0
masque_unbounded_candidate_retry_total == 0
masque_rst_suppression_without_exact_authorization_total == 0
warp_route_promoted_without_path_proof_event_total == 0
warp_forwarded_success_without_binding_trace_total == 0
warp_direct_fallback_without_trace_total == 0
warp_nested_missing_parent_link_total == 0
warp_nested_parent_generation_mismatch_total == 0
warp_nested_control_direct_leak_total == 0
warp_nested_route_active_without_parent_health_total == 0
warp_nested_stale_parent_token_total == 0
warp_geo_attestation_without_route_counter_delta_total == 0
warp_geo_quorum_without_provider_events_total == 0
warp_geo_route_gate_state_mismatch_total == 0
warp_nonru_revocation_exceeded_deadline_total == 0
warp_nonru_public_ip_change_without_refresh_total == 0
warp_dns_path_unproven_total == 0
warp_ipv6_path_unproven_total == 0
warp_connect_ip_event_wrong_generation_total == 0
warp_post_cutoff_mutation_total == 0
warp_cleanup_incomplete_total == 0
warp_owned_resource_leak_total == 0
warp_foreign_resource_removed_total == 0
warp_trace_secret_leak_total == 0
warp_trace_required_event_missing_total == 0
warp_trace_dropped_required_event_total == 0
warp_trace_event_order_violation_total == 0
warp_trace_generation_mismatch_total == 0
warp_trace_state_mismatch_total == 0
```

`WARP_CAUSAL_TRACE_READY` дополнительно требует complete required-event set, trace/runtime consistency, current-generation route proof, Android binding correlation, nested dependency proof и cleanup ownership closure.

# 27. Дополнительные acceptance criteria редакции 1.5

71. `FT-W`–`FT-AB` имеют machine-readable stage report и requirement coverage.
72. User-selected target plan проверяется раньше strategy search и сохраняет component/control roles.
73. Native direct baseline доказан и не загрязнён production processing.
74. Availability и certificate integrity являются отдельными probe outcomes.
75. TLS fingerprint verdict содержит точный fingerprint ID и provenance.
76. QUIC verdict не выводится из одного endpoint и не смешивается с TCP.
77. Packet-count и byte-count thresholds измеряются и публикуются отдельно.
78. GSO skb никогда не считается одним wire packet без нормализации/accounting proof.
79. Dynamic control scan bounded, freshness-aware и не зависит от скрытого remote runtime.
80. High confidence требует независимых evidence families и здоровых controls.
81. Contradiction снижает confidence или блокирует profile compile.
82. `BlockingProfile` immutable, network-bound и не содержит ActionAuthorization.
83. DDI revalidation выполняется перед guided search при age/context trigger.
84. Baseline-none и baseline-production не пропускаются.
85. Неудачные hints приводят к full bounded search, а не к optimistic failure.
86. Savings report не считает skipped mandatory baselines и не скрывает ухудшение winner quality.
87. Guided search promotion остаётся target/component/control validated.
88. Zero-byte soft deadline не уничтожает Telegram preconnection.
89. Partial prefix передаётся fallback без потери или дублирования.
90. Pending limits и overflow policy проверены под stress.
91. TPROXY recursion и wrong-original-destination counters остаются нулевыми.
92. Android issue #277 reproduction и explicit proxy control включены в один evidence bundle.
93. Missing clean path, target controls, Android or long-run evidence yields `BLOCKED_*`, never PASS.
94. Validator-of-validator может обнаружить намеренно отключённый ABD/DDI/TGB gate.


95. `FT-AC`–`FT-AE` имеют machine-readable stage report, requirement coverage и source addendum hash.
96. Каждый required WARP event содержит compatible schema, current boot/process/session generation и monotonic sequence.
97. Delayed event от retired `SessionGen` не изменяет runtime state и регистрируется как mismatch fixture.
98. Trace-derived state независимо вычисляется и совпадает с API/runtime state.
99. Missing, reordered or dropped required event блокирует `WARP_CAUSAL_TRACE_READY`.
100. Route/rule/table presence без positive packet/byte counter delta не считается path proof.
101. W4 требует реальный forwarded Android/LAN flow, а не router-origin probe.
102. Android application milestone связан с exact `BindingID`, `RouteTokenID`, component и current `SessionGen`.
103. Direct fallback, fail-open или fail-closed transition всегда имеет causal trace event.
104. Inner WARP имеет current parent link и parent health snapshot.
105. Parent reconnect, route-token replacement or generation retirement инвалидирует child dependency до revalidation.
106. Inner control direct-WAN leak fixture обнаруживается и strict route не активируется.
107. Geo quorum выводится независимо из provider events, а не принимается из одного aggregate field.
108. Каждый geo provider result имеет current route proof and positive counter delta.
109. RU, disagreement, direct WAN, stale attestation or public-IP change закрывают strict non-RU gate в bounded deadline.
110. DNS inner-path proof основан на observed resolver path, а не только config intent.
111. IPv6 strict-scope safety основана на observed disabled/validated state.
112. Camouflage trace связывает authorization, candidate, packet actions, CONNECT-IP and cutoff.
113. После cutoff отсутствуют packet mutations для established MASQUE stream.
114. Trace buffer/storage pressure не может молча удалить required P0 events и оставить production claim.
115. Metrics не содержат per-flow/high-cardinality IDs; detailed IDs остаются только в redacted structured events.
116. Cleanup report имеет terminal record для каждого generation-owned resource.
117. Foreign resource никогда не удаляется cleanup controller.
118. Crash, restart, rollback and uninstall leave zero owned namespace/veth/rule/NAT/token leaks.
119. Base, camouflage, non-RU and causal-trace verdicts агрегируются раздельно.
120. Base connectivity PASS не скрывает causal trace FAIL/BLOCKED.
121. Optional non-RU unavailable не ослабляет safety or trace gates.
122. Validation controller умеет воспроизвести old-generation, event-order, path-counter and cleanup mutants.
123. Real Keenetic report содержит route/path counter proof before and after probe.
124. Real Android report содержит complete target/control causal chain.
125. Export bundle содержит redacted event stream, path proofs, dependency graph, geo quorum inputs, cleanup ledger and verdicts.
126. Raw secret, private key, license, token, exact user identity or forbidden endpoint material не попадает в trace/export.
127. Trace schema incompatibility yields explicit `BLOCKED_TRACE_SCHEMA`.
128. Missing target-side path-counter or Android evidence yields `BLOCKED_TRACE_TARGET_VALIDATION`.
129. Full-fork production claim requires `WARP_CAUSAL_TRACE_READY` when WARP capability is declared.
130. Validator-of-validator detects forced-zero or skipped execution for every causal trace gate family.

# 28. Итог редакции 1.5

Field Test v1.5 сохраняет Detector-guided optimization и Telegram bridge hardening contracts и дополнительно превращает WARP/MASQUE v1.2 observability в blocking causal proof.

```text
Detector v2 claim
= clean baseline
+ independent evidence
+ controls
+ immutable BlockingProfile
+ truthful confidence

Guided search claim
= DDI context/freshness
+ unchanged baselines
+ bounded priors
+ full fallback
+ A/B target proof

Telegram bridge claim
= delayed-first-data correctness
+ bounded pending resources
+ exact prefix handoff
+ non-recursive fallback
+ Android/Keenetic proof
```

Ни правдоподобный detector summary, ни единично найденная стратегия, ни увеличение bridge timeout сами по себе не являются release evidence.



WARP v1.2 source binding:

```text
file: B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md
sha256: 87c909d59e9cad9ad70c224f81a4af08e3fb578288ae451f49f8a10451f8ed3d
```

Final WARP trace claim:

```text
WARP_CAUSAL_TRACE_READY
= complete generation-aware event chain
+ current route/path counter proof
+ forwarded Android binding correlation
+ nested parent/child proof
+ geo/DNS/IPv6 consistency
+ cleanup ownership closure
+ validation-of-observability mutants
```
