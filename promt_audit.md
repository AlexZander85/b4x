Полный независимый read-only аудит реализации B4X
0. Роль и конечная задача
Ты — независимый архитектурный и implementation-аудитор проекта B4X.
В репозитории заявлена полная реализация основного patch plan и всех перечисленных post-v2.3 addenda. Твоя задача — не подтвердить заявление разработчика, а подвергнуть его максимально строгой проверке.
Ты обязан:
1.	прочитать все нормативные документы полностью;
2.	разложить их на атомарные требования;
3.	сопоставить каждое требование с production-кодом;
4.	проверить реальный runtime path;
5.	проверить tests, hard gates, lifecycle, cleanup и observability;
6.	запустить все доступные безопасные проверки;
7.	найти полный список ошибок и архитектурных несоответствий;
8.	выявить формальные, фиктивные и не подключённые к runtime реализации;
9.	составить доказательный каталог findings;
10.	сформировать приоритизированный backlog для отдельного fixing-agent.
Ты не исправляешь код. Исправления будет выполнять другой coding-agent на основании твоих отчётов.
Главный результат:
полная requirement traceability matrix
+ полный каталог подтверждённых дефектов
+ список недоказанных требований
+ hard-gate audit
+ test-quality audit
+ приоритизированный fix backlog
+ итоговый audit verdict
________________________________________
1. Репозиторий и проверяемая ветка
Репозиторий:
AlexZander85/b4x
Проверяемая ветка:
agent/classifier-v2.3-capture-envelope
В начале аудита зафиксируй:
•	repository URL;
•	текущую ветку;
•	полный HEAD commit SHA;
•	commit timestamp;
•	состояние working tree;
•	staged files;
•	modified files;
•	untracked files;
•	доступную историю commits;
•	Go version;
•	target OS и architecture;
•	build tags;
•	версии внешних binaries;
•	доступность Keenetic/router environment;
•	доступность Android test device;
•	доступность target-side capture;
•	доступность WARP/MASQUE environment;
•	доступность reference observers;
•	доступность CI и сохранённых test artifacts.
Если фактическая ветка отличается от указанной, не переключай её скрытно. Зафиксируй расхождение и явно укажи, какой commit был проверен.
________________________________________
2. Строгий read-only режим
2.1. Запрет изменений
Ты не имеешь права:
•	изменять production-код;
•	исправлять обнаруженные ошибки;
•	изменять tests;
•	добавлять tests;
•	менять нормативные документы;
•	менять generated files;
•	менять конфигурацию;
•	менять dependencies;
•	запускать автоматический formatter по tracked-файлам;
•	выполнять migrations, меняющие repository state;
•	делать commit;
•	делать push;
•	создавать или обновлять pull request;
•	переключать branch;
•	переписывать историю;
•	удалять файлы;
•	переименовывать файлы;
•	ослаблять assertions;
•	отключать hard gates;
•	добавлять suppressions;
•	менять test expectations под текущую реализацию;
•	применять strategy/config/runtime deployment;
•	выполнять production promotion;
•	оставлять активные temporary routes, tunnels или firewall rules.
Запрещённые команды включают:
git commit
git push
git reset --hard
git clean
git checkout -- <tracked-file>
git restore <tracked-file>
go get
go mod tidy
npm install с изменением lock-файлов
любые apply/promote/deploy команды
2.2. Разрешённые действия
Разрешено:
•	читать файлы;
•	читать Git history;
•	читать commits и diffs;
•	строить call graph;
•	выполнять grep/static search;
•	запускать builds;
•	запускать unit/integration/API/UI tests;
•	запускать race detector;
•	запускать bounded fuzzing;
•	запускать static analysis;
•	запускать read-only diagnostics;
•	собирать packet captures и traces в изолированной тестовой среде;
•	создавать локальные audit reports.
Audit artifacts размещай только в:
artifacts/audit/
Они должны оставаться untracked и не должны попадать в commit или push.
2.3. Изоляция проверок
Перед выполнением потенциально изменяющих tests предпочитай:
отдельный disposable clone
или
временный read-only audit worktree
или
копию repository tree
Проверяемый исходный commit должен оставаться неизменным.
Перед и после каждой test group фиксируй:
git status --short
git diff --stat
git diff
Если test/tool изменил tracked files:
1.	сохрани diff как evidence;
2.	зафиксируй нарушение test isolation;
3.	создай отдельный finding;
4.	не скрывай изменение;
5.	не включай такой test run в доказательство чистого release verdict.
________________________________________
3. Нормативная иерархия
3.1. Главный архитектурный reference design
Главным консолидированным reference design является:
B4_FORK_ARCHITECTURE_v2.4.md
Он определяет:
•	общую архитектуру;
•	ownership подсистем;
•	межсистемные границы;
•	runtime data flow;
•	scope model;
•	authorization boundaries;
•	transactional generation model;
•	lifecycle;
•	cleanup;
•	canary;
•	promotion;
•	rollback;
•	release dependencies;
•	architectural ADR;
•	обязательные safety invariants.
3.2. Закрытый обязательный набор implementation specifications
Аудит должен проверить фактическое выполнение всех требований без исключения из следующих документов:
B4_FORK_PATCH_PLAN.md

B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md

B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md

B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md

B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md

B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md

B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md

B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md

B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md

B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md

B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md

B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md
Это закрытый обязательный список. Не заменяй ни один документ исторической версией.
3.3. Разделение объединённого addendum
Документ:
B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md
проверяется как два независимых workstream:
Detector-Guided Discovery
Telegram Bridge Hardening
Для них обязательны:
•	отдельные requirement IDs;
•	отдельные findings;
•	отдельные coverage summaries;
•	отдельные audit reports;
•	отдельные subsystem verdicts.
3.4. Разрешение конфликтов
При расхождении:
1.	актуальный addendum определяет детали собственной подсистемы;
2.	B4_FORK_ARCHITECTURE_v2.4.md определяет межсистемные границы;
3.	B4_FORK_PATCH_PLAN.md определяет classifier foundation и обязательную базовую последовательность;
4.	Implementation Validation и Field Test Automation определяют требования к доказательству реализации;
5.	код, старые комментарии и historical files не могут отменять нормативные требования.
Каждый обнаруженный конфликт между нормативными документами занеси в findings. Не исправляй документы самостоятельно.
________________________________________
4. Запрет неполного охвата
Ты не имеешь права:
•	проверять только ключевые разделы;
•	ограничиться Definition of Done;
•	ограничиться названиями stages;
•	проверять только наличие файлов;
•	проверять только наличие типов или функций;
•	пропускать prose requirements;
•	пропускать schemas;
•	пропускать псевдокод;
•	пропускать diagrams;
•	пропускать hard gates;
•	пропускать release dependencies;
•	пропускать lifecycle;
•	пропускать cleanup;
•	пропускать rollback;
•	пропускать migration/compatibility;
•	пропускать privacy/security;
•	пропускать API/UI requirements;
•	пропускать Field Test Automation;
•	пропускать Implementation Validation;
•	считать addendum проверенным только по нескольким unit tests;
•	считать требование покрытым другим документом без точной трассировки;
•	объявлять аудит завершённым при неполном чтении хотя бы одного документа.
Каждый документ необходимо разложить на атомарные требования.
________________________________________
5. Что считается фактической реализацией
Для каждого требования должна быть доказательная цепочка:
нормативное требование
→ production implementation
→ реальный runtime entry point
→ integration с зависимостями
→ positive test
→ negative test
→ failure-path test
→ lifecycle/cleanup proof
→ observability evidence
→ hard-gate/release-verdict integration
Наличие структуры, interface, enum, API endpoint, metric или test filename само по себе не является доказательством.
Требование считать невыполненным, если присутствует хотя бы одно:
•	тип объявлен, но production path его не использует;
•	функция существует, но не вызывается;
•	используется legacy implementation;
•	config field парсится, но не применяется;
•	API возвращает placeholder;
•	результат вычисляется, но не влияет на decision;
•	нарушение только логируется;
•	hard gate существует, но не блокирует unsafe action;
•	hard gate не влияет на release verdict;
•	metric никогда не инкрементируется;
•	metric всегда равна нулю из-за отсутствия producer;
•	test проверяет только serialization;
•	test проверяет только non-nil;
•	test не выполняет side effect;
•	test использует mock вместо production path;
•	отсутствует negative test;
•	отсутствует failure-path test;
•	отсутствует cleanup;
•	отсутствует generation validation;
•	отсутствует scope validation;
•	router-origin check выдан за forwarded-client proof;
•	первый успешный IP скрывает failures других endpoint;
•	incomplete или unknown превращается в PASS;
•	skipped test превращается в PASS;
•	test artifact относится к другому commit;
•	release report создан при dirty working tree;
•	behavior зависит от undocumented manual step;
•	default mode небезопасен;
•	существует competing source of truth;
•	новая subsystem реализована, но runtime продолжает использовать старую.

## 5.1. Обязательное доказательство production reachability

Для каждого заявленного реализованного stage, feature, capability и release verdict
аудитор обязан доказать достижимость реализации от реального production root.

Допустимые production roots включают только фактически используемые:

- process startup/bootstrap;
- packet/NFQUEUE/TUN entry point;
- TPROXY/listener accept loop;
- DNS resolver/forwarder entry point;
- REST/API handler, зарегистрированный в production router;
- config load/reload path;
- scheduler/controller loop;
- transactional apply/promote/rollback entry point;
- real CLI command, включённый в production binary.

Требуемая цепочка:

production root
→ registration/wiring
→ runtime owner
→ implementation
→ observable side effect
→ cleanup/rollback path

Для каждого требования необходимо указать:

- production root;
- точный файл и строку регистрации;
- полный call chain до реализации;
- build tags и platform conditions;
- config/API condition, активирующий путь;
- фактический side effect;
- failure path;
- cleanup path;
- integration test, входящий через тот же production root.

Не считаются production reachability:

- прямой вызов helper из unit-теста;
- standalone constructor test;
- тест структуры или метода Valid();
- manually populated validation object;
- test-only adapter;
- example;
- benchmark;
- documentation;
- report;
- schema без runtime consumer;
- API type без зарегистрированного handler;
- handler без вызова runtime subsystem;
- interface без production caller;
- package, который компилируется, но не импортируется production root;
- функция, вызываемая только другими недостижимыми функциями.

Для каждого нового exported type/function и каждого stage deliverable выполни
reverse-call/reachability analysis.

Если новый механизм существует, но реальный runtime продолжает старый path:

status = FAIL
severity минимум HIGH

Если при этом release/validation report утверждает readiness:

создай отдельный finding о ложном readiness verdict.

Успешная compilation и go test не компенсируют отсутствие production reachability.
Антипример TGB:

Добавлены FirstDataMachine, PendingHandshakeManager, BridgeOutcome и RoutePlan,
но TransparentBridge.Handle по-прежнему использует fixed 5-second deadline
и возвращает legacy bool.

Такое состояние означает FAIL для соответствующих TGB stages,
даже если package tests проходят.

________________________________________
6. Статусы требований
Используй только:
PASS
FAIL
BLOCKED
NOT_APPLICABLE
PASS
Допускается только при полном воспроизводимом evidence:
•	найден production implementation;
•	найден runtime entry point;
•	проверена call chain;
•	выполнены применимые tests;
•	проверены failure paths;
•	проверен cleanup;
•	проверены hard gates;
•	evidence привязан к текущему commit.
FAIL
Используй для:
•	ошибки;
•	отсутствующей функции;
•	неполной функции;
•	архитектурного нарушения;
•	отсутствующего runtime integration;
•	фиктивной реализации;
•	недостаточного теста;
•	отсутствующего test;
•	ложного PASS;
•	неработающего gate;
•	недоказанного обязательного требования.
BLOCKED
Допускается только при объективном отсутствии:
•	оборудования;
•	Android device;
•	Keenetic/router;
•	external observer;
•	credentials;
•	WARP/MASQUE environment;
•	target-side capture;
•	требуемой network topology.
Для каждого BLOCKED укажи:
•	точную причину;
•	отсутствующую зависимость;
•	какой сценарий не выполнен;
•	точные команды для будущего выполнения;
•	ожидаемые evidence artifacts;
•	критерии PASS/FAIL.
BLOCKED не считается успешным выполнением.
NOT_APPLICABLE
Допускается только со ссылкой на конкретное нормативное основание.
Запрещены:
PARTIAL
PARTIAL_PASS
MOSTLY_IMPLEMENTED
LIKELY_PASS
ASSUMED
SHOULD_WORK
IMPLEMENTED_BY_DESIGN
MANUAL_REVIEW_ONLY
Если доказательство неполное — статус должен быть FAIL или BLOCKED.
________________________________________
7. Идентификаторы требований
Используй стабильные префиксы:
ARCH-*    — B4_FORK_ARCHITECTURE_v2.4.md

PATCH-*   — B4_FORK_PATCH_PLAN.md

PPE-*     — B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md

RSTGSO-*  — B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md

CSI-*     — B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md

SPF-*     — B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md

WARP-*    — B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md

ABD-*     — B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md

MON-*     — B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md

DGD-*     — Detector-Guided Discovery portion

TGB-*     — Telegram Bridge Hardening portion

SP-*      — B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md

IV-*      — B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md

FT-*      — B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md
ID должен быть:
•	уникальным;
•	стабильным;
•	machine-readable;
•	привязанным к document section/stage;
•	сохранённым во всех последующих reports.
________________________________________
8. Normative Document Coverage
Создай:
artifacts/audit/B4X_NORMATIVE_DOCUMENT_COVERAGE.md
artifacts/audit/B4X_NORMATIVE_DOCUMENT_COVERAGE.json
Для каждого нормативного документа вычисли:
•	точное имя файла;
•	SHA-256;
•	размер;
•	количество строк;
•	sections total;
•	sections processed;
•	stages total;
•	stages processed;
•	hard gates total;
•	hard gates processed;
•	definitions of done total;
•	definitions of done processed;
•	extracted requirements;
•	requirements with status;
•	coverage complete.
JSON contract:
{
  "document": "exact filename",
  "sha256": "document hash",
  "sections_total": 0,
  "sections_processed": 0,
  "stages_total": 0,
  "stages_processed": 0,
  "hard_gates_total": 0,
  "hard_gates_processed": 0,
  "definitions_of_done_total": 0,
  "definitions_of_done_processed": 0,
  "requirements_extracted": 0,
  "requirements_with_status": 0,
  "coverage_complete": false
}
Если хотя бы для одного обязательного документа:
coverage_complete == false
финальный verdict обязан быть:
B4X_AUDIT_INCOMPLETE
________________________________________
9. Requirement Traceability Matrix
Создай:
artifacts/audit/B4X_REQUIREMENT_TRACEABILITY_MATRIX.md
artifacts/audit/B4X_REQUIREMENT_TRACEABILITY_MATRIX.json
Для каждого атомарного требования укажи:
Requirement ID
Normative document
Document SHA-256
Document version
Section
Stage
Exact text or precise requirement summary
Requirement category
Dependencies
Expected behavior
Expected default mode
Implementation files
Exact line ranges
Runtime entry points
Call-chain summary
Config fields
API endpoints
UI surfaces
Persistence objects
Metrics/events/traces
Hard gates
Relevant tests
Tests actually executed
Observed evidence
Status
Finding IDs
Missing evidence
Recommended remediation direction
Acceptance criteria
Каждое FAIL должно ссылаться хотя бы на один finding.
Каждый finding должен ссылаться хотя бы на одно нормативное требование, кроме чисто informational observations.
________________________________________
10. Findings Catalog
Создай:
artifacts/audit/B4X_FINDINGS_CATALOG.md
artifacts/audit/B4X_FINDINGS_CATALOG.json
Идентификаторы:
B4X-AUDIT-0001
B4X-AUDIT-0002
...
Для каждого finding укажи:
Finding ID
Title
Severity
Confidence
Subsystem
Normative requirement IDs
Affected files
Exact line ranges
Affected runtime entry points
Affected call chain
Expected behavior
Actual behavior
Reproduction steps
Exact commands
Observed output
Evidence artifact paths
Root-cause hypothesis
User impact
Traffic impact
Security impact
Cross-service impact
Lifecycle/cleanup impact
Why existing tests missed it
Misleading tests
Missing tests
Recommended correction direction
Acceptance criteria
Dependencies
Recommended fix order
Regression scenarios
Residual risks
Не объединяй независимые root causes в один finding.
Одинаковый root cause, проявляющийся в нескольких местах, можно объединить, но перечисли все:
•	files;
•	paths;
•	requirements;
•	scenarios;
•	impacts.
________________________________________
11. Severity и confidence
Severity
Используй:
CRITICAL
HIGH
MEDIUM
LOW
INFO
CRITICAL
Примеры:
•	cross-client contamination;
•	cross-service destructive action;
•	global route takeover;
•	mixed active generation;
•	rollback не восстанавливает согласованное состояние;
•	stale authorization выполняет action;
•	traffic corruption;
•	secret exposure;
•	удаление foreign firewall/PPE resources;
•	ложный production-ready verdict при известных violations.
HIGH
Примеры:
•	обязательная subsystem не подключена к runtime;
•	legacy Watchdog сохраняет direct apply;
•	passive evidence создаёт BlockingProfile;
•	incomplete visibility не блокирует unsafe action;
•	WARP работает без scope/path proof;
•	hard gate не влияет на promotion;
•	field-test runner выдаёт ложный PASS;
•	отсутствует обязательный rollback.
MEDIUM
Примеры:
•	неполный failure path;
•	cleanup leak в ограниченном сценарии;
•	API/runtime inconsistency;
•	неполная schema validation;
•	недостаточные bounds;
•	отсутствующая observability;
•	test coverage gap для обязательного scenario.
LOW
Примеры:
•	неточная diagnostic information;
•	слабое error message;
•	неполная trace detail;
•	minor compatibility issue без safety impact.
INFO
Только необязательные улучшения, которые не являются нарушением нормативных требований.
Confidence
Используй:
CONFIRMED
HIGH
MEDIUM
LOW
CONFIRMED требует воспроизводимого evidence или однозначного code path.
________________________________________
12. Repository Baseline Audit
Создай:
artifacts/audit/00_REPOSITORY_BASELINE.md
artifacts/audit/00_REPOSITORY_BASELINE.json
Проверь:
TODO
FIXME
XXX
HACK
TEMP
not implemented
panic placeholders
unconditional success
hard-coded healthy
hard-coded ready
empty adapters
no-op runtime
test-only production implementation
ignored errors
silent fallbacks
disabled validation
skipped tests
dead code
unreachable code
Отдельно найди:
•	interfaces без production implementation;
•	production functions без callers;
•	config fields без consumers;
•	metrics без producers;
•	gates без consumers;
•	API endpoints без runtime state;
•	lifecycle objects без cleanup;
•	generation-bound objects без generation check;
•	scopes, ключованные только destination;
•	duplicate schemas с несовпадающей семантикой;
•	competing sources of truth;
•	compatibility adapters, продолжающие выполнять legacy logic;
•	tests, которые изменяют repository state.
Каждый подтверждённый случай оформи finding.
________________________________________
13. Аудит B4_FORK_PATCH_PLAN.md
Проверь все stages полностью.
Особое внимание:
•	capture envelope;
•	ClientKey;
•	FlowKey;
•	source-scoped DNS evidence;
•	DNS A/AAAA;
•	CNAME;
•	NXDOMAIN;
•	SERVFAIL;
•	caching;
•	provider failover;
•	SNI extraction;
•	fragmented ClientHello;
•	ClientHello reassembly;
•	ECH ambiguity;
•	QUIC Initial;
•	TCP FSM;
•	unique progress;
•	retransmission idempotency;
•	hold/replay;
•	fail-open;
•	ActionAuthorization;
•	ActionPlan;
•	action executor;
•	processed marks;
•	queue ownership;
•	target-side capture diagnostics;
•	TUN end-to-end;
•	UDP NAT/flow table;
•	SOCKS5 fallback;
•	IPv4/IPv6 parity;
•	transactional hot apply;
•	deterministic canary;
•	promotion;
•	rollback;
•	last-good;
•	observability;
•	per-flow telemetry;
•	issue bundles;
•	API;
•	UI.
Проверь, что stage completion не основан только на наличии файлов или tests.
Создай:
artifacts/audit/01_PATCH_PLAN_AUDIT.md
artifacts/audit/01_PATCH_PLAN_AUDIT.json
________________________________________
14. Аудит Keenetic PPE
Документ:
B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
Проверь режимы:
detect
exclude
disable-global
Проверь:
•	capability определяется по фактическим kernel capabilities;
•	отсутствуют model-name assumptions;
•	target/match semantics;
•	tables/chains;
•	privileges;
•	locks;
•	IPv4/IPv6;
•	NDM regeneration;
•	deterministic comments;
•	resource ownership;
•	idempotent apply/remove;
•	client scope;
•	flow scope;
•	no unrelated exclusion;
•	first outgoing packets visible;
•	SYN-ACK visible;
•	FIN/RST visible;
•	second ClientHello segment visible;
•	processed bypass intact;
•	visibility verdict propagation;
•	crash/restart cleanup;
•	reboot cleanup;
•	foreign resource preservation;
•	established compatible flows возвращаются в PPE;
•	bounded CPU cost;
•	incomplete/unknown visibility блокирует зависящие от неё actions.
Создай:
artifacts/audit/02_PPE_AUDIT.md
artifacts/audit/02_PPE_AUDIT.json
________________________________________
15. Аудит RST/GSO Hardening
Документ:
B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
GSO/GRO
Проверь:
•	GSO является packet representation;
•	GSO не является свойством target domain;
•	classification parity между GSO и equivalent MSS layouts;
•	normalization выполняется только когда требуется ActionPlan;
•	first-pass token;
•	secondary pass не классифицирует заново;
•	secondary pass не авторизует заново;
•	single action execution;
•	no duplicate fake;
•	no amplification;
•	retransmission safety;
•	generation invalidation;
•	transactional queue/rule/mark apply;
•	rollback temporary queues/tokens;
•	checksum;
•	MTU;
•	IPv4;
•	IPv6;
•	malformed metadata fail-open.
Passive RST
Проверь:
•	direction;
•	seq plausibility;
•	ACK plausibility;
•	window plausibility;
•	TTL/hop baseline;
•	server progress;
•	independent evidence;
•	observe default;
•	conservative mode gates;
•	aggressive mode gates;
•	controls;
•	false-positive budget;
•	incomplete visibility suppression;
•	rollback;
•	distinction between inbound passive RST и controlled outbound RST.
Создай:
artifacts/audit/03_RST_GSO_AUDIT.md
artifacts/audit/03_RST_GSO_AUDIT.json
________________________________________
16. Аудит Cross-Service Isolation
Документ:
B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
Докажи или опровергни, что применимый scope включает:
ClientKey
+ ServiceProfileID или SetID
+ ComponentID или TargetRole
+ destination/protocol
+ NetworkContextID
+ ConfigGeneration
Проверь:
•	shared Google IP;
•	shared Meta IP;
•	shared CDN IP;
•	IP/CIDR/port являются capture hints;
•	IP/CIDR/port не дают destructive authorization;
•	clear SNI override;
•	reassembled SNI override;
•	DNS evidence не пересекается между клиентами;
•	failure state не destination-global;
•	escalation state не destination-global;
•	route binding не destination-global;
•	learned IP не становится authoritative;
•	YouTube не затрагивает Gmail;
•	YouTube не затрагивает Google Feed;
•	Telegram transport не затрагивает соседний traffic;
•	WARP binding не расширяется на другой client/component;
•	rollback восстанавливает controls;
•	isolation metrics участвуют в promotion/release verdict.
Проверяй maps, caches, persistence schemas и keys, а не только classifier code.
Создай:
artifacts/audit/04_CROSS_SERVICE_ISOLATION_AUDIT.md
artifacts/audit/04_CROSS_SERVICE_ISOLATION_AUDIT.json
________________________________________
17. Аудит Silent Path Failure and Scoped Recovery
Документ:
B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md
Проверь:
•	unique useful progress;
•	TCP milestones;
•	TLS milestones;
•	HTTP headers;
•	unique body bytes;
•	throughput/application milestones;
•	duplicate ACK не обновляет progress;
•	duplicate data не обновляет progress;
•	retransmission не обновляет progress;
•	inter-chunk stalls;
•	fast parallel-flow suppressor;
•	HLS/prefetch suppressor;
•	fresh same-scope success;
•	compatible-protocol success;
•	server/application response;
•	app lifecycle;
•	resource state;
•	visibility state;
•	classification ambiguity;
•	control health;
•	confidence ladder;
•	recurrence;
•	differential proof;
•	false-positive budgets.
Каждый RecoveryLease проверь на:
exact scope
generation
binding
expiry
rollback target
dependency graph
Проверь:
•	минимально агрессивный recovery order;
•	no global route;
•	no recursive fallback;
•	WARP-path failure не выбирает WARP снова;
•	strict non-RU не ослабляется;
•	cleanup;
•	expiration;
•	false-positive rollback;
•	forwarded-client proof;
•	unrelated controls.
Создай:
artifacts/audit/05_SILENT_PATH_RECOVERY_AUDIT.md
artifacts/audit/05_SILENT_PATH_RECOVERY_AUDIT.json
________________________________________
18. Аудит Built-in WARP/MASQUE
Документ:
B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md
Base WARP
Проверь:
•	built-in provider ownership;
•	enrollment;
•	credentials;
•	secret storage;
•	secret redaction;
•	MASQUE lifecycle;
•	CONNECT-IP;
•	TUN lifecycle;
•	routes;
•	rules;
•	marks;
•	DNS path;
•	IPv4;
•	IPv6;
•	MTU;
•	MSS;
•	reconnect;
•	endpoint validation;
•	certificate/trust policy;
•	credential rotation;
•	crash cleanup;
•	restart cleanup;
•	reboot cleanup;
•	exact client/service/component scope;
•	ConfigGeneration;
•	BindingID;
•	RouteTokenID;
•	route/path proof;
•	forwarded-client proof;
•	no global default route без отдельного разрешения.
Causal trace
Проверь связанность:
authorization
→ transport binding
→ route token
→ socket/path
→ target flow
→ control flows
→ cleanup
→ rollback
Проверь:
•	completeness;
•	ordering;
•	IDs;
•	generation;
•	current counters;
•	target identity;
•	control identity;
•	no orphan resources.
Camouflage
Проверь:
•	применяется только к WARP control traffic;
•	имеет отдельное authorization;
•	target IP blocking не авторизует camouflage;
•	service ActionAuthorization не наследуется;
•	прекращается после CONNECT-IP/established state;
•	не затрагивает established tunnel traffic.
WARP+WARP и non-RU
Проверь:
•	independent geo requirement;
•	experimental gate;
•	dependency graph;
•	no recursion;
•	provider quorum;
•	stale attestation;
•	conflicting attestation;
•	strict route;
•	fail-closed;
•	DNS leak prevention;
•	IPv6 leak prevention;
•	cleanup;
•	отсутствие обещания гарантированной страны;
•	base/camouflage/non-RU имеют отдельные verdicts.
Создай:
artifacts/audit/06_WARP_MASQUE_AUDIT.md
artifacts/audit/06_WARP_MASQUE_AUDIT.json
________________________________________
19. Аудит Adaptive Blocking Detector
Документ:
B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md
Monitoring ↔ ABD contract
Проверь:
MonitorAssessment
→ MonitorDiagnosticRequest
→ TargetPlanOverlay
→ ABD run
→ BlockingProfile
→ MonitorDiagnosticResult
Проверь обязательные поля:
•	request identity;
•	assessment identity;
•	ClientScope;
•	ServiceProfileID;
•	ComponentID;
•	TargetRole;
•	NetworkContextID;
•	ConfigGeneration;
•	MonitoringEpoch;
•	DiagnosticBudgetToken;
•	expiry;
•	ResolutionRefs;
•	ObservationRefs;
•	SuppressorSnapshot.
TargetPlan
Проверь, что overlay не способен исключить обязательные:
•	direct baseline;
•	production baseline;
•	same-service controls;
•	unrelated controls;
•	reference targets;
•	alternate IP family.
Resolution
Проверь:
•	exact client-observed resolution;
•	independent current resolution;
•	отсутствие silent replacement;
•	CNAME chain;
•	terminal IP attribution;
•	selected endpoint;
•	per-address outcomes;
•	partial-address failure;
•	first success не удаляет failures;
•	IPv4/IPv6;
•	TTL;
•	freshness.
Evidence Authority
Проверь:
passive-monitoring
provisional-fast
authoritative-abd
android-canary
Passive/provisional evidence не должно самостоятельно:
•	создавать final BlockingProfile;
•	считаться independent active probe;
•	давать ActionAuthorization;
•	запускать WARP;
•	запускать production Discovery apply.
Failure model
Проверь разделение:
ProbeFailureCode
→ FailureAttribution
→ BlockingHypothesis
→ Recommendation
Multi-vantage
Проверь capabilities observer:
•	DNS;
•	TCP;
•	TLS;
•	certificate verification;
•	HTTP headers;
•	HTTP body progress;
•	QUIC;
•	fingerprints;
•	IP families.
Проверь запреты:
•	HTTP hypothesis из TCP-only observer;
•	unavailable observer как failure;
•	exact endpoint и independent resolution не смешиваются;
•	unverified TLS alert не является окончательным origin proof;
•	один observer не считается безусловной истиной.
Completion
Проверь:
•	complete;
•	incomplete;
•	canceled;
•	suppressed;
•	rejected;
•	incomplete run не создаёт final profile;
•	result связан с assessment;
•	no cross-generation result;
•	no cross-network result;
•	no cross-epoch result.
Создай:
artifacts/audit/07_ADAPTIVE_BLOCKING_DETECTOR_AUDIT.md
artifacts/audit/07_ADAPTIVE_BLOCKING_DETECTOR_AUDIT.json
________________________________________
20. Аудит Continuous Monitoring
Документ:
B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md
Проверь:
•	MonitorObservationBus;
•	bounded event intake;
•	subject identity;
•	ClientKey;
•	ServiceProfileID;
•	ComponentID;
•	TargetRole;
•	network context;
•	config generation;
•	ClientResolutionSnapshot;
•	DNS query correlation;
•	CNAME correlation;
•	selected endpoint;
•	flow-health correlation;
•	temporal buckets;
•	time separation;
•	recurrence;
•	evidence independence;
•	contradictions;
•	decay;
•	hysteresis;
•	recovery;
•	source heartbeat;
•	visibility suppressors;
•	resource suppressors;
•	global WAN suppressor;
•	scheduler;
•	quick budget;
•	deep budget;
•	cooldown;
•	persistence;
•	privacy;
•	redaction;
•	API;
•	UI.
Проверь отсутствие production path:
passive observation
→ Discovery
→ direct config mutation
Найди и проверь legacy:
watchdog checker
applyBatchResults
watchdog-* set creation
direct Discovery apply
Установи:
•	вызываются ли они;
•	доступны ли через config/API;
•	могут ли работать одновременно с новым monitor;
•	могут ли стать source of truth после restart;
•	могут ли изменять production config без ABD/DDI/canary.
Проверь migration phases:
•	shadow;
•	trigger shadow;
•	diagnostic cutover;
•	API cutover;
•	apply cutover;
•	removal.
Создай:
artifacts/audit/08_CONTINUOUS_MONITORING_AUDIT.md
artifacts/audit/08_CONTINUOUS_MONITORING_AUDIT.json
________________________________________
21. Аудит Detector-Guided Discovery
Источник:
B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md
Проверяемая цепочка:
BlockingProfile
→ DDI
→ freshness/context validation
→ candidate-family prioritization
→ mandatory baselines
→ guided search
→ bounded full fallback
→ canary
→ promote или rollback
Проверь:
•	stale profile rejected;
•	cross-network profile rejected;
•	cross-generation profile rejected;
•	Detector output не является ActionAuthorization;
•	DDI provenance;
•	baseline-none;
•	baseline-production;
•	same-service controls;
•	unrelated controls;
•	bounded full fallback;
•	candidate coverage accounting;
•	capacity budgets;
•	partial runs;
•	resumability;
•	no silent candidate exclusion;
•	causal candidate results;
•	deterministic canary;
•	target proof;
•	control proof;
•	promotion gates;
•	rollback;
•	last-good;
•	Discovery не подменён Detector;
•	Detector только меняет search priors/order/budget.
Создай:
artifacts/audit/09_DETECTOR_GUIDED_DISCOVERY_AUDIT.md
artifacts/audit/09_DETECTOR_GUIDED_DISCOVERY_AUDIT.json
________________________________________
22. Аудит Telegram Bridge Hardening
Источник:
B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md
Проверь:
•	delayed-first-data FSM;
•	pending manager;
•	bounded pending state;
•	timeout;
•	cancellation;
•	prefix preservation;
•	no byte loss;
•	no byte duplication;
•	transparent handoff;
•	partial first data;
•	half-close;
•	reconnect;
•	cleanup;
•	no recursive fallback;
•	direct path;
•	MTProxy;
•	SOCKS5;
•	WARP;
•	fallback separation;
•	exact ClientKey;
•	ServiceProfileID/component scope;
•	no destination-global routing;
•	multiple Telegram DCs;
•	media;
•	app reconnect;
•	crash/restart;
•	route leak prevention;
•	secret leak prevention;
•	Android Telegram proof.
Router-origin probe не является доказательством Telegram client success.
Создай:
artifacts/audit/10_TELEGRAM_BRIDGE_AUDIT.md
artifacts/audit/10_TELEGRAM_BRIDGE_AUDIT.json
________________________________________
23. Аудит Service Profiles and Beginner UX
Документ:
B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md
Compiler
Проверь:
•	schema;
•	version;
•	compatibility;
•	deterministic compile;
•	canonical hash;
•	ownership;
•	managed;
•	manual;
•	pinned;
•	excluded;
•	conflict detection;
•	preview diff;
•	signatures;
•	provenance;
•	no executable fields;
•	no raw firewall snippets;
•	no external hooks;
•	no embedded secrets;
•	update;
•	removal;
•	rollback;
•	preserving manual objects.
Runtime boundaries
Проверь отсутствие service-specific branches в packet core.
Profile не должен владеть:
•	NFQUEUE topology;
•	queue numbers;
•	marks;
•	GSO tokens;
•	RST baseline;
•	PPE lifecycle;
•	WARP process;
•	WARP credentials;
•	WARP routes;
•	WARP session;
•	Detector;
•	Monitoring;
•	recovery runtime.
Profile задаёт policy и upper bounds, но не обходит runtime safety gates.
Components
Проверь разделение:
api
ui
video/media
transport-required components
Проверь:
•	разные objectives;
•	разные winners;
•	independent health;
•	no cross-component promotion.
WARP recommendation
Проверь state machine:
not-applicable
unavailable
eligible-to-test
testing
validated
rejected
expired
blocked-by-safety
Проверь:
•	fresh scoped IP/SYN/CIDR evidence;
•	healthy controls;
•	reference path;
•	origin health;
•	target canary;
•	forwarded-client proof;
•	production authorization;
•	no recommendation по одному destination IP;
•	no recommendation при dead origin;
•	no production authorization из test token;
•	no automatic non-RU без geo requirement;
•	camouflage не предлагается из-за target IP blocking;
•	temporary route cleanup;
•	fail-open/fail-closed visible.
Beginner UX
Проверь:
•	uncertainty-aware wording;
•	no false Healthy;
•	suspicion отдельно от confirmed;
•	exact scope;
•	controls;
•	degraded capabilities;
•	rollback;
•	advanced visibility;
•	basic и advanced используют одну generation;
•	partial/inconclusive states отображаются честно.
Создай:
artifacts/audit/11_SERVICE_PROFILES_AUDIT.md
artifacts/audit/11_SERVICE_PROFILES_AUDIT.json
________________________________________
24. Аудит Implementation Validation v1.5
Документ:
B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md
Это самостоятельная обязательная implementation specification, а не только список пожеланий.
Проверь наличие и фактическую работу:
•	validation runner;
•	suite registry;
•	schemas;
•	API/CLI contracts;
•	static architecture checks;
•	lifecycle tests;
•	race tests;
•	leak tests;
•	fuzz tests;
•	property tests;
•	mutation tests;
•	fault injection;
•	restart tests;
•	reboot tests;
•	cross-service negative tests;
•	malformed packet tests;
•	malformed manifest tests;
•	stale-generation tests;
•	replay tests;
•	exhaustion tests;
•	cleanup verification;
•	causal trace verification;
•	hard-gate completeness;
•	false-PASS resistance;
•	aggregation;
•	report generation;
•	commit binding.
Validation aggregator не имеет права выдавать PASS, если:
•	required suite отсутствует;
•	suite skipped;
•	environment unknown;
•	required artifact отсутствует;
•	hard gate unknown;
•	field test blocked;
•	report относится к другому commit;
•	working tree dirty;
•	implementation и field verdict конфликтуют;
•	generated report неполон;
•	test ничего не проверяет.
Наличие test files без production runner и verdict aggregation считать FAIL.
Создай:
artifacts/audit/12_IMPLEMENTATION_VALIDATION_AUDIT.md
artifacts/audit/12_IMPLEMENTATION_VALIDATION_AUDIT.json
________________________________________
25. Аудит Field Test Automation v1.5
Документ:
B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md
Проверь:
•	field-test runner;
•	suite registry;
•	suite schemas;
•	prerequisites;
•	environment capture;
•	router commands;
•	Android actions;
•	target-side actions;
•	packet captures;
•	target-side captures;
•	evidence collection;
•	timeout handling;
•	cleanup;
•	retries;
•	artifact naming;
•	commit binding;
•	hard-gate aggregation;
•	failure reporting;
•	blocked reporting;
•	rerun stability;
•	report generation;
•	CLI/API surface.
Каждая обязательная suite должна:
•	реально существовать;
•	иметь runtime implementation;
•	иметь scenario;
•	иметь expected evidence;
•	иметь PASS/FAIL criteria;
•	иметь cleanup;
•	запускаться либо возвращать обоснованный BLOCKED;
•	не превращать skip/unknown в PASS.
Hardware field test нельзя заменять unit test.
Dry-run, который только перечисляет команды, не доказывает выполнение field test.
Создай:
artifacts/audit/13_FIELD_TEST_AUTOMATION_AUDIT.md
artifacts/audit/13_FIELD_TEST_AUTOMATION_AUDIT.json
________________________________________
26. Отдельный аудит Transactional Runtime
Проверь transactions, охватывающие применимые ресурсы:
config snapshot
immutable matcher/runtime
classifier/evidence generation
NFQUEUE owner/topology
marks/firewall rules
PPE rules
route/proxy bindings
WARP bindings
service-profile compiled objects
monitoring generation
last-good metadata
Проверь failure points:
•	parse;
•	schema validation;
•	compilation;
•	ownership conflict;
•	queue allocation;
•	firewall prepare;
•	PPE apply;
•	routing apply;
•	WARP daemon startup;
•	persistence;
•	readiness;
•	canary;
•	commit point;
•	crash before commit;
•	crash after commit;
•	retire previous generation;
•	rollback;
•	rollback health check;
•	concurrent apply;
•	duplicate Idempotency-Key;
•	stale expected generation;
•	reboot during transaction.
Допустимы только:
old complete generation
или
new complete generation
Mixed generation должна быть CRITICAL finding.
Создай:
artifacts/audit/14_TRANSACTIONAL_RUNTIME_AUDIT.md
artifacts/audit/14_TRANSACTIONAL_RUNTIME_AUDIT.json
________________________________________
27. API, UI и config consistency
Сравни:
config schema
Go structs
defaults
validation
migration
runtime consumers
REST API
Swagger/OpenAPI
UI models
UI forms
persistence
import/export
Найди:
•	поля только в одном слое;
•	несовпадающие enum;
•	неправильные defaults;
•	parsed-but-ignored fields;
•	stale endpoints;
•	placeholder endpoints;
•	UI optimistic state;
•	UI Healthy без backend proof;
•	migration semantic loss;
•	secret export;
•	generation mismatch;
•	API action, обходящий transaction engine;
•	API action, обходящий authorization;
•	compatibility path, изменяющий config напрямую.
Создай:
artifacts/audit/15_API_UI_CONFIG_CONSISTENCY_AUDIT.md
artifacts/audit/15_API_UI_CONFIG_CONSISTENCY_AUDIT.json
________________________________________
28. Hard-Gate Audit
Создай:
artifacts/audit/B4X_HARD_GATE_REGISTRY.md
artifacts/audit/B4X_HARD_GATE_REGISTRY.json
Для каждого hard gate укажи:
Gate name
Normative source
Requirement IDs
Producer
Consumer
Runtime condition
Metric/event implementation
Test scenario
Release-verdict dependency
Observed state
Status
Finding IDs
Создай finding, если:
•	gate не производится;
•	gate не потребляется;
•	gate всегда равен нулю;
•	gate не участвует в aggregation;
•	unknown трактуется как success;
•	reset скрывает violation;
•	test не способен сделать gate non-zero;
•	gate только логируется;
•	promotion не блокируется;
•	release verdict не зависит от gate.
________________________________________
29. Test Quality Audit
Не доверяй тестам по названиям.
Для каждого существенного test проверь:
•	какую production function он вызывает;
•	используется ли production path;
•	используется ли mock;
•	проверяется ли side effect;
•	проверяется ли scope;
•	проверяется ли generation;
•	проверяется ли cleanup;
•	проверяется ли failure path;
•	можно ли заменить production implementation на no-op без падения test;
•	влияет ли test result на final verdict.
Отдельно найди:
assertion-free tests
tests checking only non-nil
tests checking only HTTP 200
tests catching and ignoring errors
tests using unconditional PASS
golden tests without semantic assertions
disabled tests
skipped tests
environment unavailable treated as success
tests bound to stale fixtures only
tests that never enter production runtime
Создай:
artifacts/audit/B4X_TEST_QUALITY_AUDIT.md
artifacts/audit/B4X_TEST_QUALITY_AUDIT.json
________________________________________
30. Выполняемые команды
В безопасной изолированной среде запусти применимые:
go test ./...
go test -race ./...
go vet ./...
Также:
•	build для всех заявленных targets;
•	staticcheck;
•	configured linters;
•	unit suites;
•	integration suites;
•	API tests;
•	UI tests;
•	packet fixtures;
•	bounded fuzzing;
•	mutation tests;
•	leak tests;
•	field-test dry-run;
•	реальные field tests, если environment доступен;
•	target-side capture diagnostics;
•	Android tests;
•	router tests;
•	restart/reboot tests.
Для каждого запуска зафиксируй:
Execution ID
Exact command
Working directory
Environment variables
Tool versions
Start time
End time
Exit code
stdout artifact
stderr artifact
Commit SHA
Working tree before
Working tree after
Related requirement IDs
Related finding IDs
Создай:
artifacts/audit/B4X_TEST_EXECUTION_INDEX.md
artifacts/audit/B4X_TEST_EXECUTION_INDEX.json
Не исправляй failures.
________________________________________
31. Security и robustness audit
Проверь:
•	command injection;
•	path traversal;
•	unsafe file permissions;
•	secret leakage;
•	raw capture leakage;
•	issue-bundle privacy;
•	profile signature bypass;
•	unsigned official content;
•	SSRF через probes;
•	SSRF через reference observer;
•	unrestricted proxy activation;
•	route escape;
•	DNS leak;
•	IPv6 leak;
•	scope escalation;
•	cross-client state reuse;
•	cross-service state reuse;
•	token replay;
•	stale authorization;
•	generation confusion;
•	unsafe raw nfqws arguments;
•	malicious profile data;
•	unbounded regex;
•	unbounded input;
•	archive traversal;
•	foreign firewall deletion;
•	foreign PPE rule deletion;
•	stale routes;
•	stale interfaces;
•	stale processes;
•	stale credentials;
•	stale temporary files.
Создай:
artifacts/audit/B4X_SECURITY_ROBUSTNESS_AUDIT.md
artifacts/audit/B4X_SECURITY_ROBUSTNESS_AUDIT.json
________________________________________
32. Performance и resource-bound audit
Проверь или найди evidence для:
•	CPU;
•	memory;
•	goroutines;
•	file descriptors;
•	sockets;
•	packet latency;
•	throughput;
•	NFQUEUE drops;
•	queue user drops;
•	GSO normalization overhead;
•	reassembly memory;
•	monitoring cardinality;
•	ABD parallelism;
•	Discovery candidate count;
•	WARP overhead;
•	PPE exclusion window;
•	trace cardinality;
•	API report size.
Проверь bounded behavior при:
•	сотнях clients;
•	тысячах DNS events;
•	shared CDN;
•	reconnect burst;
•	retransmission storm;
•	malformed traffic;
•	WARP reconnect loop;
•	observer outage;
•	DNS outage;
•	WAN outage;
•	NDM regeneration;
•	config churn;
•	repeated monitor triggers;
•	repeated canary failures.
Создай:
artifacts/audit/B4X_RESOURCE_BOUND_AUDIT.md
artifacts/audit/B4X_RESOURCE_BOUND_AUDIT.json
________________________________________
33. Обязательная сводка по документам
Итоговый report должен содержать таблицу:
Документ/workstream	Требований	PASS	FAIL	BLOCKED	N/A	Coverage complete
B4_FORK_PATCH_PLAN.md						yes/no
B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md						yes/no
B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md						yes/no
B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md						yes/no
B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md						yes/no
B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md						yes/no
B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md						yes/no
B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md						yes/no
Detector-Guided Discovery						yes/no
Telegram Bridge Hardening						yes/no
B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md						yes/no
B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md						yes/no
B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md						yes/no
Coverage complete = yes допускается только если:
•	документ полностью прочитан;
•	все sections обработаны;
•	все stages обработаны;
•	все hard gates обработаны;
•	все Definition of Done обработаны;
•	все требования внесены в matrix;
•	каждому требованию присвоен статус;
•	все findings связаны с requirements;
•	все доступные проверки выполнены;
•	недоступные проверки оформлены как BLOCKED.
________________________________________
34. Fix Backlog для отдельного агента
Создай:
artifacts/audit/B4X_FIX_BACKLOG.md
artifacts/audit/B4X_FIX_BACKLOG.json
Приоритеты:
P0 — безопасность, corruption, cross-service, mixed generation
P1 — отсутствующие runtime paths, direct unsafe paths, ложные verdicts
P2 — lifecycle, cleanup, rollback, visibility, authorization
P3 — функциональная неполнота
P4 — tests, observability, API/UI, validation gaps
P5 — необязательные improvements
Для каждой backlog task укажи:
Backlog ID
Finding IDs
Priority
Recommended order
Subsystem
Likely affected files
Normative requirement IDs
Problem summary
Required implementation outcome
Tests to add or repair
Field validation required
Acceptance criteria
Dependencies
Risk
Estimated complexity: S/M/L/XL
Не пиши готовый patch.
Не изменяй production code.
Backlog должен быть пригоден для непосредственной передачи fixing-agent без повторного полного аудита.
________________________________________
35. Остальные обязательные артефакты
Создай:
artifacts/audit/B4X_UNTESTED_REQUIREMENTS.md
artifacts/audit/B4X_UNTESTED_REQUIREMENTS.json

artifacts/audit/B4X_BLOCKED_VALIDATIONS.md
artifacts/audit/B4X_BLOCKED_VALIDATIONS.json

artifacts/audit/B4X_RESIDUAL_RISK_REGISTER.md
artifacts/audit/B4X_RESIDUAL_RISK_REGISTER.json

artifacts/audit/B4X_ARCHITECTURE_COMPLIANCE_REPORT.md
artifacts/audit/B4X_ARCHITECTURE_COMPLIANCE_REPORT.json

artifacts/audit/B4X_AUDIT_VERDICT.md
artifacts/audit/B4X_AUDIT_VERDICT.json
________________________________________
36. Финальный audit verdict
Допустимые verdicts:
B4X_ARCHITECTURE_COMPLIANT
B4X_NOT_COMPLIANT
B4X_AUDIT_INCOMPLETE
B4X_ARCHITECTURE_COMPLIANT
Разрешён только если:
FAIL == 0
BLOCKED == 0
required skipped tests == 0
all mandatory documents coverage_complete == true
all hard gates verified
all required field tests executed
all required implementation suites executed
all evidence bound to current HEAD
working tree remained clean
B4X_NOT_COMPLIANT
Используй, если:
•	найден хотя бы один подтверждённый FAIL;
•	обязательная implementation отсутствует;
•	runtime нарушает архитектуру;
•	release verdict является ложным;
•	hard gate не работает;
•	test system создаёт ложный PASS.
B4X_AUDIT_INCOMPLETE
Используй, если:
•	хотя бы один документ обработан не полностью;
•	существенная часть repository недоступна;
•	отсутствует нормативный документ;
•	невозможно извлечь требования;
•	значительная часть аудита BLOCKED;
•	невозможно подтвердить проверенный commit;
•	test environment не позволяет завершить обязательный охват.
Не называй систему «100% корректной» без доказательства каждого обязательного requirement.
________________________________________
37. Финальный ответ агента
В финальном ответе укажи:
1.	repository;
2.	branch;
3.	проверенный commit SHA;
4.	working tree до аудита;
5.	working tree после аудита;
6.	hashes всех нормативных документов;
7.	общее число извлечённых требований;
8.	PASS;
9.	FAIL;
10.	BLOCKED;
11.	NOT_APPLICABLE;
12.	findings по severity;
13.	полный список CRITICAL findings;
14.	полный список HIGH findings;
15.	выполненные test commands;
16.	failed tests;
17.	skipped tests;
18.	недоступные environments;
19.	hard-gate coverage;
20.	coverage каждого обязательного документа;
21.	пути ко всем audit artifacts;
22.	рекомендуемый порядок исправлений;
23.	итоговый audit verdict.
Не скрывай findings ради компактности ответа.
Полный каталог может находиться в artifacts, но все CRITICAL и HIGH findings должны быть перечислены непосредственно в финальном сообщении.
________________________________________
38. Главный принцип аудита
Твоя задача не доказать, что реализация хорошая.
Твоя задача попытаться доказать, что реализация:
неполная
не подключена к runtime
архитектурно неверная
небезопасная
неизолированная
нетранзакционная
не имеет rollback
не имеет cleanup
не имеет доказательных tests
создаёт ложный PASS
Только требования, выдержавшие такую проверку, получают PASS.
Никаких исправлений, commits или push.
Только:
найти
→ воспроизвести
→ доказать
→ классифицировать
→ связать с нормативным требованием
→ определить acceptance criteria
→ добавить в fix backlog
