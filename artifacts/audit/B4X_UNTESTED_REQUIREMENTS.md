# B4X Untested Requirements

Дата: 31.07.2026. Требования без исполняемого тестового покрытия (причины: пакет не подключён / тесты не компилируются / тестов нет).

| Группа | Требования | Причина | Источник |
|---|---|---|---|
| WARP v1.2 | все 44 (WARP-1..12, WARP-C1..10, ADR-WARP-1..7) | пакет не подключён; 19/19 тестов покрывают только модели; нет тестов hard gates, causal trace, leak counter, P0 | warp_audit.md |
| MON v1.0 | MON-1..12 (33) | strangler не реализован; 0 профильных тестов (1 касательный — CutoverVersion) | mon_abd_ddi_audit.md, test_quality_audit.md |
| DDI/TGB | DDI-1..10, TGB-1..10 (30) | детекторная приоритизация не работает (`_ = prior`); bridge-поведение противоречит норме; тестов на #277/#278 нет | mon_abd_ddi_audit.md |
| ABD v1.2 | 24 из 26 (кроме библиотечных контрактов) | схемы (SchemaVersion=1 vs 2, отсутствуют Components/DNS/Infrastructure/Exclusions/Controls/SearchPrior) не соответствуют; authority-механика в runtime не задействована | mon_abd_ddi_audit.md |
| SPF v1.0 | 48 из 74 (PARTIAL+ABSENT): BaselineModel (SPF-19), RetryCorrelator (SPF-20), DifferentialProbeController (SPF-21), quarantine (SPF-40), thresholds (SPF-41), 17/21 hard gates | пакет не подключён; детекционная цепочка отсутствует | sp_ft_spf_audit.md |
| SP v1.6 | 13 из 22; warp_recommendation YAML не реализован (нет path_proof_supported) | пакет не подключён | sp_ft_spf_audit.md |
| FT v1.5 | FT-AC/AD/AE мутанты (9/7/12) не существуют; 1 тест против норм; WARP_CAUSAL_TRACE_READY декларативен | пакет не подключён; Controller не вызывает HardGatesPass | sp_ft_spf_audit.md, test_quality_audit.md |
| PPE | 52 теста не исполняются (build failed); selftest e2e-конвейер не покрыт; PPE-06 авто-старт не проверяем | B4X-AUDIT-003 | test_quality_audit.md |
| CSI | CSI-15 (GSOPassToken поля) — FAIL; 4 NOT-VERIFIED | расхождение нормы и кода | csi_ppe_rstgso_audit.md |
| RST/GSO | 4 NOT-VERIFIED | не удалось верифицировать (см. csi_ppe_rstgso_audit.md) | csi_ppe_rstgso_audit.md |
| IV v1.5 | критерии 1–86 | неисполнимы без активных hard gates и meta-suite | hard_gates_audit.md |
| ARCH v2.4 | §42–45 (hold: частично), §132–136 (WARP: мёртв) | см. patch_plan_quality.md | patch_plan_quality.md |
| geodat, quic | 0 тестов при активном использовании | нет тест-файлов | wiring_analysis.md |
| metrics | пакет пустой (коллектор в handler) | нет тестов | wiring_analysis.md |
