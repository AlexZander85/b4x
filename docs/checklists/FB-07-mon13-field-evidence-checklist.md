# FB-07 / MON-13 — полевой чек-лист field evidence для MON_PRODUCTION_READY

Цель: собрать внешние (полевые) подтверждения для гейта `MON_PRODUCTION_READY` (MON addendum v1.0 §57.1/§59; mon-12/mon-13).
Формат: пошаговая инструкция для человека с доступом к реальному роутеру/машине. Время: ~1,5–2,5 часа.
Что нужно прислать после прогонов — см. раздел 10.

---

## 0. Что понадобится (оборудование)

| # | Ресурс | Обязательно? | Зачем |
|---|---|---|---|
| 1 | Linux-машина с root (роутер на OpenWrt ×86_64/ARM, или обычный Linux-ПК/VM с NETFILTER) | ✅ обязательно | b4 работает только под Linux + root (netfilter queue) |
| 2 | Рабочий интернет на этой машине (WAN) | ✅ обязательно | functional run |
| 3 | Вторая линия интернета (модем/кабель/Cellular USB) | 🔶 желательно | multi-WAN прогон (п. 7) |
| 4 | Android-телефон | 🟡 опционально | полевой прогон с клиента (п. 8) |

> Требования к ядру/пакетам роутера: поддержка NFQUEUE (`nftables`/`netfilter`); на OpenWrt — пакеты `kmod-nfnetlink-queue` и базовый набор (iptables/nftables). Проверка: `nft list tables` или `iptables -L -n` не должны падать.

### 0.1. Что качать и куда класть (обязательно)
- Бинарник `b4` (собрать из исходника — команда ниже) → `/usr/local/bin/b4`, права `chmod 755`.
- Конфиг → `/etc/b4/b4.json` (пример в разделе 2).
- Папка логов → `/etc/b4/logs/` (по умолчанию `system.logging.directory` — см. конфиг ниже).

### 0.2. Сборка бинарника (на вашем ПК — Windows/Любое, где есть Docker)

```bash
# amd64 (обычные ПК/роутеры x86_64)
docker run --rm -v "D:\b4x:/src" -w /src/src golang:1.25.3-bookworm \
  bash -c "GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /src/artifacts/field/b4-amd64 ."

# arm64 (OpenWrt/ARM-роутеры)
docker run --rm -v "D:\b4x:/src" -w /src/src golang:1.25.3-bookworm \
  bash -c "GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o /src/artifacts/field/b4-arm64 ."
```

Файл появится в `artifacts/field/`. Скорировать на устройство: `scp b4-amd64 root@192.168.1.1:/usr/local/bin/b4` (назвать файл просто `b4`).

### 0.3. Проверка бинарника

```bash
b4 --version          # должно показать version + commit
b4 iv18 --json        # IV-18 conformance suite: verdict PASS, production_ready fltr
```

---

## 1. Обязательный конфиг — включить cutover (MON §57.1)

Файл `/etc/b4/b4.json`. Минимум для прогона — две важные строчки в секции `discovery.watchdog`:

```json
{
  "version": <текущий>,
  "system": {
    "web_server": {
      "port": 7000,
      "bind_address": "0.0.0.0"
    },
    "logging": {
      "level": "info",
      "directory": "/etc/b4/logs"
    }
  },
  "discovery": {
    "watchdog": {
      "legacy_watchdog_api": false,
      "legacy_watchdog_direct_apply": false
    }
  }
}
```

Точки:
- `legacy_watchdog_api: false` — кьюовер активен: legacy mutating `/api/watchdog/*` → 410 Gone, `GET /api/watchdog/status` — read-only проекция Monitoring (§57.1).
- `legacy_watchdog_direct_apply` опущено/`false` — безопасно (по умолч. false; `true` невозможно для production).
- Если уже есть рабочий конфиг — добавь эти два ключа в существующую секцию `discovery.watchdog`, не переписывай остальное.
- Если в старой версии конфига ключей нет — b4 сам мигрирует при запуске (автосохранение), дефолты безопасны.

### Проверка загрузки конфига

```bash
b4 --config /etc/b4/b4.json   # в логах ДОЛЖНЫ появиться :
# [WATCHDOG] legacy_watchdog_api=false: cutover active (MON §57.1) — legacy mutating /api/watchdog/* endpoints return 410 Gone; GET /api/watchdog/status serves the Monitoring projection
# Web server started on http://0.0.0.0:7000
```

> ⚠️ `legacy_watchdog_api=false` **включён** — это кьютера. Проверка каждого прогона ниже делается в режиме cutover.

---

## 2. Прогон 1 — Real-router run (базовая работа)

1. Запусти `b4` (в терминале/через сервис, см. раздел 9): `b4 --config /etc/b4/b4.json`
2. Дай поработать 10–15 минут с обычным трафиком (интернет с ноутбука/телефона, заходить на сайты).
3. Проверь живые endpoint'ы (сделай 3 вызова с интервалом ~2 мин):

```bash
curl -s http://127.0.0.1:7000/api/version
curl -s http://127.0.0.1:7000/api/monitor/v1
curl -s http://127.0.0.1:7000/api/watchdog/status
```

Ожидания:
- `GET /api/monitor/v1` — JSON-проекция состояния мониторинга (200).
- `GET /api/watchdog/status` — тот же источник (alias, 200), поля vocabulary §58: `healthy|degraded|queued|escalating` и прочие статусы (не старый формат watchdog).
- `/api/version` — версия и commit.

Артефакт: `curl -s .../api/monitor/v1 > run1_monitor.json` (3 снимка: `run1_monitor_00.json`, `run1_monitor_01.json`...).

4. Убедись, что counter-ка нули:

```bash
curl -s http://127.0.0.1:7000/api/observability/metrics | grep monitor_legacy_watchdog_direct_apply_total
# должно быть: monitor_legacy_watchdog_direct_apply_total 0
```

---

## 3. Прогон 2 — cutover API (410 Gone на все legacy mutating)

Делай ТОЛЬКО после прогона 1 (это не безопасен, но именно он доказывает, что wrong путей закрыт). Порядок вызовов не важен.

```bash
curl -si -X POST http://127.0.0.1:7000/api/watchdog/check
curl -si -X POST -H "Content-Type: application/json" -d '{"domain":"example.com"}' http://127.0.0.1:7000/api/watchdog/domains
curl -si -X DELETE http://127.0.0.1:7000/api/watchdog/domains/example.com
curl -si -X POST http://127.0.0.1:7000/api/watchdog/enable
curl -si -X POST http://127.0.0.1:7000/api/watchdog/disable
```

Ожидания для **всех**: HTTP-статус **410** и Body:

```text
legacy watchdog API is cut over: mutating legacy endpoints are disabled (MON addendum §57.1); use the monitoring API
```

(Заголовок `Content-Type: text/plain; charset=utf-8`.)

Контрольный момент «нет второго источника истины»: повторные `GET /api/watchdog/status` по-прежнему работают как alias (200, не 410) — записать в артефакт рядом с 410-ответами.

Артефакт: `curl -si ... > run2_<имя_эндпоинта>.txt` для каждого.

---

## 4. Прогон 3 — Restart / reboot (устойчивость cutover)

1. **Рестарт процесса** (в терминале: `Ctrl+C`, затем заново запусти `b4`), либо `systemctl restart b4` / `/etc/init.d/b4 restart`.
2. После старта повтори минимум 3 проверки из прогона 2 (410 на один mutating, alias 200, метрика = 0) + `curl /api/monitor/v1`.
3. **Перезагрузка роутера**: `reboot`, подожди до поднятия сети, SSH обратно.
4. Повтори пункт 2.
5. Зафиксируй в лог: startup-предупреждение о cutover появляется заново при каждом старте; никаких сбросов конфига не происходит; `b4 --version` тот же commit.

Артефакт: `run3_after_reboot_*.json/txt`.

---

## 5. Прогон 4 — Multi-WAN / failover (опционально, если есть 2-я линия)

1. Основной интерфейс: активный WAN1. Убедись, что packet-путь работает (проксирует сайты).
2. Отключи WAN1 (команды ниже в зависимости от типа), включи WAN2:
   - физически вытащи кабель / `ip link set wan1 down` / отключи PPPoE-сессию.
3. В течение 60–120 сек делай снимки `GET /api/monitor/v1` и `GET /api/watchdog/status` (каждые 15 сек): ожидается изменение статуса на degraded/queued при обрыве и возврат к healthy после подъёма WAN2.
4. Проверь, что HTTP-тайм для прокси не сломан (открой сайт с ноутбука — грузится).
5. Верни WAN1 (подними) и снова сделай снимок — статус должен вернуться к healthy.

Артефакт: серия снимков `run4_wan_*.json`.

---

## 6. Прогон 5 — Fault injection (обрыв канала)

1. Снимок «до»: `curl /api/monitor/v1 > before.json`, `curl /api/config > before_config.json` (снимок конфига для сравнения).
2. Физически отключи/повали интернет (вытащи кабель WAN или `if link set wan1 down` — на 1–2 минуты, не больше).
3. В течение обрыва (каждые 15–30 сек): снимки `/api/watchdog/status` и `/api/monitor/v1`.
   - Ожидание: статус мониторинга НЕ остаётся «healthy»; видно `degraded`/`queued`/`escalating` (vocabulary §58).
   - Контроль fail-closed: **не** должно происходить никаких изменений конфига, никаких автоматических транзакций (rollout/rollback/применений) — `/api/config` по-прежнему равен `before_config.json` (или содержит только ручные правки).
4. Верни интернет (подними WAN1). Подожди 2–3 мин.
5. Финальный снимок: `/api/monitor/v1` → healthy; метрика zero; конфиг без изменений.

Артефакт: снимки + `diff before_config.json after_config.json` (или их копии; если diff пуст — отлично).

---

## 7. Прогон 6 — Android (опционально, если клиент есть)

1. На телефоне включай прокси на b4 (`socks5://<ip_роутера>:<порт>` или MTProto-прокси, если настроен).
2. Открой 5–10 сайтов/приложений — 5–10 минут трафика.
3. На роутере сними `/api/monitor/v1` и `/api/watchdog/status` — активность клиента видна (статус healthy, есть данные по трафику/паттернам).
4. Прокси выключ – телефон рrometheus прямо (без b4) — 2 мин – мониторинг не должен ломаться.

Артефакт: снимки `run6_android_*.json` + `curl .../api/metrics/summary` (если есть смысл для evidence).

---

## 8. Прогон 7 — Privacy audit (краткий)

1. Возьми файл логов: `/etc/b4/logs/errors.log` (+ `update.log`, если есть) — проверь, нет ли там:
   - паролей/токенов/секретов и содержимого передаваемых данных (не должно быть НИКОГДА);
   - доменов из личного трафика, адресов клиентов (IP из LAN) — только обезличенные счётчики.
2. Собери update-бандл: `curl -s http://127.0.0.1:7000/api/diagnostics/issue-bundle > bundle.zip` — просмотри содержимое (выборочно), убедись в тех же правилах (конфиг содержит чувствительные ключи/пароли? если да — внеси имя файла/секцию в отчёт «исключено из бандла», но не выкладывай содержимое).
3. Запиши вывод одним предложением: «логи/бандл не содержат <чувствительное>».

Артефакт: `privacy_audit_notes.txt` (что проверил, что нашёл/не нашёл).

---

## 9. Автозапуск (необязательно, но желательно) — systemd / OpenWrt procd

**systemd (`/etc/systemd/system/b4.service`):**

```ini
[Unit]
Description=B4 network packet processor
After=network.target
[Service]
ExecStart=/usr/local/bin/b4 --config /etc/b4/b4.json
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now b4
```

**OpenWrt procd (`/etc/init.d/b4`):**

```sh
#!/bin/sh /etc/rc.common
START=99
start() {
  procd_open_instance
  procd_set_param command /usr/local/bin/b4 --config /etc/b4/b4.json
  procd_set_param respawn
  procd_close_instance
}
```

```bash
chmod +x /etc/init.d/b4 && /etc/init.d/b4 enable && /etc/init.d/b4 start
```

---

## 10. Что прислать после прогонов (evidence pack)

Архив (zip) с содержимым:

1. `checklist.md` в со сканами каждый прогон: № прогона | сделано (да/нет) | результат-оценка (соответствует эталону/отличается) | примечание
2. Файлы из разделов 2–7: `run1_*`, `410_*`, `after_reboot_*`, `wan_*`, `fault_*`, `android_*` — JSON/TXT копии ответов curl.
3. `privacy_audit_notes.txt`.
4. `b4 --version` вывод; фрагмент лога с startup-warning (первые 20 строк).
5. Скриншот/фото настройки сети (необязательно).

Ожидаемые «зелёные» критерии (по всему пакету):
- All monitors 200, alias-статус из vocabulary §58, met6н = 0, 410 на все mutating, конфиг не меняется при обрыве, после reboot cutover активен.

---

## Резюме для финального отчёта

После получения пакета этих evidence: обновлю `docs/reports/mon-13-production-readiness.md` (gate → CLAIMED/ISSUED), внесу результат в Beads b4x-070 и закрою MON_PRODUCTION_READY (или оформлю требование-замечание).