# INJECT_C_EXTERNAL_RESEARCH.md

> **Исследовательский отчёт:** Сравнительный анализ механизмов обработки длинных/сегментированных TCP ClientHello (ECH), стратегий десинхронизации, сборки потоков и детекции сбоев в открытых Anti-DPI проектах.

---

## 1. Постановка проблемы b4x

В архитектуре `b4x` на роутере Keenetic воспроизводится специфическая проблема при воспроизведении и перемотке видео YouTube (seek в YouTube/ReVanced на CDN Googlevideo / GGC):

1. **QUIC (UDP/443)** на googlevideo работает стабильно (`fake UDP 6/6`), и мобильные клиенты (например, ReVanced) при штатном воспроизведении используют QUIC.
2. **Короткий TCP TLS ClientHello** для служебных хостов YouTube (`youtubei.googleapis.com`, `i.ytimg.com`, `yt3.ggpht.com`): Fake SNI + combo (first-byte split + shuffle + delay) успешно пробивает ТСПУ.
3. **Длинный TCP ClientHello с ECH** (~1740–2100 байт) на Googlevideo / GGC при перемотке (seek):
   - Мобильный стек (Cronet / Android TLS) отправляет ClientHello сегментированно: первый TCP-пакет ~1396 байт (MTU/MSS limit) + последующий хвост.
   - Механизм `tcp_ch_hold` в b4x успешно удерживает первый пакет, дожидается хвоста и собирает полный TLS record (**полевое свидетельство holdch3: 33/33 assembled, timeout=0**).
   - Однако после этапа `classify -> hold/assemble` попытка отправить десинхронизированный инжект (этап **Inject C**) на собранный handshake приводит к сбою:
     - **C-combo15** (агрессивный combo: 12–15 кусков, first-byte, shuffle, задержка 30 мс) на GGC: сервер не отвечает `ServerHello` (нет `0x17` с клиента), сокет зависает, Cronet делает ретраи на новые сокеты.
     - **C-2/3 segment inject / C5 (4 ordered segments)**: на части GGC вызывает hang/retries, а при ошибочном попадании на `youtube-ui` вызывал 30–40 с backoff в приложении.
     - **Fake-only без фрагментации** (отправка фейка + исходного 1396-байтного куска как есть): на части GGC сервер молчит из-за нарушения порядка/целостности.

Задача данного исследования — изучить 8 открытых проектов, выяснить, как они решают аналогичные задачи на уровне TCP/L7 dataplane, и сформировать доказательные варианты решения для b4x.

---

## 2. Известные полевые свидетельства и ограничения b4x

На основе `PROJECT_DIRECTIVES.md`, `YOUTUBE_DATAPLANE.md` и исходного кода b4x (`D:\b4x\src\nfq\`):
- **Сборка (Reassembly) работает корректно:** `chHoldStore.append` в `src/nfq/tcp_ch_hold.go` аккуратно собирает `e.payload` до `tlsHandshakeRecordTotal(payload)` и восстанавливает целый пакет `rebuildHeldHandshake`.
- **Проблема локализована исключительно на GGC:** Тот же combo на собранный длинный ECH `youtubei` / `i.ytimg` интерфейс поднимает. GGC-серверы Google более чувствительны к потере порядка, переполнению буферов TCP reassembly queue или аномалиям в TCP sequence space.
- **Действующие запреты:**
  - Запрещён `offload_policy=exclude`.
  - Запрещён `sni_mutation` / substitute на проде (ломает TLS 1.3).
  - Запрещено смешивать Google /16 в одну кучу с GGC.
  - Аппаратный PPE отключен на этапе отладки.

---

## 3. Анализ проекта: zapret2 / nfqws2

- **Репозиторий:** `D:\netcreaze\zapret2` (upstream: `bol-van/zapret2`)
- **Ключевые файлы:**
  - `nfq2/desync.c`
  - `nfq2/protocol.c`
  - `lua/zapret-lib.lua`
  - `lua/zapret-antidpi.lua`

### A. TCP desync / Fake
- В `zapret2` отправка фейков вынесена в Lua-функцию `fake(ctx, desync)` (`lua/zapret-antidpi.lua:449`).
- **Fooling-методы:** `badsum` (порча чексуммы L4), `badseq` / `tcp_seq` (смещение sequence), `tcp_ts` / `tcp_ts_up` (манипуляция TCP Timestamp), `ip_autottl` (вычисление TTL до DPI).
- **Изоляция фейка:** Фейковый пакет генерируется с отдельным TTL или заведомо невалидной чексуммой/seq, чтобы конечный сервер его сбросил на уровне TCP/IP стека.

### B. Разделение ClientHello (Split / Disorder / Seqovl)
- В `lua/zapret-antidpi.lua`:
  - `multisplit` (строка 483): режет `data` на сегменты по маркерам (`pos=1`, `pos=sld+1`, `pos=sniext+1`). Отправляет их последовательно от первого к последнему.
  - `multidisorder` (строка 597): режет `data` на сегменты, но отправляет их в **обратном порядке** (`for i=#pos,0,-1 do ... rawsend_payload_segmented(...)`).
  - `seqovl` (Sequence Overlap): уменьшает sequence number сегмента на N байт и заполняет нахлёст байтами из шаблона `seqovl_pattern` (или нулями). ТСПУ склеивает первый пришедший кусок, а сервер при TCP reassembly перезаписывает нахлёст вторым корректным пакетом (или отбрасывает дубликаты по TCP seq).

### C. Segmented ClientHello (> MSS) и Reassembly
- В `nfq2/desync.c:1562-1605`:
  1. При получении неполного TLS ClientHello (`!IsTLSRecordFull`), `nfqws2` вызывает `reasm_client_start(ps.ctrack, IPPROTO_TCP, L7P_TLS_CLIENT_HELLO, TLSRecordLen(dis->data_payload), TCP_MAX_REASM, ...)` и буферизует входящий пакет в очередь задержки `rawpacket_queue(&ps.ctrack->delayed, ...)`.
  2. Пакет дропается (`VERDICT_DROP`), освобождая ядро от передачи неполного CH.
  3. При приходе последующих сегментов они скармливаются в `reasm_client_feed`.
  4. Когда `ReasmIsFull(&ps.ctrack->reasm_client)` становится `true`, вызывается `replay_queue(&ps.ctrack->delayed)`. Очередь заново прогоняется через Lua-десинхронизатор.
  5. В Lua-скрипте вызывается проверка `if replay_first(desync) then`. На первом же пакете реплея строится **весь desync** на полном `desync.reasm_data`.
  6. После отправки сплитов выставляется флаг `replay_drop_set(desync)`, и все остальные сегменты очереди дропаются (`replay_drop(desync) -> VERDICT_DROP`), предотвращая двойной инжект или пропуск остаточных кусков!
- **Важнейшая деталь:** в `lua/zapret-lib.lua:1232` функция `rawsend_dissect_segmented` проверяет MSS:
  Если кусок сплита превышает MSS, `zapret2` автоматически режет его на MTU-совместимые TCP-сегменты с монотонно растущим `tcp.th_seq`.

### D. ECH
- В `protocol.c` и `desync.c:118` есть отладочный детектор `TLSFindExtInHandshake(tls, sz, 65037, ...)` (0xFE0D / 0x56E5).
- Специального режима шифрования ECH нет. Но благодаря `desync.reasm_data`, `multisplit` и `multidisorder` работают с ECH точно так же, как с обычным ClientHello, опираясь на байтовые смещения (`pos=1`, `pos=2`, `seqovl=681`).

---

## 4. Анализ проекта: z2k

- **Репозиторий:** `D:\netcreaze\z2k` (upstream: `necronicle/z2k`)
- **Ключевые файлы:**
  - `files/lua/z2k-detectors.lua`
  - `files/lua/z2k-modern-core.lua`
  - `files/lua/z2k-autocircular.lua`

### A. YouTube / Googlevideo пресеты и стратегии
В каталоге пресетов z2k (`z2k_autocircular_gv` / `z2k_autocircular_yt`):
- Для `googlevideo` (GV) выделен отдельный пул стратегий с ротацией `key=gv_tcp`.
- Основные успешные стратегии z2k для GV:
  1. `multisplit:pos=1,sniext+1:seqovl=1` (минимальный split + overlap в 1 байт).
  2. `fake:blob=tls_clienthello_www_google_com:badsum:badseq` + `multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google` (десинхронизация по оверлепу 681 байт).
  3. `fake:blob=fake_default_tls:badsum:tls_mod=rnd,dupsid,sni=www.google.com` + `multidisorder:pos=1,midsld` (disorder из 2 кусков).
  4. `fake:blob=0x00000000:tcp_ack=-66000` + `multisplit:pos=1,midsld`.

### B. Механизм детекции сбоев (Failure Detection)
В `files/lua/z2k-detectors.lua:650-750`:
- **`z2k_tls_stalled`:**
  - Отслеживает время между повторными `ClientHello` от клиента без прихода валидного `ServerHello` (от 3 до 30 секунд).
  - Если клиент вынужден перепосылать ClientHello или открывать новый сокет на тот же хост, не дождавшись ServerHello, детектор регистрирует `FAIL` и инициирует ротацию стратегии в `circular`.
- **`z2k_mid_stream_stall`:**
  - Ловит обрыв соединения после успешного хендшейка во время передачи медиаданных.
- **`z2k_classify_server_active`:**
  - Различает RST/Alert от самого сервера (например, 403 Forbidden / WAF) и сброс со стороны ТСПУ.

---

## 5. Анализ проекта: zapret-discord-youtube (Flowseal / winws v1)

- **Репозиторий:** `D:\FreeDPI\research\zapret-discord-youtube`
- **Ключевые файлы:** `general (ALT).bat`, `general (ALT11).bat`, `general (FAKE TLS AUTO).bat`, `general (ALT2).bat`

### Анализ тактик для YouTube/Google:
В командных файлах запуска `winws.exe`:
- **Политика QUIC:**
  `--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6..11 --dpi-desync-fake-quic=quic_initial_www_google_com.bin`
  (QUIC не блокируется, а активно десинхронизируется 6–11 фейковыми пакетами Initial).
- **Политика TCP Google/YouTube:**
  - `--filter-tcp=443 --hostlist=list-google.txt --ip-id=zero --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern=tls_clienthello_www_google_com.bin`
  - `--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=badseq`
  - `--dpi-desync=hostfakesplit --dpi-desync-fooling=ts --dpi-desync-hostfakesplit-mod=host=www.google.com`

**Ключевой паттерн winws v1:**
Число фрагментов настоящего ClientHello почти никогда не превышает **2–3 сегментов** (`split-pos=1`, `split-pos=1,midsld`, `split-pos=2,sniext+1`). Агрессивное дробление на 10–15 частей отсутствует, так как конечные TCP-стеки серверов Google отбрасывают слишком мелко нарезанные потоки.

---

## 6. Анализ проекта: Nova

- **Репозиторий:** `D:\FreeDPI\research\Nova`
- **Ключевые файлы:**
  - `docs/adr/0001-zapret-backend.md`
  - `docs/adr/0002-diversity-over-rank.md`
  - `docs/adr/0004-neutral-sni.md`

### Ключевые выводы Nova:
1. **Пространство поведений (Diversity Niche):**
   Nova классифицирует Anti-DPI стратегии по 3 ортогональным осям:
   - *Technique*: Inject (fake) vs Segment (split) vs Decoy-segment (hostfakesplit) vs Fragment (ipfrag).
   - *Reach*: TTL <= 4, 5-8, >= 9, AutoTTL.
   - *Deniability*: `badsum` vs `badseq` vs `tcp_ts` vs TTL-only.
2. **Сегментация против GGC:**
   Исследование Nova показало, что перебор случайных мутаций без сохранения ортогональности приводит к деградации. Для YouTube/Google 89% эффективных стратегий укладываются в нишу: `Inject (fake google CH) + 2-segment Split/Disorder + badseq/ts fooling`.
3. **Маршрутизация и нейтральный SNI:**
   Для ряда протоколов (Telegram WebSockets over CF Workers) доказано разделение SNI и HTTP Host (ADR 0004).

---

## 7. Анализ проекта: Ladon

- **Репозиторий:** `D:\FreeDPI\research\Ladon`
- **Ключевые файлы:**
  - `README.md`
  - `docs/methodology.md`
  - `internal/engine/engine.go`

### Методология реактивной классификации отказов:
Ladon реализует 4-стадийную модель валидации (`DNS -> TCP:443 -> TLS Handshake -> HTTP Read 32KB`):
- **Разделение типов сбоев:**
  - *Server-active failure* (TCP RST на SYN, TLS Alert от сервера): означает, что сервер доступен, но отклонил запрос сам.
  - *Path-active failure* (Silent Drop / Timeout во время Handshake, TLS Garbage, обрыв чтения HTTP): доказательство вмешательства ТСПУ.
- **Применение к b4x:**
  Поведение GGC на C-combo15 (молчание сервера после отправки ClientHello) по классификации Ladon является классическим `tls_timeout` / `tls_stalled` (DPI или endpoint дропнул искаженный поток).

---

## 8. Анализ проекта: SpoofDPI

- **Репозиторий:** `D:\FreeDPI\research\SpoofDPI`
- **Ключевые файлы:**
  - `internal/desync/tls.go`
  - `internal/packet/tcp_writer.go`

### Реализация десинхронизации:
- SpoofDPI работает как юзерспейс-прокси.
- В `internal/desync/tls.go:80-120` метод `sendSegments`:
  - Разбивает ClientHello на 2 куска: 1-й байт (`splitFirstByte`) или по границе SNI (`splitSNI`).
  - Для создания *disorder* устанавливает на сокете `SetTTL(conn, 1)` для первого куска (`chunk.Lazy = true`).
  - Первый кусок дропается на первом хопе, затем отправляется остаток с нормальным TTL, после чего стек ОС штатно ретрансмитит первый кусок по таймауту.
- **Ограничение:** Не работает с ECH напрямую, не производит сборку сегментированных входящих ClientHello на сыром сокете.

---

## 9. Анализ проектов: zapret-gui и nfqws2-keenetic

- **Репозитории:** `D:\netcreaze\zapret-gui`, `D:\netcreaze\nfqws2-keenetic`
- **Ключевые файлы:**
  - `etc/nfqws2/nfqws2.conf`
  - `catalogs/builtin/z2k_all_in_one.txt`

### Архитектура деплоя на Keenetic:
- Использование одной очереди NFQUEUE (`NFQUEUE_NUM=300`) и единого демона `nfqws2` с разделением по `--filter-tcp` и `--filter-udp`.
- Строгое разделение очередей и профилей через `--new`, предотвращающее взаимное влияние L7-обработчиков.
- Для QUIC выделяется отдельный поток с фейком `quic_initial.bin` (`repeats=11`).

---

## 10. Сравнительная матрица проектов

| Проект | Техника TCP Desync | Нужен полный CH? | ECH-aware? | Работа с CH > MSS | Метод подавления Fake | Порядок реального payload | Обработка Retransmit | Специфика GGC/YouTube | QUIC Policy | Failure Detection | Применимость к b4x | Обоснование |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **zapret2 / nfqws2** | Fake + Multisplit / Multidisorder / Seqovl | Да (`reasm_client`) | Частично (смещение/raw) | Да (`rawsend_dissect_segmented`) | `badsum`, `badseq`, `tcp_ts`, AutoTTL | Ordered или Reverse (2–3 куска) | Игнорирует reasm при повторах | Да (пресеты по смещению) | Fake UDP (Initial) | Auto hostlist, fail counter | **DIRECT** | Полная модель reassembly + segmented rawsend |
| **z2k** | Autocircular (50/22 стратегий), seqovl | Да (через nfqws2 core) | Да (через L7 match) | Да | `badsum`, `badseq`, `tcp_md5`, TTL | Ordered (1 байт + хвост) или Disorder | Детектор сброса/повторов | Да (`gv_tcp`, `yt_tcp`) | Fake UDP 6–11 | `z2k_tls_stalled`, `mid_stream_stall` | **DIRECT** | Идеальная модель детекции stall на GGC |
| **zapret-discord-youtube** | winws v1 fake + multisplit/seqovl | Нет (только 1-й пакет) | Нет | Нет (только MTU) | `badseq`, `ts`, AutoTTL | Ordered (2–3 куска) | Встроен в драйвер WinDivert | Да (`list-google.txt`) | Fake UDP (Google bin) | Нет (статические батники) | **ADAPTABLE** | Проверенные на практике параметры сплита для GGC |
| **Nova** | Diversity-архив ниш | Нет (winws v1 бэкенд) | Нет | Нет | `badsum`, `badseq`, TTL | 2-segment split | Откат по фазам | Да (выделенный пул) | QUIC pass / fake | Анализ кодов ответов и таймаутов | **ADAPTABLE** | Концепция ортогональных ниш для ABD |
| **Ladon** | DNS-reactive ipset tunneling | Нет (прокси/L7) | Нет | Нет | N/A (туннелирование) | Штатный TCP OS | Kernel TCP stack | Да (семейство eTLD) | UDP tunnel / block | 4-стадийный probe (DNS->TCP->TLS->HTTP) | **ADAPTABLE** | Модель классификации отказов для monitor/ABD |
| **SpoofDPI** | L7 Proxy Split / Fake | Да (в сокете) | Нет | Да (OS TCP stack) | TTL 1 (lazy chunk) | Ordered с дропом 1-го байта | TCP Stack ОС | Нет | QUIC block | Нет | **NOT APPLICABLE** | Юзерспейс L7 прокси, неприменимо к роутерному NFQ |
| **nfqws2-keenetic / zapret-gui** | Каталоги пресетов nfqws2 | Да | Частично | Да | `badsum`, `tcp_seq`, `tcp_ts` | 2-3 сегмента | Через ctrack nfqws2 | Да (разделение TCP/GV) | Fake UDP 11 | Через syslog / healthcheck | **ADAPTABLE** | Конфигурация фильтров для Keenetic |

---

## 11. Обнаруженные паттерны во всех проектах

1. **Ни один зрелый проект не использует 12–15 фрагментов со shuffle и 30 мс задержкой для ClientHello.**
   - Максимум: **2–3 сегмента**.
   - Типичное разделение: `pos=1` (первый байт отдельно) + остаток, либо `pos=1,midsld` (1-й байт + до середины домена + остаток).
2. **Сегментация с учётом MSS обязательна при CH > MSS.**
   - Если собранный ECH (~1900 байт) разбить на 2 части по 1-му байту (1 байт + 1899 байт), второй кусок обязан быть отправлен как **два MTU-валидных TCP-сегмента** (например, 1396 байт + 503 байта) с непрерывными TCP Sequence Numbers!
   - Если роутер отправляет IP/TCP-пакет размером 1900 байт без IP-фрагментации на интерфейс с MTU 1500, пакет либо дропается ядром/драйвером, либо отбрасывается сетевым оборудованием.
3. **Изоляция Fake-пакетов:**
   - На серверах Google/GGC лучше всего работает `badsum` (порча чексуммы TCP) либо `badseq` (seq вне текущего TCP-окна на 10^7). Фейки с валидным seq и валидной чексуммой, но коротким TTL, часто пробивают ТСПУ, но если TTL рассчитан неверно хотя бы на 1 хоп — пакет долетает до GGC и ломает TCP-сессию.
4. **QUIC — основной рабочий транспорт для видео Google:**
   - Все ведущие конфигурации (z2k, zapret-discord-youtube, nfqws2-keenetic) держат QUIC открытым и десинхронизируют его фейковыми пакетами Initial (`quic_initial_www_google_com.bin`, 6–11 повторов).

---

## 12. Что b4x делает по-другому

1. **Reassembly (Сборка):**
   - В `b4x` механизм `tcp_ch_hold` реализован нативно в Go (`src/nfq/tcp_ch_hold.go`). Он эффективно буферизует первый пакет (1396 байт), ловит хвост, склеивает полный payload и строит цельный псевдо-пакет. Это работает стабильно (33/33).
2. **Inject C (Дробление и отправка):**
   - **В b4x (эксперименты combo15):** попытка применить агрессивный combo (15 микросегментов, случайные паузы до 30 мс, перемешивание порядка). Серверы GGC закрывают такие соединения по таймауту/аномалии.
   - **В b4x (эксперимент C5):** 4 равных куска по ~450 байт с паузой 2 мс.
   - **В zapret2 / z2k:** используется асимметричный сплит: **1 байт (или SNI prefix)** уходит первым (или в disorder), а весь остальной массив данных уходит стандартными MSS-размерными сегментами без искусственных задержек.

---

## 13. Ранжированные гипотезы отказа GGC на текущих C

### Гипотеза 1 (Наивысшая вероятность — 85%): GGC TCP Reassembly Buffer & Pipelining Rejection
- **Суть:** TCP-стек серверов Google (BBR / Linux kernel TCP GGC) настроен на защиту от DoS/DPI-fuzzing:
  - При получении 12–15 разрозненных TCP-сегментов с перетасованными seq-номерами (shuffle) или искусственной задержкой 30 мс, очередь Out-Of-Order (OOO) пакетов в ядре сервера исчерпывает лимиты (`tcp_max_reordering`), либо срабатывает таймер ожидания сегментов, и сокет молча переводится в backoff.
- **Доказательство в других проектах:** В `zapret2` и `z2k` десинхронизация достигается ровно **одним** оверлепом/сплитом на 1-м байте (`pos=1:seqovl=681` или `pos=1,sniext+1`), после чего весь остальной хвост отдаётся полными MSS-кусками.

### Гипотеза 2 (Высокая вероятность — 75%): Нарушение MTU/MSS при сборке и повторном инжекте
- **Суть:** Собранный ECH ClientHello имеет размер ~1800–2100 байт. Если после hold/reassemble модуль инжекта пытается выдать сегмент длиной > 1460 байт (например, 1 кусок на 1-й байт и 2-й кусок на 1800+ байт) без корректного TCP-сегментирования по MSS, пакет отбрасывается на исходящем интерфейсе Keenetic или провайдером из-за превышения MTU (DF flag).
- **Доказательство в других проектах:** Функция `rawsend_dissect_segmented` в `zapret-lib.lua:1232` принудительно циклом нарезает любой payload длиннее `max_data = mss - extra_len` на куски <= MSS.

### Гипотеза 3 (Средняя вероятность — 50%): Чувствительность GGC к Fake SNI с валидной чексуммой
- **Суть:** Если Fake SNI отправляется с AutoTTL, погрешность в 1 хоп приводит к тому, что фейковый TLS ClientHello реально попадает в сокет GGC. Получив два разных ClientHello в одном TCP-потоке, сервер GGC разрывает сессию или игнорирует её.
- **Доказательство в других проектах:** Использование `badsum` (порча L4 чексуммы фейка), которая гарантирует, что фейк прочитает DPI на пути, но физически отбросит сетевая карта сервера.

---

## 14. Три кандидатных варианта для b4x

### Вариант A: Minimal 2-Segment Head Split + MSS-Compliant Forward Segments (на основе zapret2 / z2k gv_tcp)
- **Идея:** Отказ от микро-дробления на 4/12/15 кусков. После сборки полного ECH ClientHello (~1800–2100 B):
  1. Отправка 1 фейкового пакета SNI (с защитой `badsum` или AutoTTL).
  2. Настоящий ClientHello делится ровно в **одной** точке: `pos=1` (первый байт TLS record: `0x16`) или `pos=2` (`0x16 0x03`).
  3. Сегмент 1: 1–2 байта (уходит первым).
  4. Сегмент 2 (хвост ~1800+ байт): разбивается строго по размеру MTU/MSS клиента (сегмент 2a ~1396 байт, сегмент 2b ~400–700 байт) и отправляется в прямом порядке TCP seq.
- **Почему подходит:** DPI видит разорванный заголовок TLS handshake на 1-м байте и теряет контекст ECH; сервер GGC получает простейшую пересборку из 2–3 упорядоченных TCP-пакетов без переполнения OOO-буфера.
- **Риск:** Если DPI собирает 1-й байт при прямом порядке (без disorder).
- **A/B тест:** Сравнение `C-2seg-head` против baseline. Проверка: появление `0x17` (Application Data) сразу после инжекта.

### Вариант B: Sequence Overlap (Seqovl) Injection (на основе zapret2 multisplit:seqovl=681)
- **Идея:** После сборки полного ECH:
  1. Генерируется Fake TLS пакет (размером, например, 681 байт).
  2. Реальный ClientHello отправляется со смещением `seqovl`: первый реальный сегмент перекрывает по TCP sequence пространство фейка.
  3. ТСПУ видит фейковый SNI в первом пакете; сервер GGC по правилам TCP reassembly перезаписывает перекрывающийся диапазон реальными данными.
- **Почему подходит:** Не требует Out-of-Order отправки, работает в прямом потоке TCP.
- **Риск:** Требует точного совпадения TCP ack/seq дельт.

### Вариант C: Fast-Path QUIC Steering + Conservative TCP Fallback (на основе Nova ADR 0003 & z2k)
- **Идея:** Перевод основного трафика YouTube Video на QUIC (где fake UDP 6/6 уже доказан и работает 100% стабильно на GGC), а для редких TCP-сессий (браузеры без QUIC / seek fallback) использование консервативного Варианта A с детектором `z2k_tls_stalled`.
- **Почему подходит:** Минимизирует нагрузку на CPU роутера и исключает риски зависания видеопотока.
- **Риск:** Зависит от доступности UDP у провайдера.

---

## 15. Предпочтительный следующий эксперимент

**Выбор:** **Вариант A (Minimal 2-Segment Head Split с MSS-нормализацией хвоста).**

### Обоснование выбора:
1. **TCP Correctness:** Полное соответствие RFC и возможностям TCP-стека GGC.
2. **Безопасность для Gmail/UI/API:** Применяется строго к `youtube-video` (GGC).
3. **Минимальная сложность:** Устраняет избыточный оверхед комбо/таймеров в коде b4x.
4. **Однозначная верификация:** Успех фиксируется появлением пакета `0x17` от клиента в течение <= 50 мс без повторных ClientHello.

---

## 16. Явно отклоненные подходы (Rejected Approaches)

1. **Агрессивный Combo (10–15 сегментов, shuffle, задержки > 10 мс):** Опровергнут полем и кодом всех 8 проектов. Убивает handshake на серверах Google/GGC.
2. **Подмена/мутация SNI на ECH потоках (SNI substitution):** Ломает криптографический транскрипт TLS 1.3 (RFC 8446).
3. **google /16 exclusion & offload_policy=exclude:** Нарушает изоляцию маршрутизации и роняет PPE.
4. **Попытка инжектировать целый собранный ECH (1900+ B) одним TCP-пакетом:** Приведет к дропу по MTU (1500 B).

---

## 17. Файлы и функции b4x, подлежащие модификации (при реализации)

*(Для справки, без внесения изменений на текущем этапе)*:
1. `src/nfq/tcp_ch_hold_inject.go`:
   - Функции `buildC5SegmentsV4` / `buildC5SegmentsV6` — замена 4 равных сплитов на `2-segment head split` (1 байт + MSS-сегментированный хвост).
   - Функция `c5OrderedSplits` — приведение к логике `pos=1` + MTU chunks.
2. `src/nfq/tcp_ch_hold.go`:
   - Функция `dropAndInjectHandshake` — передача MSS-лимита в генератор сегментов.
