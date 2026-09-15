// Package tcp16 — активная проба линии на блокировку по объёму соединения
// (класс «12-69 КБ»; z2k internal/tcp16 lineage, port по MIT с сохранением
// атрибуции — см. NOTICE в targets.go).
//
// Класс блокировки: коробка пропускает рукопожатие и первые килобайты, а
// затем рвёт соединение, набравшее пороговый объём. Пассивный
// классификатор движка (netprobe.DomainTCP16: «Read stalled after TSPU
// fat-flow window (12-69KB)») видит это на трафике пользователя ПОСЛЕ
// факта; эта проба спрашивает про линию ДО и не трогая пользовательский
// трафик: наблюдение отвечает «этот хост сейчас режут?» и ошибается
// (здоровая крупная загрузка выглядит как обрыв), проба отвечает «есть ли
// этот блок на ЭТОЙ линии» на контролируемой мишени и контролируемым
// объёмом.
//
// Процедура (z2k canon): по ОДНОМУ keep-alive соединению десять HEAD-
// запросов, со второго — с мусорным заголовком X-Pad на 4000 байт;
// накопленный объём растёт 4, 8, 12 … 40 КБ. Смерть соединения на чанке,
// где объём перевалил порог, и есть вердикт; смерть раньше порога —
// обычный сетевой сбой, не наш класс. Накачиваем ИСХОДЯЩИМ объёмом, а не
// скачиванием: объём задаём мы сами и не зависим от того, что отдаёт
// мишень.
//
// Числа пробы — из замеров z2k на боевом роутере 31.08.2026; менять
// только вместе с новым замером. Верхняя граница пассивного окна
// классификатора (69 КБ) шире зонда намеренно: пассивная сеть ловит
// медленные коробки, активный зонд измеряет наблюдавшийся разброс
// 12-34 КБ с запасом.
package tcp16

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	// ПАРАМЕТРЫ ПРОБЫ (z2k, замер 31.08.2026).
	ChunkSize  = 4000
	ChunkCount = 10

	// MinDetectKB: ниже этого объёма обрыв нашим классом не считается —
	// до 12 КБ соединения рвутся по десятку обычных причин, и вердикт был
	// бы шумом. Совпадает с TCP16MinBytes пассивного классификатора.
	MinDetectKB = 12

	connectTimeout   = 8 * time.Second
	handshakeTimeout = 8 * time.Second
	chunkDelay       = 50 * time.Millisecond

	// ОЖИДАНИЕ ОТВЕТА СЧИТАЕТСЯ ОТ ИЗМЕРЕННОГО RTT, а не берётся с
	// потолка: живой ответ приходит за один RTT, «нет ответа» — коробка
	// молчит на неподходящем имени. Втрое от RTT с разумными границами
	// (z2k: каждый мимо-кандидат стоил полные 6 с фиксированного потолка).
	readTimeoutMin = 1500 * time.Millisecond
	readTimeoutMax = 12 * time.Second
)

// Target — мишень пробы: адрес, порт и AS, к которой он принадлежит.
type Target struct {
	ID       string
	ASN      string
	Provider string
	IP       string
	Port     int
	// SNI — имя, которое надо предъявить этой мишени (пусто у большинства:
	// туда ходим по адресу; непустое у тех, кто без имени отвечает чужой
	// заглушкой — обрыв по объёму на них не наступает никогда).
	SNI string
}

// Result — исход одной пробы.
type Result struct {
	Target   Target
	SNI      string
	Alive    bool // сервер вообще ответил на первый запрос
	Detected bool // соединение умерло за порогом — это наш класс
	DiedAtKB int  // на каком накопленном объёме умерло
	Err      string
	RTT      time.Duration
}

var padPool = func() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, ChunkSize*2)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}()

// Probe гоняет пробу по одной мишени. sni пустой — идём без SNI (по
// адресу); непустой — подставляем имя в ClientHello (режим подбора).
func Probe(ctx context.Context, t Target, sni string) Result {
	res := Result{Target: t, SNI: sni}

	d := net.Dialer{Timeout: connectTimeout}
	addr := net.JoinHostPort(t.IP, fmt.Sprint(t.Port))
	start := time.Now()
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Err = "no TCP: " + errShort(err)
		return res
	}
	defer raw.Close()

	var conn net.Conn = raw
	if t.Port != 80 {
		// Сертификат не проверяем: идём по адресу, имя подставляем сами —
		// интересует реакция коробки, а не подлинность сервера. Дедлайн
		// обязателен: коробка на неподходящем имени не отвечает вовсе, и
		// рукопожатие висит без ограничения (z2k: перебор вставал
		// намертво на первом же таком имени).
		raw.SetDeadline(time.Now().Add(handshakeTimeout))
		tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err := tc.HandshakeContext(ctx); err != nil {
			res.Err = "no TLS: " + errShort(err)
			return res
		}
		conn = tc
	}
	raw.SetDeadline(time.Time{})
	res.RTT = time.Since(start)

	host := t.IP
	if sni != "" {
		host = sni
	}
	br := bufio.NewReader(conn)

	// Пока RTT не измерен — ждём по потолку; после первого ответа сужаем.
	readTimeout := readTimeoutMax

	for i := 0; i < ChunkCount; i++ {
		var sb strings.Builder
		sb.WriteString("HEAD / HTTP/1.1\r\nHost: ")
		sb.WriteString(host)
		sb.WriteString("\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n")
		if i > 0 {
			// Мусор в заголовке — единственный способ накачать соединение
			// исходящим объёмом, не завися от того, что отдаёт сервер.
			off := rand.Intn(len(padPool) - ChunkSize)
			sb.WriteString("X-Pad: ")
			sb.WriteString(padPool[off : off+ChunkSize])
			sb.WriteString("\r\n")
		}
		sb.WriteString("\r\n")

		sentKB := i * ChunkSize / 1024
		conn.SetDeadline(time.Now().Add(readTimeout))
		reqStart := time.Now()
		if _, err := conn.Write([]byte(sb.String())); err != nil {
			return finish(res, i, sentKB, err)
		}
		if err := drainHead(br); err != nil {
			return finish(res, i, sentKB, err)
		}
		if i == 0 {
			res.Alive = true
			// RTT известен — дальше ждём втрое дольше него, но в границах.
			rtt := time.Since(reqStart)
			readTimeout = rtt * 3
			if readTimeout < readTimeoutMin {
				readTimeout = readTimeoutMin
			}
			if readTimeout > readTimeoutMax {
				readTimeout = readTimeoutMax
			}
		}
		// Пауза между запросами: без неё запросы уходят одной очередью, и
		// коробка видит поток иначе, чем видит его браузер.
		select {
		case <-time.After(chunkDelay):
		case <-ctx.Done():
			return res
		}
	}
	return res
}

// finish превращает обрыв на чанке i в вердикт с учётом порога.
func finish(res Result, i, sentKB int, err error) Result {
	res.Err = errShort(err)
	res.DiedAtKB = sentKB
	if i == 0 {
		// Умерли на первом же запросе — сервер недоступен, а не блок.
		return res
	}
	res.Alive = true
	if sentKB >= MinDetectKB {
		res.Detected = true
	}
	return res
}

// drainHead читает ответ на HEAD: заголовки до пустой строки, тела нет.
func drainHead(br *bufio.Reader) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

func errShort(err error) string {
	if err == nil {
		return ""
	}
	if len(err.Error()) > 120 {
		return err.Error()[:120]
	}
	return err.Error()
}
