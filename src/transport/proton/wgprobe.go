// WG-handshake-пробер для Proton-кандидатов (Nova probeHandshakeRttMs
// lineage). Измеряет RTT полного Noise-IK обмена против узла БЕЗ поднятия
// туннеля: initiation из того же ключа, которым пользуется движок
// (DeriveKeyPair по семени идентичности), аутентифицированный type-2 ответ
// доказывает сразу и живость, и принадлежность ключа, и достижимость
// UDP-пути — всё, чего TCP-коннект не доказывает ничего.
//
// Проба обязана повторять прелюдию движка (Nova-урок: «голое рукопожатие
// как проба было ошибкой — на сети с DPI блокируют именно его, и замер
// отвечал "узел мёртв" там, где реальное подключение с обфускацией
// поднялось бы»): сначала I1 (поддельный QUIC Initial профиля), затем Jc
// мусорных пакетов. Стоковый WireGuard на той стороне лишние датаграммы
// отбрасывает, так что для Proton это безопасно.
//
// Ретраи уходят на ТОМ ЖЕ сокете (RekeyTimeout-семантика движка): первый
// пакет нового потока теряется штатно, повтор идёт по «знакомому» для сети
// потоку. Ответ может прийти не первым — cookie-запрос (тип 3) на любой из
// отправленных пакетов не приговор, узел жив и просто требует mac2.
package proton

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/daniellavrushin/b4/transport/wgprobe"
)

// Probe timing canon (Nova ProtonCrypto).
const (
	// ProbeRetryAfter: пауза перед повтором рукопожатия (RekeyTimeout
	// движка — тот же интервал использует amneziawg-go).
	ProbeRetryAfter = 700 * time.Millisecond
	// ProbeRetryLimit: число повторов на один узел сверх первого.
	ProbeRetryLimit = 3
	// ProbeRTTFloor: сэмпл быстрее миллисекунды рендерится как 0 в
	// ms-потребителях (Nova coerceAtLeast(1)).
	ProbeRTTFloor = time.Millisecond
	// DefaultProbeLocalPorts — число ЛОКАЛЬНЫХ портов, с которых пробуем
	// (Nova PROTON_PREPROBE_ATTEMPTS): узел отвечает данной паре
	// (локальный порт, порт узла) детерминированно, поэтому перебор портов
	// находит живой и даёт порт для закрепления.
	DefaultProbeLocalPorts = 5
	// DefaultProbeAttemptTimeout — бюджет одного локального порта.
	DefaultProbeAttemptTimeout = 1500 * time.Millisecond
	// ProbeAttemptPause — пауза между портами (выше лимита WireGuard на
	// 20 мс между инициациями одного пира, чтобы повтор не дропался).
	ProbeAttemptPause = 50 * time.Millisecond
)

// ProbeHandshakeConfig задаёт форму одной пробы (нулевые поля → дефолт).
type ProbeHandshakeConfig struct {
	// Timeout на весь замер (сокет живёт дольше первого выстрела).
	Timeout time.Duration
	// I1 — hex-цепочка InitPacket[0] ("<b 0x…>") того же формата, что
	// выдаёт BuildQuicInitial; "" = без прелюдии (vanilla-семейство).
	I1 string
	// JunkCount/Min/Max — прелюдия джанка (Jc профиля; 0 = нет).
	JunkCount int
	JunkMin   int
	JunkMax   int
	// Rand — источник случайности (тесты); nil = math/rand.
	Rand *rand.Rand
	// Attempts — число ЛОКАЛЬНЫХ портов, с которых пробуем (0 => 5, Nova
	// PROTON_PREPROBE_ATTEMPTS). Каждый порт = свежий сокет + свежее
	// рукопожатие; ответивший порт закрепляется за узлом.
	Attempts int
	// AttemptTimeout — бюджет одного локального порта (0 => 1500 мс).
	AttemptTimeout time.Duration
	// Stop, when non-nil, ends the probe as soon as it returns true — the
	// yield seam (Nova canon): a check gives the identity key up to a waiting
	// session start so the two never handshake one key at once.
	Stop func() bool
}

func (c ProbeHandshakeConfig) withDefaults() ProbeHandshakeConfig {
	out := c
	if out.Timeout <= 0 {
		out.Timeout = 3 * time.Second
	}
	if out.JunkCount > 32 {
		out.JunkCount = 32
	}
	return out
}

// decodeI1Hex разбирает "<b 0x…>" в байты (Nova decodeAwgBinary): формат
// hex-цифр после маркера, пробелы допустимы. Пустая/битая строка → nil.
func decodeI1Hex(v string) []byte {
	hexStr := v
	// маркеры "<b " и ">" опциональны по краям
	for len(hexStr) > 0 && (hexStr[0] == '<' || hexStr[0] == ' ') {
		hexStr = hexStr[1:]
	}
	for len(hexStr) > 0 && (hexStr[len(hexStr)-1] == '>' || hexStr[len(hexStr)-1] == ' ') {
		hexStr = hexStr[:len(hexStr)-1]
	}
	if len(hexStr) >= 2 && hexStr[0] == 'b' && hexStr[1] == ' ' {
		hexStr = hexStr[2:]
	}
	if len(hexStr) >= 2 && hexStr[0] == '0' && (hexStr[1] == 'x' || hexStr[1] == 'X') {
		hexStr = hexStr[2:]
	}
	// выкидываем внутренние пробелы/переводы строк
	clean := make([]byte, 0, len(hexStr))
	for i := 0; i < len(hexStr); i++ {
		ch := hexStr[i]
		if ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' {
			continue
		}
		clean = append(clean, ch)
	}
	if len(clean) == 0 || len(clean)%2 != 0 {
		return nil
	}
	out, err := hex.DecodeString(string(clean))
	if err != nil {
		return nil
	}
	return out
}

// ProbeHandshakeResult — итог одного замера.
type ProbeHandshakeResult struct {
	// RTT — время от отправки initiation до аутентифицированного ответа
	// (floor 1ms). Ноль, когда ok=false.
	RTT time.Duration
	// OK: получен и аутентифицирован type-2 ответ.
	OK bool
	// CookieSeen: узел ответил cookie-запросом (тип 3) — узел ЖИВ, но
	// под нагрузкой требует mac2; для ранжирования это не успех, но и не
	// «мертвец» (Nova onPacketType).
	CookieSeen bool
	// SourcePort — ЛОКАЛЬНЫЙ UDP-порт, чья инициация получила
	// аутентифицированный ответ (0 когда ok=false). Закрепляется
	// ListenPort'ом туннеля (Nova canon): узел отвечает данной паре
	// (локальный порт, порт узла) детерминированно.
	SourcePort int
	// Attempts — сколько локальных портов перепробовано.
	Attempts int
	// Err: транспортная ошибка замера (не «узел молчит»).
	Err error
}

// ProbeHandshakeRTT выполняет один замер WG-handshake RTT против
// node:port. privateKeyB64 — WG-ключ идентичности (тот же, что движок);
// peerPublicKeyB64 — статический ключ узла из serverlist. cfg.I1/Jc*
// обязаны повторять профиль, которым будет подниматься туннель.
func ProbeHandshakeRTT(ctx context.Context, privateKeyB64, peerPublicKeyB64 string,
	addr *net.UDPAddr, cfg ProbeHandshakeConfig) ProbeHandshakeResult {

	cfg = cfg.withDefaults()
	res := ProbeHandshakeResult{}

	priv, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil || len(priv) != 32 {
		res.Err = fmt.Errorf("proton probe: bad private key")
		return res
	}
	peer, err := base64.StdEncoding.DecodeString(peerPublicKeyB64)
	if err != nil || len(peer) != 32 {
		res.Err = fmt.Errorf("proton probe: bad peer key")
		return res
	}

	attempts := cfg.Attempts
	if attempts <= 0 {
		attempts = DefaultProbeLocalPorts
	}
	perTimeout := cfg.AttemptTimeout
	if perTimeout <= 0 {
		perTimeout = DefaultProbeAttemptTimeout
	}
	// Overall budget across all local ports (rank batches bound the probe).
	allDeadline := time.Time{}
	if cfg.Timeout > 0 {
		allDeadline = time.Now().Add(cfg.Timeout)
	}

	rng := cfg.Rand
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	// Пара (локальный порт, порт узла) отвечает детерминированно (Nova canon):
	// перебираем ЛОКАЛЬНЫЕ порты, каждый — свежий сокет + свежее рукопожатие;
	// порт, чья инициация получила аутентифицированный ответ, закрепляем.
	buf := make([]byte, 2048)
	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			res.Err = ctx.Err()
			return res
		}
		if cfg.Stop != nil && cfg.Stop() {
			return res // yielded the key to a waiting session start
		}
		if !allDeadline.IsZero() && !time.Now().Before(allDeadline) {
			break
		}
		if attempt > 0 {
			time.Sleep(ProbeAttemptPause)
		}
		res.Attempts = attempt + 1

		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			res.Err = fmt.Errorf("proton probe: dial: %w", err)
			return res
		}
		srcPort := 0
		if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			srcPort = la.Port
		}

		// Прелюдия движка: I1, затем Jc джанк-пакетов (профиль-зависимо).
		if i1 := decodeI1Hex(cfg.I1); len(i1) > 0 {
			if _, err := conn.Write(i1); err != nil {
				_ = conn.Close()
				res.Err = fmt.Errorf("proton probe: send i1: %w", err)
				return res
			}
		}
		if cfg.JunkCount > 0 && cfg.JunkMax >= cfg.JunkMin && cfg.JunkMin > 0 {
			for i := 0; i < cfg.JunkCount; i++ {
				size := cfg.JunkMin
				if cfg.JunkMax > cfg.JunkMin {
					size = cfg.JunkMin + rng.Intn(cfg.JunkMax-cfg.JunkMin+1)
				}
				if size < 1 {
					size = 1
				}
				if size > 1280 {
					size = 1280
				}
				junk := make([]byte, size)
				if _, err := rng.Read(junk); err != nil {
					break
				}
				if _, err := conn.Write(junk); err != nil {
					_ = conn.Close()
					res.Err = fmt.Errorf("proton probe: send junk: %w", err)
					return res
				}
			}
		}

		// Свежий initiation: новый ephemeral + sender index + timestamp.
		var ephPriv [32]byte
		if _, err := rng.Read(ephPriv[:]); err != nil {
			_ = conn.Close()
			res.Err = fmt.Errorf("proton probe: eph: %w", err)
			return res
		}
		ephPriv[0] &= 248
		ephPriv[31] &= 127
		ephPriv[31] |= 64
		var senderIdx [4]byte
		if _, err := rng.Read(senderIdx[:]); err != nil {
			_ = conn.Close()
			res.Err = fmt.Errorf("proton probe: index: %w", err)
			return res
		}
		in, err := wgprobe.BuildInitiation([32]byte(priv), [32]byte(peer), ephPriv,
			binary.LittleEndian.Uint32(senderIdx[:]), wgprobe.Tai64n(time.Now()))
		if err != nil {
			_ = conn.Close()
			res.Err = fmt.Errorf("proton probe: build: %w", err)
			return res
		}

		started := time.Now()
		if _, err := conn.Write(in.Packet()); err != nil {
			_ = conn.Close()
			res.Err = fmt.Errorf("proton probe: send: %w", err)
			return res
		}

		deadline := started.Add(perTimeout)
		if !allDeadline.IsZero() && deadline.After(allDeadline) {
			deadline = allDeadline
		}
		cookie := false
		for {
			if ctx.Err() != nil {
				_ = conn.Close()
				res.Err = ctx.Err()
				return res
			}
			if cfg.Stop != nil && cfg.Stop() {
				_ = conn.Close()
				return res // yielded the key to a waiting session start
			}
			if time.Now().After(deadline) {
				break
			}
			if err := conn.SetReadDeadline(deadline); err != nil {
				_ = conn.Close()
				res.Err = err
				return res
			}
			n, rerr := conn.Read(buf)
			if rerr != nil {
				break // таймаут/ошибка сокета — следующий локальный порт
			}
			packet := buf[:n]
			if len(packet) >= 1 && packet[0] == wgprobe.MessageCookieReply {
				cookie = true
				break
			}
			if !in.ResponseLooksLike(packet) {
				continue // чужая датаграмма (эхо прелюдии и т.п.)
			}
			if err := in.ConsumeResponse(packet); err != nil {
				continue // подделка/брак — ждём настоящую
			}
			rtt := time.Since(started)
			if rtt < ProbeRTTFloor {
				rtt = ProbeRTTFloor
			}
			res.RTT = rtt
			res.OK = true
			res.SourcePort = srcPort
			_ = conn.Close()
			return res
		}
		_ = conn.Close()
		if cookie {
			res.CookieSeen = true
			return res
		}
	}
	return res
}
