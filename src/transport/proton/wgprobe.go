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

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		res.Err = fmt.Errorf("proton probe: dial: %w", err)
		return res
	}
	defer conn.Close()

	// ctx-гашение сокета: замер умирает вместе с вызывающим контекстом.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	rng := cfg.Rand
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	// Прелюдия движка: I1, затем Jc джанк-пакетов (профиль-зависимо).
	if i1 := decodeI1Hex(cfg.I1); len(i1) > 0 {
		if _, err := conn.Write(i1); err != nil {
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
				res.Err = fmt.Errorf("proton probe: send junk: %w", err)
				return res
			}
		}
	}

	// Сам initiation: свежий ephemereral + случайный sender index.
	var ephPriv [32]byte
	if _, err := rng.Read(ephPriv[:]); err != nil {
		res.Err = fmt.Errorf("proton probe: eph: %w", err)
		return res
	}
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64
	var senderIdx [4]byte
	if _, err := rng.Read(senderIdx[:]); err != nil {
		res.Err = fmt.Errorf("proton probe: index: %w", err)
		return res
	}
	in, err := wgprobe.BuildInitiation([32]byte(priv), [32]byte(peer), ephPriv,
		binary.LittleEndian.Uint32(senderIdx[:]), wgprobe.Tai64n(time.Now()))
	if err != nil {
		res.Err = fmt.Errorf("proton probe: build: %w", err)
		return res
	}

	started := time.Now()
	if _, err := conn.Write(in.Packet()); err != nil {
		res.Err = fmt.Errorf("proton probe: send: %w", err)
		return res
	}

	// Цикл чтения с ретраями на том же сокете (двигатель RekeyTimeout).
	deadline := started.Add(cfg.Timeout)
	retryAfter := ProbeRetryAfter
	if retryAfter > cfg.Timeout {
		retryAfter = cfg.Timeout
	}
	retriesLeft := ProbeRetryLimit
	if err := conn.SetReadDeadline(time.Now().Add(retryAfter)); err != nil {
		res.Err = err
		return res
	}

	buf := make([]byte, 2048)
	for {
		n, rerr := conn.Read(buf)
		if rerr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				res.Err = ctxErr
				return res
			}
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				if time.Now().After(deadline) {
					return res // тишина: не ошибка — узел молчит
				}
				if retriesLeft > 0 {
					retriesLeft--
					if _, err := conn.Write(in.Packet()); err != nil {
						if ctxErr := ctx.Err(); ctxErr != nil {
							res.Err = ctxErr
							return res
						}
						res.Err = fmt.Errorf("proton probe: retry send: %w", err)
						return res
					}
					if err := conn.SetReadDeadline(time.Now().Add(retryAfter)); err != nil {
						res.Err = err
						return res
					}
				} else {
					return res // ретраи исчерпаны
				}
				continue
			}
			res.Err = rerr
			return res
		}
		packet := buf[:n]
		if len(packet) >= 1 && packet[0] == wgprobe.MessageCookieReply {
			res.CookieSeen = true // узел жив, требует mac2 — не успех
			continue
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
		return res
	}
}
