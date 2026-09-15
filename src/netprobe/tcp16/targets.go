// Мишени пробы tcp16 — данные z2k (MIT, Copyright (c) 2026 Necronicle),
// перенесены дословно с сохранением атрибуции. Это НЕ список
// заблокированных сетей и не список того, что надо обходить: набор
// контролируемых адресов, на которых проба выясняет одно — есть ли этот
// класс блокировки на этой линии. Отвечать на вопрос «режут ли конкретный
// сайт» по такому списку нельзя: за одной AS живут и зарезанные хосты, и
// совершенно рабочие.
//
// Формат: id<TAB>asn<TAB>подтверждено(*|-)<TAB>провайдер<TAB>ip<TAB>порт
// <TAB>имя_для_SNI(опционально)
package tcp16

import (
	"bufio"
	"bytes"
	_ "embed"
	"strconv"
	"strings"
)

//go:embed targets.tsv
var embeddedTargets []byte

// TargetsFilter сужает встроенный список мишеней.
type TargetsFilter struct {
	// ASN оставляет только эту AS (пусто — все).
	ASN string
	// ConfirmedOnly оставляет AS, подтверждённые многими сообщениями
	// (колонка «*» в исходных данных z2k).
	ConfirmedOnly bool
	// Limit обрезает список до N мишеней (0 — все).
	Limit int
}

// DefaultTargets возвращает встроенные мишени z2k с фильтрами.
func DefaultTargets(f TargetsFilter) []Target {
	return ParseTargets(embeddedTargets, f)
}

// ParseTargets разбирает формат z2k (см. комментарий пакета).
func ParseTargets(data []byte, f TargetsFilter) []Target {
	var out []Target
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) < 6 {
			continue
		}
		if f.ASN != "" && p[1] != f.ASN {
			continue
		}
		if f.ConfirmedOnly && p[2] != "*" {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(p[5]))
		if err != nil {
			continue
		}
		t := Target{ID: p[0], ASN: p[1], Provider: p[3], IP: p[4], Port: port}
		if len(p) >= 7 {
			t.SNI = strings.TrimSpace(p[6])
		}
		out = append(out, t)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}
