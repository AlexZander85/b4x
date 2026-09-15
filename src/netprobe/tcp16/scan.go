// Скан линии: два режима, и это принципиально разные вопросы (z2k canon):
//
//	ProbeLine   есть ли этот блок на линии (и в каких AS);
//	ScanPerASN  какое имя из белого списка провайдер пропускает — СВОЁ
//	            для каждой сети с блоком (замер z2k 30.08.2026: одного
//	            имени на всех не бывает — hcaptcha.com бьёт двадцать AS,
//	            но НЕ Hetzner; Hetzner, DigitalOcean и OVH берёт 300.ya.ru;
//	            Melbicom — ad.adriver.ru; семь AS не берёт ничего).
//
// Оба идут по КУРИРУЕМЫМ мишеням, а не по трафику человека.
package tcp16

import (
	"context"
	"sort"
	"sync"
	"time"
)

// ProbeLineOptions задаёт прогон пробы линии.
type ProbeLineOptions struct {
	// SNI подставляется всем мишеням (обычно пусто — идём по адресу).
	SNI string
	// Parallel ограничивает одновременные пробы (замер z2k на роутере:
	// 110 мишеней при потолке 4 — 2 м 44 с, при 50 — 15 секунд).
	Parallel int
	// PerProbeTimeout — потолок на одну пробу.
	PerProbeTimeout time.Duration
}

// ASAgg — агрегат по одной AS.
type ASAgg struct {
	ASN      string
	Total    int
	Alive    int
	Detected int
}

// LineVerdict — итог пробы линии.
type LineVerdict struct {
	PerAS    []ASAgg // сортировано по ASN
	AnyAlive int
	AnyDet   int
	// DetectedASN — только AS, где блок найден: рантайм ставит имя из
	// белого списка только адресам этих сетей (замер z2k 30.08.2026: без
	// этого фильтра linode, cdn77, aws и scaleway доезжают целиком и без
	// имени — платят за него зря).
	DetectedASN []string
}

// Verdict рисует человеческий итог.
func (v LineVerdict) Verdict() string {
	switch {
	case v.AnyAlive == 0:
		return "мишени не отвечают вовсе — линия или список мишеней негодны, судить не по чему"
	case v.AnyDet > 0:
		return "блок по объёму ЕСТЬ"
	default:
		return "блока по объёму НЕТ"
	}
}

// ProbeLine прогоняет пробу по всем мишеням и агрегирует по AS.
func ProbeLine(ctx context.Context, targets []Target, opts ProbeLineOptions) LineVerdict {
	par := opts.Parallel
	if par < 1 {
		par = 4
	}
	timeout := opts.PerProbeTimeout
	if timeout <= 0 {
		timeout = 40 * time.Second
	}
	results := make([]Result, len(targets))
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			results[i] = Probe(c, t, opts.SNI)
		}(i, t)
	}
	wg.Wait()

	byASN := map[string]*ASAgg{}
	for _, r := range results {
		a := byASN[r.Target.ASN]
		if a == nil {
			a = &ASAgg{ASN: r.Target.ASN}
			byASN[r.Target.ASN] = a
		}
		a.Total++
		if r.Alive {
			a.Alive++
		}
		if r.Detected {
			a.Detected++
		}
	}
	keys := make([]string, 0, len(byASN))
	for k := range byASN {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := LineVerdict{}
	for _, k := range keys {
		a := byASN[k]
		out.PerAS = append(out.PerAS, *a)
		out.AnyAlive += a.Alive
		out.AnyDet += a.Detected
		if a.Detected > 0 {
			out.DetectedASN = append(out.DetectedASN, k)
		}
	}
	return out
}

// ScanPerASNOptions задаёт per-AS подбор имени.
type ScanPerASNOptions struct {
	// Names — кандидаты в ПОРЯДКЕ ПРИОРИТЕТА (порядок осмысленный:
	// побеждает первое подошедшее ИМЯ ПО ПОРЯДКУ, а не «кто быстрее
	// ответил» — иначе порядок ломался бы от гонок таймингов).
	Names []string
	// Parallel — общий потолок одновременных проб на весь прогон
	// (ограничивать только число сетей мало: внутри каждой идёт ещё батч,
	// и суммарная нагрузка получается непредсказуемой — z2k замер).
	Parallel int
	// Batch — сколько имён проверять разом внутри одной сети.
	Batch int
}

// ASNName — найденное имя для одной сети.
type ASNName struct {
	ASN     string
	Name    string // пусто — не нашлось
	Tried   int    // сколько кандидатов перебрано
	Blocked bool   // был ли блок вообще (нет блока — имя не нужно)
}

// ScanPerASN ищет СВОЁ имя для КАЖДОЙ сети, где нашёлся блок.
// Мишени порта 80 в подборе не участвуют: там нет TLS, имя подставлять
// некуда, и требовать от них «пройти» — значит не найти имя никогда.
func ScanPerASN(ctx context.Context, targets []Target, opts ScanPerASNOptions) []ASNName {
	par := opts.Parallel
	if par < 1 {
		par = 4
	}
	batch := opts.Batch
	if batch < 1 {
		batch = 5
	}

	byASN := map[string][]Target{}
	for _, t := range targets {
		if t.Port != 443 {
			continue
		}
		byASN[t.ASN] = append(byASN[t.ASN], t)
	}
	keys := make([]string, 0, len(byASN))
	for k := range byASN {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	gate := make(chan struct{}, par)
	probe := func(t Target, sni string) Result {
		gate <- struct{}{}
		defer func() { <-gate }()
		c, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		return Probe(c, t, sni)
	}

	results := make([]ASNName, len(keys))
	var wg sync.WaitGroup
	for i, asn := range keys {
		wg.Add(1)
		go func(i int, asn string, tgs []Target) {
			defer wg.Done()
			// Мишень выбираем ту, на которой блок реально виден, а из
			// нескольких таких — с наименьшим RTT: перебор идёт по ней
			// десятки раз, лишние сто миллисекунд на пробу выливаются в
			// минуты. Имя мишени, если оно у неё есть, предъявляем (z2k:
			// раньше стояла пустая строка для ВСЕХ — и мишени, отвечающие
			// только по имени, молча выпадали из замера).
			var target *Target
			var bestRTT time.Duration
			for j := range tgs {
				r := probe(tgs[j], tgs[j].SNI)
				if r.Alive && r.Detected && (target == nil || r.RTT < bestRTT) {
					t := tgs[j]
					target = &t
					bestRTT = r.RTT
				}
			}
			if target == nil {
				results[i] = ASNName{ASN: asn}
				return
			}
			results[i].ASN = asn
			results[i].Blocked = true

			// Кандидаты идём БАТЧАМИ: по одному это сотни кандидатов ×
			// шесть секунд на сеть, где не подходит ничто. Батч
			// запускается целиком, из подошедших берём ПЕРВОГО ПО ПОРЯДКУ.
			for start := 0; start < len(opts.Names); start += batch {
				select {
				case <-ctx.Done():
					return
				default:
				}
				end := start + batch
				if end > len(opts.Names) {
					end = len(opts.Names)
				}
				namesBatch := opts.Names[start:end]
				okIdx := make([]bool, len(namesBatch))
				var bwg sync.WaitGroup
				for j, name := range namesBatch {
					bwg.Add(1)
					go func(j int, name string) {
						defer bwg.Done()
						r := probe(*target, name)
						okIdx[j] = r.Alive && !r.Detected
					}(j, name)
				}
				bwg.Wait()
				for j := range okIdx {
					if okIdx[j] {
						results[i].Name = namesBatch[j]
						results[i].Tried = start + j + 1
						return
					}
				}
			}
			results[i].Tried = len(opts.Names)
		}(i, asn, byASN[asn])
	}
	wg.Wait()
	return results
}
