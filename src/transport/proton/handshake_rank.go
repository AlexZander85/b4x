// Параллельный опрос Proton-кандидатов (Nova parallel probing canon):
// WG-handshake-пробы по парам (адрес, порт) + TCP/443-замер адресов,
// оба вида работами одновременно, слияние в 3-ярусный рейтинг:
//
//	ярус 1  handshake-проверенные узлы (RTT аутентифицированного
//	        Noise-IK обмена) — лучший доступный сигнал;
//	ярус 2  TCP-измеренные (сортировочный хинт PR #4);
//	ярус 3  неизмеренные (Load/Score, прежнее поведение).
//
// RTT разных видов проб НЕ сравниваются между собой напрямую (handshake
// несёт полный round-trip + крипто-работу, TCP/443 — только connect):
// сравнение только внутри яруса, ярус всегда старше числа.
//
// Дедуп по паре (ip, port) — НЕ по адресу: port-fallback даёт один адрес
// на нескольких портах, и сэмплы разных портов независимы (урок прошлой
// сессии: дедуп по EntryIP ронял легитимные пробы fallback-портов).
// Слияние до адреса — уже ПОСЛЕ замера (лучший OK-сэмпл адреса).
package proton

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// DefaultHandshakeProbeParallel ограничивает одновременные UDP-пробы
// (роутер: UDP-сокеты + крипта дешевле TCP, но очередь тоже конечна).
const DefaultHandshakeProbeParallel = 8

// DefaultHandshakeProbeTimeout — бюджет одной пробы в батче (батч не
// должен растягиваться на таймауты всех узлов подряд).
const DefaultHandshakeProbeTimeout = 2 * time.Second

// HandshakeSample — результат WG-handshake пробы одной пары (ip, port).
type HandshakeSample struct {
	RTT        time.Duration
	OK         bool
	CookieSeen bool
}

// CandidateKey рендерит дедупликационный ключ пары (адрес, порт).
func CandidateKey(cand Candidate) string {
	return net.JoinHostPort(cand.Node.EntryIP, strconv.Itoa(int(cand.Port)))
}

// ProbeHandshakeBatch параллельно опрашивает кандидатов handshake-пробами.
// Возвращает сэмплы по ключам CandidateKey; кандмы без адреса пропускаются.
// privateKeyB64 пустой => пустой результат (пробер не вооружён — TCP-режим).
func ProbeHandshakeBatch(ctx context.Context, privateKeyB64 string,
	cands []Candidate, cfg ProbeHandshakeConfig) map[string]HandshakeSample {

	out := make(map[string]HandshakeSample, len(cands))
	if privateKeyB64 == "" || len(cands) == 0 {
		return out
	}

	// Дедуп по (ip, port) с сохранением первого вхождения.
	type job struct {
		cand Candidate
	}
	seen := make(map[string]struct{}, len(cands))
	jobs := make([]job, 0, len(cands))
	for _, cand := range cands {
		if cand.Node.EntryIP == "" || cand.Node.PeerPubKey == "" {
			continue
		}
		key := CandidateKey(cand)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		jobs = append(jobs, job{cand: cand})
	}
	if len(jobs) == 0 {
		return out
	}

	parallel := DefaultHandshakeProbeParallel
	if len(jobs) < parallel {
		parallel = len(jobs)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	in := make(chan job)
	wg.Add(parallel)
	for i := 0; i < parallel; i++ {
		go func() {
			defer wg.Done()
			for j := range in {
				res := probeOneCandidate(ctx, privateKeyB64, j.cand, cfg)
				mu.Lock()
				out[CandidateKey(j.cand)] = res
				mu.Unlock()
			}
		}()
	}
	go func() {
		defer close(in)
		for _, j := range jobs {
			select {
			case in <- j:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	return out
}

// probeOneCandidate выполняет одну handshake-пробу с разрешением адреса.
func probeOneCandidate(ctx context.Context, privateKeyB64 string,
	cand Candidate, cfg ProbeHandshakeConfig) HandshakeSample {

	addr, err := net.ResolveUDPAddr("udp", CandidateKey(cand))
	if err != nil {
		return HandshakeSample{}
	}
	res := ProbeHandshakeRTT(ctx, privateKeyB64, cand.Node.PeerPubKey, addr, cfg)
	return HandshakeSample{RTT: res.RTT, OK: res.OK, CookieSeen: res.CookieSeen}
}

// MergeProbeRanking сводит handshake-сэмплы и TCP-замеры в узлы:
// адресу достаётся лучший (минимальный) OK-сэмпл handshake среди
// опрошенных портов; иначе TCP-сэмпл; иначе узел остаётся неизмеренным.
// RTTSource фиксирует происхождение сэмпла для ярусной сортировки.
func MergeProbeRanking(nodes []Node, hs map[string]HandshakeSample,
	tcpRTTs map[string]time.Duration, ports []uint16) []Node {

	// Лучший handshake-сэмпл по адресу (по опрошенным портам).
	bestHS := make(map[string]HandshakeSample, len(hs))
	for key, s := range hs {
		if !s.OK {
			continue
		}
		host, _, err := net.SplitHostPort(key)
		if err != nil || host == "" {
			continue
		}
		cur, exists := bestHS[host]
		if !exists || s.RTT < cur.RTT {
			bestHS[host] = s
		}
	}

	out := append([]Node(nil), nodes...)
	for i := range out {
		ip := out[i].EntryIP
		if ip == "" {
			continue
		}
		if s, ok := bestHS[ip]; ok {
			out[i].RTT = s.RTT
			out[i].RTTSource = RTTSourceHandshake
			continue
		}
		if rtt, ok := tcpRTTs[ip]; ok && rtt > 0 {
			out[i].RTT = rtt
			out[i].RTTSource = RTTSourceTCP
			continue
		}
		out[i].RTT = 0
		out[i].RTTSource = ""
	}
	return out
}

// SortCandidatesByProbeTiers применяет 3-ярусный порядок к копии списка:
// handshake-ярус, затем TCP-ярус, затем неизмеренные; внутри яруса RTT
// по возрастанию, дальше Load/Score. Стабильно.
func SortCandidatesByProbeTiers(nodes []Node) []Node {
	out := append([]Node(nil), nodes...)
	tier := func(n Node) int {
		switch n.RTTSource {
		case RTTSourceHandshake:
			return 0
		case RTTSourceTCP:
			return 1
		}
		if n.RTT > 0 { // legacy PR #4 sample without provenance
			return 1
		}
		return 2
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := tier(out[i]), tier(out[j])
		if ti != tj {
			return ti < tj
		}
		if ti < 2 { // измеренные ярусы сравнивают RTT только между собой
			ri, rj := out[i].RTT, out[j].RTT
			if ri != rj {
				return ri < rj
			}
		}
		if out[i].Load != out[j].Load {
			return out[i].Load < out[j].Load
		}
		return out[i].Score < out[j].Score
	})
	return out
}
