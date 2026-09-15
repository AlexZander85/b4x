package tcp16

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

// fakeBoxServer — тестовая «коробка»: TLS-эхо HEAD-сервер, который рвёт
// соединение, когда НАКОПЛЕННЫЙ объём запросов перевалил за cutKB.
// Накопление считается по суммарно прочитанным байтам всех запросов — не
// по одному (урок прошлой сессии: коробка режет по накопленному объёму
// соединения, а не по размеру отдельного запроса).
func fakeBoxServer(t *testing.T, cutKB int) net.Addr {
	t.Helper()
	cert := selfSignedCert(t)
	pc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		for {
			conn, err := pc.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tc.Handshake(); err != nil {
					return
				}
				br := bufio.NewReader(tc)
				total := 0
				for {
					req, err := br.ReadString('\n')
					if err != nil {
						return
					}
					total += len(req) // каждая строка ровно один раз
					if req == "\r\n" {
						// конец запроса: решаем, отвечать ли
						if cutKB > 0 && total >= cutKB*1024 {
							// коробка рвёт: соединение набрало порог
							_ = tc.SetDeadline(time.Now())
							return
						}
						_, _ = tc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
					}
				}
			}(conn)
		}
	}()
	return pc.Addr()
}

// TestProbeDetectsVolumeCut: мишень, рвущаяся на 20 КБ накопленного
// объёма, даёт Detected=true с DiedAtKB в наблюдавшемся окне.
func TestProbeDetectsVolumeCut(t *testing.T) {
	addr := fakeBoxServer(t, 20)
	target := Target{
		ID: "T-1", ASN: "64512", Provider: "test",
		IP:   addr.(*net.TCPAddr).IP.String(),
		Port: addr.(*net.TCPAddr).Port,
	}
	res := Probe(context.Background(), target, "")
	if !res.Alive {
		t.Fatalf("first request must succeed: %+v", res)
	}
	if !res.Detected {
		t.Fatalf("20KB cut must be detected: %+v", res)
	}
	if res.DiedAtKB < MinDetectKB || res.DiedAtKB > 40 {
		t.Fatalf("died at %d KB, want inside the probe window", res.DiedAtKB)
	}
}

// TestProbeCleanLine: мишень без порога отдаёт все 10 запросов —
// Detected=false, Alive=true.
func TestProbeCleanLine(t *testing.T) {
	addr := fakeBoxServer(t, 0)
	target := Target{
		ID: "T-2", ASN: "64512", Provider: "test",
		IP:   addr.(*net.TCPAddr).IP.String(),
		Port: addr.(*net.TCPAddr).Port,
	}
	res := Probe(context.Background(), target, "")
	if !res.Alive || res.Detected {
		t.Fatalf("clean line must be alive+undetected: %+v", res)
	}
}

// TestProbeDeadTarget: недоступная мишень — не блок (Err заполнен,
// Alive=false).
func TestProbeDeadTarget(t *testing.T) {
	target := Target{ID: "T-3", ASN: "64512", IP: "127.0.0.1", Port: 1}
	res := Probe(context.Background(), target, "")
	if res.Alive || res.Detected {
		t.Fatalf("dead target must not be a verdict: %+v", res)
	}
	if res.Err == "" {
		t.Fatalf("dead target must carry an error")
	}
}

// TestParseTargetsEmbeddedFormat: встроенные данные z2k парсятся, формат
// узнан, фильтры работают.
func TestParseTargetsEmbeddedFormat(t *testing.T) {
	all := DefaultTargets(TargetsFilter{})
	if len(all) < 50 {
		t.Fatalf("embedded targets = %d, want the full z2k list (110)", len(all))
	}
	// у всех есть ASN, IP, порт; подтверждённые помечены
	for _, tg := range all {
		if tg.ASN == "" || tg.IP == "" || tg.Port == 0 {
			t.Fatalf("malformed target: %+v", tg)
		}
	}
	hetzner := DefaultTargets(TargetsFilter{ASN: "24940"})
	if len(hetzner) == 0 {
		t.Fatalf("ASN filter dropped everything")
	}
	for _, tg := range hetzner {
		if tg.ASN != "24940" {
			t.Fatalf("foreign AS leaked: %+v", tg)
		}
	}
	confirmed := DefaultTargets(TargetsFilter{ConfirmedOnly: true})
	if len(confirmed) == 0 || len(confirmed) >= len(all) {
		t.Fatalf("confirmed filter = %d of %d, want a strict subset", len(confirmed), len(all))
	}
	limited := DefaultTargets(TargetsFilter{Limit: 3})
	if len(limited) != 3 {
		t.Fatalf("limit filter = %d, want 3", len(limited))
	}
}

// TestParseTargetsSNI: седьмая колонка (имя мишени) читается, старый
// формат без неё — тоже.
func TestParseTargetsSNI(t *testing.T) {
	data := []byte("X-1\t64500\t*\tTest\t192.0.2.1\t443\treal.name.example\n" +
		"X-2\t64500\t-\tTest\t192.0.2.2\t443\n")
	tg := ParseTargets(data, TargetsFilter{})
	if len(tg) != 2 {
		t.Fatalf("parsed %d, want 2", len(tg))
	}
	if tg[0].SNI != "real.name.example" {
		t.Fatalf("sni = %q", tg[0].SNI)
	}
	if tg[1].SNI != "" {
		t.Fatalf("legacy row must have empty sni, got %q", tg[1].SNI)
	}
}

// TestProbeLineAggregatesByAS: агрегация вердикта по сетям.
func TestProbeLineAggregatesByAS(t *testing.T) {
	dead := Target{ID: "D", ASN: "64599", IP: "127.0.0.1", Port: 1}
	v := ProbeLine(context.Background(), []Target{dead},
		ProbeLineOptions{Parallel: 1, PerProbeTimeout: 2 * time.Second})
	if v.AnyAlive != 0 || v.AnyDet != 0 {
		t.Fatalf("dead-only verdict must be empty: %+v", v)
	}
	if v.Verdict() == "блока по объёму НЕТ" {
		t.Fatalf("no alive targets must not read as a clean line")
	}
}

// selfSignedCert генерирует настоящую self-signed пару (проба всё равно
// InsecureSkipVerify — нужен лишь валидный TLS-сервер).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
