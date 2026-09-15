// Command tcp16probe — проба линии на блокировку по объёму соединения
// (z2k z2k-detect tcp16 lineage; мишени z2k MIT встроены в пакет).
//
// Два режима — принципиально разные вопросы:
//
//	tcp16probe                     есть ли блок на линии (по каждой AS)
//	tcp16probe -names names.txt    какое имя провайдер пропускает (per-AS)
//
//	tcp16probe -asn 24940 -confirmed -limit 10 -parallel 8
//	tcp16probe -names names.txt -batch 5 -out map.tsv
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/daniellavrushin/b4/netprobe/tcp16"
)

func main() {
	fs := flag.NewFlagSet("tcp16probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asn := fs.String("asn", "", "только эта AS (иначе все)")
	confirmed := fs.Bool("confirmed", false, "только AS, подтверждённые многими сообщениями")
	limit := fs.Int("limit", 0, "не больше N мишеней (0 — все)")
	names := fs.String("names", "", "файл имён-кандидатов: искать проходящее имя per-AS")
	par := fs.Int("parallel", 4, "сколько проб разом")
	batch := fs.Int("batch", 5, "сколько имён проверять разом внутри одной сети")
	asnOut := fs.String("asn-out", "", "куда выписать AS, где блок найден")
	out := fs.String("out", "", "куда выписать карту «сеть -> имя» (-names режим)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	targets := tcp16.DefaultTargets(tcp16.TargetsFilter{
		ASN:           *asn,
		ConfirmedOnly: *confirmed,
		Limit:         *limit,
	})
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "tcp16probe: мишеней не осталось после фильтров")
		os.Exit(2)
	}

	if *names != "" {
		scanPerASN(ctx, targets, *names, *par, *batch, *out)
		return
	}
	probeLineMode(ctx, targets, *par, *asnOut)
}

func probeLineMode(ctx context.Context, targets []tcp16.Target, par int, asnOut string) {
	v := tcp16.ProbeLine(ctx, targets, tcp16.ProbeLineOptions{Parallel: par})
	for _, a := range v.PerAS {
		mark := "—"
		if a.Detected > 0 {
			mark = "БЛОК"
		} else if a.Alive > 0 {
			mark = "чисто"
		}
		fmt.Printf("AS%-8s %-6s  мишеней %2d, ответили %2d, блок на %d\n",
			a.ASN, mark, a.Total, a.Alive, a.Detected)
	}
	fmt.Println()
	switch {
	case v.AnyAlive == 0:
		fmt.Println("ВЕРДИКТ: мишени не отвечают вовсе — линия или список мишеней негодны, судить не по чему")
		os.Exit(3)
	case v.AnyDet > 0:
		fmt.Printf("ВЕРДИКТ: блок по объёму ЕСТЬ (сработал на %d мишенях из %d ответивших)\n", v.AnyDet, v.AnyAlive)
	default:
		fmt.Printf("ВЕРДИКТ: блока по объёму НЕТ (%d мишеней ответили, ни одна не оборвалась)\n", v.AnyAlive)
	}
	if asnOut != "" {
		var sb strings.Builder
		sb.WriteString("# AS, где проба нашла блок по объёму. Пересобирается пробой.\n")
		for _, a := range v.DetectedASN {
			sb.WriteString(a)
			sb.WriteString("\n")
		}
		if err := os.WriteFile(asnOut, []byte(sb.String()), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "tcp16probe: не смог записать %s: %v\n", asnOut, err)
		}
	}
	if v.AnyDet > 0 {
		os.Exit(1)
	}
}

func scanPerASN(ctx context.Context, targets []tcp16.Target, namesPath string, par, batch int, out string) {
	candidates, err := loadNames(namesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcp16probe: %v\n", err)
		os.Exit(2)
	}
	results := tcp16.ScanPerASN(ctx, targets, tcp16.ScanPerASNOptions{
		Names:    candidates,
		Parallel: par,
		Batch:    batch,
	})

	// Детерминированный вывод.
	sorted := append([]tcp16.ASNName(nil), results...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ASN < sorted[j].ASN })
	var sb strings.Builder
	sb.WriteString("# Имя из белого списка на каждую сеть, где найден блок по объёму.\n")
	sb.WriteString("# Формат: <asn><TAB><имя>. Пересобирается пробой.\n")
	ok := 0
	for _, r := range sorted {
		switch {
		case r.Name != "":
			fmt.Printf("AS%-8s ПОДОШЛО %-24s (кандидат %d)\n", r.ASN, r.Name, r.Tried)
			sb.WriteString(r.ASN + "\t" + r.Name + "\n")
			ok++
		case r.Blocked:
			fmt.Printf("AS%-8s имя не найдено (перебрано %d)\n", r.ASN, r.Tried)
		default:
			fmt.Printf("AS%-8s блока нет — имя не нужно\n", r.ASN)
		}
	}
	fmt.Printf("\nимена найдены для %d сетей из %d\n", ok, len(sorted))
	if out != "" {
		if err := os.WriteFile(out, []byte(sb.String()), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "tcp16probe: не смог записать %s: %v\n", out, err)
		}
	}
	if ok == 0 {
		os.Exit(2)
	}
}

func loadNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("нет файла имён %s: %w", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := sc.Text()
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		s = strings.TrimSpace(s)
		if s != "" {
			// имя обязано выглядеть именем: мусор в списке стоит всей пробе
			if _, err := netip.ParseAddr(s); err == nil {
				continue
			}
			out = append(out, s)
		}
	}
	return out, sc.Err()
}
