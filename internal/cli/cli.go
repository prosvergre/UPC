// Package cli реализует консольный режим работы: proxycheck запускается
// с аргументами командной строки для использования в скриптах автоматизации.
package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"proxycheck/internal/config"
	"proxycheck/internal/engine"
	"proxycheck/internal/node"
	"proxycheck/internal/relay"
	"proxycheck/internal/sources"
)

func engineConfig() (engine.Config, error) {
	bin, err := engine.FindBinary()
	if err != nil {
		return engine.Config{}, err
	}
	return engine.Config{Binary: bin, WorkDir: filepath.Join(os.TempDir(), "proxycheck-sb")}, nil
}

// Run разбирает флаги и выполняет всю работу. args — обычно os.Args[1:].
func Run(args []string) int {
	fs := flag.NewFlagSet("proxycheck", flag.ExitOnError)
	output := fs.String("o", "proxies.txt", "выходной файл (.txt — ссылки по строкам, иначе JSON)")
	concurrency := fs.Int("c", 50, "число одновременных проверок; игнорируется при -sequential")
	sequential := fs.Bool("sequential", false, "проверять сервера последовательно")
	timeoutSec := fs.Int("t", 5, "таймаут одной проверки, секунды")
	extraSources := fs.String("sources", "", "доп. источники (raw-URL), через запятую")
	noDefault := fs.Bool("no-default-sources", false, "не использовать встроенный список источников")
	top := fs.Int("top", 0, "оставить только N самых быстрых серверов (0 = все рабочие)")
	selectIDs := fs.String("select", "", "оставить ТОЛЬКО эти сервера (host:port,...) — переопределяет -top")
	quiet := fs.Bool("q", false, "не выводить прогресс, только итог")
	listSources := fs.Bool("list-sources", false, "показать встроенный список источников и выйти")
	listProtos := fs.Bool("list-protocols", false, "показать поддерживаемые протоколы и выйти")

	serve := fs.Bool("serve", false, "после проверки поднять локальные входы (SOCKS5+HTTP) и работать демоном")
	servePortStart := fs.Int("serve-port-start", 1080, "первый локальный порт при -serve")
	healthInterval := fs.Int("health-interval", 30, "интервал health-проверки при -serve, секунды")
	failThreshold := fs.Int("fail-threshold", 2, "сколько неудач подряд означают, что сервер мёртв (при -serve)")

	doSpeedtest := fs.Bool("speedtest", false, "замерить скорость скачивания у отобранных серверов")
	fs.Parse(args)

	if *listSources {
		for _, s := range sources.Default {
			fmt.Printf("%-30s %s\n", s.Name, s.URL)
		}
		return 0
	}
	if *listProtos {
		fmt.Println("ss (в т.ч. SS2022), vless (reality, ws, grpc, ...), vmess, trojan, socks4/5, http(s), hysteria, hysteria2, tuic, wireguard, ssh")
		return 0
	}

	srcList := []sources.Source{}
	if !*noDefault {
		srcList = append(srcList, sources.Default...)
	}
	for _, u := range strings.Split(*extraSources, ",") {
		if u = strings.TrimSpace(u); u != "" {
			srcList = append(srcList, sources.Source{Name: u, URL: u})
		}
	}
	if len(srcList) == 0 {
		fmt.Fprintln(os.Stderr, "нет ни одного источника (--no-default-sources без --sources)")
		return 1
	}
	if !*quiet {
		fmt.Printf("Загружаю %d источник(ов)...\n", len(srcList))
	}
	fetched := sources.FetchAll(srcList, 20*time.Second)

	var all []node.Node
	seen := map[string]bool{}
	for _, fr := range fetched {
		if fr.Err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "  [ошибка] %s: %v\n", fr.Source.Name, fr.Err)
			}
			continue
		}
		found := node.ExtractAll(fr.Body)
		added := 0
		for _, s := range found {
			if seen[s.ID()] {
				continue
			}
			seen[s.ID()] = true
			all = append(all, s)
			added++
		}
		if !*quiet {
			fmt.Printf("  [ok] %-28s %4d серверов (уникальных: %d)\n", fr.Source.Name, len(found), added)
		}
	}
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "не удалось извлечь ни одного сервера из источников")
		return 1
	}
	var valid []node.Node
	for _, s := range all {
		if node.Validate(s) == nil {
			valid = append(valid, s)
		}
	}
	if !*quiet && len(valid) != len(all) {
		fmt.Printf("Пропущено %d серверов с некорректными параметрами.\n", len(all)-len(valid))
	}
	all = valid
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "не осталось серверов с корректными параметрами")
		return 1
	}

	cfg, err := engineConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conc := *concurrency
	if *sequential {
		conc = 1
	}
	if !*quiet {
		fmt.Printf("Запускаю ядро, загружаю %d серверов...\n", len(all))
	}
	lab, err := engine.NewLab(cfg, all, 4)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка ядра:", err)
		return 1
	}
	lastPrint := time.Now()
	results := lab.CheckAll(context.Background(), all, conc, time.Duration(*timeoutSec)*time.Second, func(done, total int, r engine.Result) {
		if *quiet {
			return
		}
		if time.Since(lastPrint) > 200*time.Millisecond || done == total {
			fmt.Printf("\r  проверено %d/%d...", done, total)
			lastPrint = time.Now()
		}
	})
	if !*quiet {
		fmt.Println()
	}
	var alive []engine.Result
	for _, r := range results {
		if r.Alive {
			alive = append(alive, r)
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].Latency < alive[j].Latency })
	if !*quiet {
		fmt.Printf("Рабочих серверов: %d из %d\n", len(alive), len(all))
	}
	if len(alive) == 0 {
		lab.Close()
		fmt.Fprintln(os.Stderr, "ни один сервер не прошёл проверку, дальше идти некуда")
		return 1
	}

	chosen := alive
	if *selectIDs != "" {
		wanted := map[string]bool{}
		for _, id := range strings.Split(*selectIDs, ",") {
			if id = strings.TrimSpace(id); id != "" {
				wanted[id] = true
			}
		}
		chosen = nil
		for _, r := range alive {
			if wanted[r.Node.Addr()] || wanted[r.Node.ID()] {
				chosen = append(chosen, r)
			}
		}
		if len(chosen) == 0 {
			lab.Close()
			fmt.Fprintln(os.Stderr, "ни один из -select не найден среди рабочих серверов")
			return 1
		}
	} else if *top > 0 && len(chosen) > *top {
		chosen = chosen[:*top]
	}
	var chosenNodes []node.Node
	for _, r := range chosen {
		chosenNodes = append(chosenNodes, r.Node)
	}

	if *doSpeedtest && !*serve {
		if !*quiet {
			fmt.Println("Замер скорости скачивания...")
		}
		for _, s := range chosenNodes {
			down, _, derr, _ := lab.Speed(context.Background(), s, false, 20*time.Second)
			if derr != nil {
				fmt.Printf("  %-30s ошибка: %v\n", s.Label(), derr)
				continue
			}
			fmt.Printf("  %-30s %.2f Мбит/с (%.1f МБ за %v)\n", s.Label(), down.Mbps,
				float64(down.Bytes)/1_000_000, down.Duration.Round(10*time.Millisecond))
		}
	}
	lab.Close()

	if err := config.Write(*output, chosenNodes); err != nil {
		fmt.Fprintf(os.Stderr, "не удалось записать %s: %v\n", *output, err)
		return 1
	}
	if !*quiet {
		fmt.Printf("Записано: %s (%d серверов)\n", *output, len(chosenNodes))
		limit := 5
		if len(chosen) < limit {
			limit = len(chosen)
		}
		fmt.Printf("Топ-%d по задержке:\n", limit)
		for i := 0; i < limit; i++ {
			fmt.Printf("  %2d. %-30s %v\n", i+1, chosen[i].Node.Label(), chosen[i].Latency.Round(time.Millisecond))
		}
	}
	if !*serve {
		return 0
	}
	return runServe(cfg, chosenNodes, alive, *servePortStart, time.Duration(*healthInterval)*time.Second,
		time.Duration(*timeoutSec)*time.Second, *failThreshold, *quiet)
}

// runServe поднимает по одному входу на выбранный сервер (все в одном процессе
// sing-box), включает health-мониторинг с failover и блокируется до Ctrl+C.
func runServe(cfg engine.Config, chosen []node.Node, allAlive []engine.Result, portStart int,
	healthInterval, checkTimeout time.Duration, failThreshold int, quiet bool) int {

	pool := make([]node.Node, 0, len(allAlive))
	for _, r := range allAlive {
		pool = append(pool, r.Node)
	}
	mgr := relay.NewManager(pool, checkTimeout)
	mgr.Listen = "127.0.0.1"
	mgr.SetEngine(cfg)

	ports := make([]int, len(chosen))
	for i := range ports {
		ports[i] = portStart + i
	}
	eps, errs := mgr.StartMany(chosen, ports)
	for i, s := range chosen {
		if errs[i] != nil {
			fmt.Fprintf(os.Stderr, "не удалось запустить %s: %v\n", s.Label(), errs[i])
			continue
		}
		fmt.Printf("127.0.0.1:%-6d -> %s\n", eps[i].LocalPort, s.Label())
	}

	stop := make(chan struct{})
	go mgr.RunHealthLoop(healthInterval, checkTimeout, failThreshold, stop)
	if !quiet {
		go func() {
			for ev := range mgr.Events() {
				fmt.Printf("[%s] %s: %s\n", ev.Time.Format("15:04:05"), ev.EndpointID, ev.Message)
			}
		}()
	}
	fmt.Println("Демон запущен. Ctrl+C для остановки.")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\nОстанавливаюсь...")
	close(stop)
	mgr.StopAll()
	return 0
}
