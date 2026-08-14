// Package cli реализует консольный режим работы: proxycheck запускается
// с аргументами командной строки для использования в скриптах автоматизации.
package cli

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"proxycheck/internal/checker"
	"proxycheck/internal/config"
	"proxycheck/internal/relay"
	"proxycheck/internal/sources"
	"proxycheck/internal/speedtest"
	"proxycheck/internal/ssclient"
	"proxycheck/internal/ssuri"
)

// Run разбирает флаги и выполняет всю работу. args — обычно os.Args[1:].
func Run(args []string) int {
	fs := flag.NewFlagSet("proxycheck", flag.ExitOnError)
	output := fs.String("o", "proxies.json", "путь к выходному конфигу (формат shadowsocks-rust)")
	concurrency := fs.Int("c", 50, "число одновременных проверок (потоков); игнорируется при -sequential")
	sequential := fs.Bool("sequential", false, "проверять сервера последовательно, а не параллельно")
	timeoutSec := fs.Int("t", 5, "таймаут одной проверки, секунды")
	localPort := fs.Int("local-port", 1080, "локальный порт в итоговом JSON-конфиге (поле local_port)")
	extraSources := fs.String("sources", "", "доп. источники (raw-URL), через запятую")
	noDefault := fs.Bool("no-default-sources", false, "не использовать встроенный список источников")
	top := fs.Int("top", 0, "оставить только N самых быстрых серверов (0 = все рабочие)")
	selectIDs := fs.String("select", "", "сохранить/использовать ТОЛЬКО эти сервера (host:port,host:port,...) — переопределяет -top")
	quiet := fs.Bool("q", false, "не выводить прогресс, только итог")
	listSources := fs.Bool("list-sources", false, "показать встроенный список источников и выйти")
	listMethods := fs.Bool("list-methods", false, "показать поддерживаемые методы шифрования и выйти")

	serve := fs.Bool("serve", false, "после проверки поднять локальные SOCKS5-прокси на отобранные сервера и работать демоном (Ctrl+C для выхода)")
	servePortStart := fs.Int("serve-port-start", 1080, "первый локальный порт при -serve (дальше по возрастанию: 1080, 1081, ...)")
	healthInterval := fs.Int("health-interval", 30, "интервал health-проверки активных прокси при -serve, секунды")
	failThreshold := fs.Int("fail-threshold", 2, "сколько подряд неудачных проверок означают, что сервер мёртв (при -serve)")

	doSpeedtest := fs.Bool("speedtest", false, "замерить скорость скачивания у отобранных серверов (через реальный SS-туннель)")
	speedtestURL := fs.String("speedtest-url", "", "свой URL для замера скорости (по умолчанию — файл с speed.cloudflare.com)")

	deepVerify := fs.Bool("deep-verify", true, "после TCP-проверки дополнительно подтверждать сервера реальным SS-подключением (медленнее, но не даёт ложно-живых)")

	fs.Parse(args)

	if *listSources {
		for _, s := range sources.Default {
			fmt.Printf("%-30s %s\n", s.Name, s.URL)
		}
		return 0
	}
	if *listMethods {
		for _, m := range ssclient.SupportedMethods() {
			fmt.Println(m)
		}
		return 0
	}

	srcList := []sources.Source{}
	if !*noDefault {
		srcList = append(srcList, sources.Default...)
	}
	if *extraSources != "" {
		for _, u := range strings.Split(*extraSources, ",") {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
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

	var all []ssuri.Server
	seen := make(map[string]bool)
	for _, fr := range fetched {
		if fr.Err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "  [ошибка] %s: %v\n", fr.Source.Name, fr.Err)
			}
			continue
		}
		found := ssuri.ExtractAll(fr.Body)
		added := 0
		for _, s := range found {
			id := s.ID()
			if seen[id] {
				continue
			}
			seen[id] = true
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

	// отсеиваем сервера с методами шифрования, которые мы не умеем
	// подключать — иначе они честно проходили бы TCP-проверку (порт
	// открыт), но реально никогда не смогли бы установить соединение.
	var supported []ssuri.Server
	skippedByMethod := map[string]int{}
	for _, s := range all {
		if ssclient.Supported(s.Method) {
			supported = append(supported, s)
		} else {
			skippedByMethod[s.Method]++
		}
	}
	if len(skippedByMethod) > 0 && !*quiet {
		fmt.Printf("Пропущено %d серверов с неподдерживаемыми методами шифрования:\n", len(all)-len(supported))
		for m, n := range skippedByMethod {
			fmt.Printf("  %-30s ×%d\n", m, n)
		}
		fmt.Printf("  (поддерживаются: %s)\n", strings.Join(ssclient.SupportedMethods(), ", "))
	}
	all = supported
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "не осталось серверов с поддерживаемыми методами шифрования")
		return 1
	}

	checkConcurrency := *concurrency
	if *sequential {
		checkConcurrency = 1
	}
	if !*quiet {
		mode := "параллельно"
		if *sequential {
			mode = "последовательно"
		}
		fmt.Printf("Всего уникальных серверов: %d. Проверяю (%s, таймаут: %ds)...\n",
			len(all), mode, *timeoutSec)
	}

	opts := checker.Options{
		Concurrency: checkConcurrency,
		Timeout:     time.Duration(*timeoutSec) * time.Second,
	}

	lastPrint := time.Now()
	results := checker.CheckAll(all, opts, func(done, total int, r checker.Result) {
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

	var alive []checker.Result
	for _, r := range results {
		if r.Alive {
			alive = append(alive, r)
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].Latency < alive[j].Latency })

	if *deepVerify && len(alive) > 0 {
		if !*quiet {
			fmt.Printf("Глубокая проверка %d серверов (реальное SS-подключение)...\n", len(alive))
		}
		var candidates []ssuri.Server
		for _, r := range alive {
			candidates = append(candidates, r.Server)
		}
		lastPrint = time.Now()
		deepResults := checker.DeepVerifyAll(candidates, opts, func(done, total int, r checker.Result) {
			if *quiet {
				return
			}
			if time.Since(lastPrint) > 200*time.Millisecond || done == total {
				fmt.Printf("\r  глубокая проверка %d/%d...", done, total)
				lastPrint = time.Now()
			}
		})
		if !*quiet {
			fmt.Println()
		}
		var deepAlive []checker.Result
		for _, r := range deepResults {
			if r.Alive {
				deepAlive = append(deepAlive, r)
			}
		}
		sort.Slice(deepAlive, func(i, j int) bool { return deepAlive[i].Latency < deepAlive[j].Latency })
		if !*quiet {
			fmt.Printf("Реально рабочих: %d из %d прошедших TCP.\n", len(deepAlive), len(alive))
		}
		alive = deepAlive
	}

	if !*quiet {
		fmt.Printf("Рабочих серверов: %d из %d\n", len(alive), len(all))
	}
	if len(alive) == 0 {
		fmt.Fprintln(os.Stderr, "ни один сервер не прошёл проверку, дальше идти некуда")
		return 1
	}

	// отбор: -select имеет приоритет над -top
	var chosen []checker.Result
	if *selectIDs != "" {
		wanted := make(map[string]bool)
		for _, id := range strings.Split(*selectIDs, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				wanted[id] = true
			}
		}
		for _, r := range alive {
			if wanted[r.Server.ID()] {
				chosen = append(chosen, r)
			}
		}
		if len(chosen) == 0 {
			fmt.Fprintln(os.Stderr, "ни один из -select не найден среди рабочих серверов")
			return 1
		}
	} else {
		chosen = alive
		if *top > 0 && len(chosen) > *top {
			chosen = chosen[:*top]
		}
	}

	var chosenServers []ssuri.Server
	for _, r := range chosen {
		chosenServers = append(chosenServers, r.Server)
	}

	if *doSpeedtest && !*serve {
		if !*quiet {
			fmt.Println("Замер скорости скачивания...")
		}
		runSpeedtests(chosenServers, *speedtestURL, time.Duration(*timeoutSec)*time.Second, *quiet)
	}

	cfg := config.FromServers(chosenServers, *localPort)
	if err := config.WriteJSON(*output, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "не удалось записать %s: %v\n", *output, err)
		return 1
	}
	if !*quiet {
		fmt.Printf("Конфиг записан: %s (%d серверов)\n", *output, len(chosenServers))
		limit := 5
		if len(chosen) < limit {
			limit = len(chosen)
		}
		fmt.Printf("Топ-%d по задержке:\n", limit)
		for i := 0; i < limit; i++ {
			r := chosen[i]
			name := r.Server.Remarks
			if name == "" {
				name = r.Server.ID()
			}
			fmt.Printf("  %2d. %-30s %v\n", i+1, name, r.Latency.Round(time.Millisecond))
		}
	}

	if !*serve {
		return 0
	}

	return runServe(chosenServers, alive, *servePortStart, time.Duration(*healthInterval)*time.Second,
		time.Duration(*timeoutSec)*time.Second, *failThreshold, *quiet)
}

// runSpeedtests качает тестовый файл через каждый сервер по очереди
// (по одному временному локальному порту) и печатает результат.
func runSpeedtests(servers []ssuri.Server, url string, timeout time.Duration, quiet bool) {
	const tmpPort = 19999
	mgr := relay.NewManager(nil, timeout)
	for _, s := range servers {
		_, err := mgr.Start(s, tmpPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: не удалось поднять локальный вход: %v\n", s.ID(), err)
			continue
		}
		res, err := speedtest.Download(fmt.Sprintf("127.0.0.1:%d", tmpPort), url, 20*time.Second)
		mgr.Stop(s.ID())
		name := s.Remarks
		if name == "" {
			name = s.ID()
		}
		if err != nil {
			fmt.Printf("  %-30s ошибка: %v\n", name, err)
			continue
		}
		fmt.Printf("  %-30s %.2f Мбит/с (%.1f МБ за %v)\n", name, res.Mbps,
			float64(res.Bytes)/1_000_000, res.Duration.Round(10*time.Millisecond))
	}
}

// runServe поднимает по одному локальному SOCKS5-входу на каждый
// выбранный сервер (последовательные локальные порты, начиная с
// portStart), включает health-мониторинг с точечным failover из
// полного пула alive-результатов последнего скана и блокируется до
// Ctrl+C/SIGTERM.
func runServe(chosen []ssuri.Server, allAlive []checker.Result, portStart int,
	healthInterval, checkTimeout time.Duration, failThreshold int, quiet bool) int {

	pool := make([]ssuri.Server, 0, len(allAlive))
	for _, r := range allAlive {
		pool = append(pool, r.Server)
	}

	mgr := relay.NewManager(pool, checkTimeout)
	port := portStart
	for _, s := range chosen {
		ep, err := mgr.Start(s, port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "не удалось запустить %s на порту %d: %v\n", s.ID(), port, err)
			port++
			continue
		}
		name := s.Remarks
		if name == "" {
			name = s.ID()
		}
		fmt.Printf("127.0.0.1:%-6d -> %s (%s)\n", ep.LocalPort, name, s.ID())
		port++
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
