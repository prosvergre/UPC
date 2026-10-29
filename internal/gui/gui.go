// Package gui реализует графический интерфейс (таблица + кнопки) на Fyne.
// Запускается автоматически, если программа стартовала без аргументов.
package gui

import (
	"context"
	"embed"
	"fmt"
	"io"
	"log"
	"net"
	"proxycheck/internal/engine"
	"sort"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	"proxycheck/internal/config"
	"proxycheck/internal/debugflag"
	"proxycheck/internal/firewall"
	"proxycheck/internal/localdns"
	"proxycheck/internal/netutil"
	"proxycheck/internal/node"
	"proxycheck/internal/sources"
)

//go:embed assets/icon.png
var iconAssets embed.FS

// appIcon загружает встроенную иконку приложения (используется и для
// окна, и для системного трея — так программу видно и в диспетчере
// задач/панели задач, и в трее при сворачивании).
func appIcon() fyne.Resource {
	data, err := iconAssets.ReadFile("assets/icon.png")
	if err != nil {
		return nil // не критично — просто останется иконка Fyne по умолчанию
	}
	return fyne.NewStaticResource("icon.png", data)
}

// колонки главной таблицы:
// [0]✓ [1]Имя [2]Адрес:порт [3]Метод [4]Статус [5]Задержка [6]↓ [7]↑ [8]IP [9]DNS [10]★ [11]Прокси
const mainNumCols = 12

// колонки таблицы закладок:
// [0]✓ [1]Имя [2]Адрес:порт [3]Комментарий [4]Статус [5]Задержка [6]Прокси [7]Убрать
const bookmarkNumCols = 8

// RunOptions — параметры автозапуска GUI.
type RunOptions struct {
	AutoStart      bool // сразу после старта загрузить+проверить сервера (игнорируется, если есть сохранённые профили)
	StartMinimized bool // сразу свернуться в трей
}

// singleInstanceLockPort — фиксированный локальный порт-"замок": если
// забиндиться на него не удаётся, значит другой экземпляр уже запущен.
const singleInstanceLockPort = 58712

func Run(opts RunOptions) {
	a := app.NewWithID("com.thomasszaund.proxycheck")
	if icon := appIcon(); icon != nil {
		a.SetIcon(icon)
	}

	lock, err := netutil.ListenExclusiveTCP(fmt.Sprintf("127.0.0.1:%d", singleInstanceLockPort))
	if err != nil {
		w := a.NewWindow("proxycheck уже запущен")
		w.Resize(fyne.NewSize(420, 160))
		msg := widget.NewLabel("Похоже, proxycheck уже запущен (возможно, свёрнут в трей).\n\n" +
			"Если иконки в трее нет, найдите процесс через диспетчер задач\n" +
			"(вкладка \"Подробности\", proxycheck-windows-amd64.exe) и закройте его,\n" +
			"либо просто переключитесь на уже открытое окно.")
		msg.Wrapping = fyne.TextWrapWord
		okBtn := widget.NewButton("Понятно", func() { a.Quit() })
		w.SetContent(container.NewVBox(msg, okBtn))
		w.Show()
		a.Run()
		return
	}
	defer lock.Close()

	w := a.NewWindow("Shadowsocks Proxy Checker")
	w.Resize(fyne.NewSize(1250, 640))

	state := newAppState()

	// --- вкладка логов ---
	logText := widget.NewMultiLineEntry()
	logText.Wrapping = fyne.TextWrapWord
	logText.SetPlaceHolder("Здесь будут события: запуск/остановка прокси, DNS, ошибки подключения, health-мониторинг...")
	lb := &logBuffer{widget: logText}

	// trayFailed отслеживает, реально ли инициализировался системный
	// трей. Официального API "получилось ли" у Fyne/systray нет —
	// библиотека просто пишет "systray error: ..." через стандартный
	// log при сбое инициализации. Раз мы уже перехватываем весь log —
	// ловим эту подстроку и запоминаем: если трея на самом деле нет,
	// "Свернуть в трей" не должно прятать окно в никуда (именно это
	// произошло в прошлый раз — пришлось убивать процесс вручную).
	trayDetector := &trayFailureDetector{}
	log.SetOutput(safeMultiWriter{writers: []io.Writer{logWriterStderr{}, lb, trayDetector}})
	log.SetFlags(log.Ltime)

	status := widget.NewLabel("Готово. Нажмите «Загрузить и проверить».")
	progress := widget.NewProgressBar()
	progress.Hide()

	// activeTab отслеживает, какая вкладка сейчас выбрана — нужно
	// кнопкам "Перепроверить" и "Замер скорости отмеченных", которые
	// работают то с основным списком, то с закладками, в зависимости
	// от того, где сейчас находится пользователь.
	activeTab := 0 // 0 = Сервера, 1 = Закладки, 2 = Логи

	var mainTable, bookmarkTable *widget.Table
	var runBtn, recheckBtn, recheckSpeedBtn, stopAllBtn, exportAllBtn, exportSelectedBtn, speedtestBtn *widget.Button

	refreshTables := func() {
		if mainTable != nil {
			mainTable.Refresh()
		}
		if bookmarkTable != nil {
			bookmarkTable.Refresh()
		}
	}

	saveSoon := func() {
		go func() {
			if err := state.saveSettings(); err != nil {
				log.Printf("не удалось сохранить настройки: %v", err)
			}
		}()
	}

	// bookmarkedRows/allRows — снимки для индексации таблиц.
	bookmarkedRows := func() []*rowState {
		var out []*rowState
		for _, r := range state.rowsSnapshot() {
			if r.bookmarked {
				out = append(out, r)
			}
		}
		return out
	}

	concurrencyEntry := widget.NewEntry()
	concurrencyEntry.SetText("50")
	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText("5")
	healthIntervalEntry := widget.NewEntry()
	healthIntervalEntry.SetText(fmt.Sprintf("%d", state.healthIntervalSec))
	startPortEntry := widget.NewEntry()
	startPortEntry.SetText(fmt.Sprintf("%d", state.startPort))
	startPortEntry.OnChanged = func(v string) {
		state.mu.Lock()
		state.startPort = parseIntDefault(v, 1080)
		state.mu.Unlock()
		saveSoon()
	}
	sequentialCheck := widget.NewCheck("Последовательно", nil)
	healthCheck := widget.NewCheck("Авто-мониторинг активных", nil)
	healthCheck.SetChecked(true)
	exitIPCheck := widget.NewCheck("Определять выходной IP", nil)
	exitIPCheck.SetChecked(state.detectExitIP)
	exitIPCheck.OnChanged = func(v bool) {
		state.mu.Lock()
		state.detectExitIP = v
		state.mu.Unlock()
		saveSoon()
	}
	startMinimizedCheck := widget.NewCheck("Запускать свёрнутым", nil)
	startMinimizedCheck.SetChecked(state.startMinimized)
	startMinimizedCheck.OnChanged = func(v bool) {
		state.mu.Lock()
		state.startMinimized = v
		state.mu.Unlock()
		saveSoon()
	}

	var healthStop chan struct{}
	startHealthLoop := func() {
		if healthStop != nil {
			close(healthStop)
		}
		healthStop = make(chan struct{})
		to := parseIntDefault(timeoutEntry.Text, 5)
		interval := parseIntDefault(healthIntervalEntry.Text, 20)
		state.mu.Lock()
		state.healthIntervalSec = interval
		state.mu.Unlock()
		go state.mgr.RunHealthLoop(time.Duration(interval)*time.Second, time.Duration(to)*time.Second, 2, healthStop)
		go func() {
			for ev := range state.mgr.Events() {
				fyne.Do(func() {
					status.SetText(fmt.Sprintf("[%s] %s", ev.EndpointID, ev.Message))
					refreshTables()
				})
			}
		}()
	}

	// runCheckPhase проверяет серверы ядром sing-box (один процесс на всю
	// пачку): каждая проверка — реальный HTTPS-запрос через сервер. Затем
	// (опционально) определяет выходной IP у живых.
	runCheckPhase := func(servers []node.Node) []node.Node {
		var supported []node.Node
		skippedReasons := map[string]int{}
		for _, s := range servers {
			if err := node.Validate(s); err != nil {
				skippedReasons[s.Proto]++
				continue
			}
			supported = append(supported, s)
		}
		if len(skippedReasons) > 0 {
			log.Printf("пропущено %d серверов с некорректными параметрами: %v", len(servers)-len(supported), skippedReasons)
		}
		finish := func(msg string) {
			fyne.Do(func() {
				status.SetText(msg)
				progress.Hide()
				runBtn.Enable()
				recheckBtn.Enable()
			})
		}
		if len(supported) == 0 {
			finish("Нет серверов с корректными параметрами.")
			return nil
		}
		conc := parseIntDefault(concurrencyEntry.Text, 50)
		if sequentialCheck.Checked {
			conc = 1
		}
		to := parseIntDefault(timeoutEntry.Text, 5)

		fyne.Do(func() {
			status.SetText(fmt.Sprintf("Запускаю ядро и загружаю %d серверов...", len(supported)))
		})
		lab, err := state.newLab(supported, 8)
		if err != nil {
			log.Printf("ядро: %v", err)
			finish("Ошибка ядра sing-box: " + err.Error())
			return nil
		}
		defer lab.Close()

		fyne.Do(func() {
			status.SetText(fmt.Sprintf("Проверяю %d серверов (реальный HTTPS-запрос через каждый)...", len(supported)))
		})
		results := lab.CheckAll(context.Background(), supported, conc, time.Duration(to)*time.Second, func(done, total int, r engine.Result) {
			fyne.Do(func() { progress.SetValue(float64(done) / float64(total)) })
		})
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].Alive != results[j].Alive {
				return results[i].Alive
			}
			return results[i].Latency < results[j].Latency
		})
		var aliveFinal []engine.Result
		for _, r := range results {
			if r.Alive {
				aliveFinal = append(aliveFinal, r)
			}
		}
		state.setFromResults(results)
		refreshTables()

		// выходной IP — только для живых; не влияет на статус жив/мёртв/умер
		if exitIPCheck.Checked && len(aliveFinal) > 0 {
			fyne.Do(func() {
				status.SetText(fmt.Sprintf("Определяю выходной IP для %d серверов...", len(aliveFinal)))
			})
			var wg sync.WaitGroup
			sem := make(chan struct{}, 8)
			for _, r := range aliveFinal {
				wg.Add(1)
				sem <- struct{}{}
				go func(srv node.Node) {
					defer wg.Done()
					defer func() { <-sem }()
					ip, err := lab.ExitIP(context.Background(), srv, time.Duration(to)*time.Second)
					if err != nil && debugflag.Enabled() {
						log.Printf("[exitip] %s: %v", srv.Label(), err)
					}
					state.mu.Lock()
					for _, row := range state.rows {
						if row.server.ID() == srv.ID() {
							row.exitIPAttempted = true
							if err == nil {
								row.exitIP = ip
								row.exitIPDone = true
							}
						}
					}
					state.mu.Unlock()
					fyne.Do(refreshTables)
				}(r.Node)
			}
			wg.Wait()
		}

		skippedNote := ""
		if n := len(servers) - len(supported); n > 0 {
			skippedNote = fmt.Sprintf(" (+ %d пропущено — некорректные параметры)", n)
		}
		fyne.Do(func() {
			refreshTables()
			progress.Hide()
			status.SetText(fmt.Sprintf("Готово: %d рабочих из %d проверенных%s.", len(aliveFinal), len(results), skippedNote))
			runBtn.Enable()
			recheckBtn.Enable()
			if healthCheck.Checked {
				startHealthLoop()
			}
		})
		saveSoon()

		var finalServers []node.Node
		for _, r := range aliveFinal {
			finalServers = append(finalServers, r.Node)
		}
		return finalServers
	}

	doScan := func() {
		runBtn.Disable()
		recheckBtn.Disable()
		status.SetText("Загружаю источники...")
		progress.Show()
		progress.SetValue(0)

		go func() {
			fetched := sources.FetchAll(sources.Default, 20*time.Second)
			var all []node.Node
			seen := map[string]bool{}
			for _, fr := range fetched {
				if fr.Err != nil {
					continue
				}
				for _, s := range node.ExtractAll(fr.Body) {
					if seen[s.ID()] {
						continue
					}
					seen[s.ID()] = true
					all = append(all, s)
				}
			}

			// подмешиваем закладки — они должны освежаться вместе со
			// всеми, а не "вымываться" из списка при новом скане
			for _, bs := range state.bookmarkedServersForMerge() {
				if !seen[bs.ID()] {
					seen[bs.ID()] = true
					all = append(all, bs)
				}
			}

			if len(all) == 0 {
				fyne.Do(func() {
					status.SetText("Не удалось получить ни одного сервера из источников.")
					progress.Hide()
					runBtn.Enable()
					recheckBtn.Enable()
				})
				return
			}

			runCheckPhase(all)
		}()
	}

	runBtn = widget.NewButton("Загрузить и проверить", func() { doScan() })

	recheckBtn = widget.NewButton("Перепроверить", func() {
		var servers []node.Node
		if activeTab == 1 {
			servers = state.bookmarkServers()
		} else {
			servers = state.allServers()
		}
		if len(servers) == 0 {
			dialog.ShowInformation("Нет данных", "Список пуст — нечего перепроверять.", w)
			return
		}
		runBtn.Disable()
		recheckBtn.Disable()
		status.SetText(fmt.Sprintf("Перепроверяю %d серверов (без повторной загрузки источников)...", len(servers)))
		progress.Show()
		progress.SetValue(0)
		go runCheckPhase(servers)
	})

	exportFunc := func(onlySelected bool) {
		var srvs []node.Node
		if onlySelected {
			srvs = state.selectedServers()
		} else {
			for _, r := range state.rowsSnapshot() {
				if r.status == statusAlive {
					srvs = append(srvs, r.server)
				}
			}
		}
		if len(srvs) == 0 {
			dialog.ShowInformation("Нет данных", "Список пуст — нечего сохранять.", w)
			return
		}
		saveDialog := dialog.NewFileSave(func(uc fyne.URIWriteCloser, err error) {
			if err != nil || uc == nil {
				return
			}
			defer uc.Close()
			path := uc.URI().Path()
			if err := config.Write(path, srvs); err != nil {
				dialog.ShowError(err, w)
				return
			}
			dialog.ShowInformation("Готово", fmt.Sprintf("Сохранено: %s (%d серверов)", path, len(srvs)), w)
		}, w)
		saveDialog.SetFileName("proxies.txt")
		saveDialog.Show()
	}
	exportAllBtn = widget.NewButton("Экспорт всех рабочих", func() { exportFunc(false) })
	exportSelectedBtn = widget.NewButton("Экспорт отмеченных ✓", func() { exportFunc(true) })

	// runSpeedtestOn — общая логика замера download+upload скорости для
	// списка серверов (используется и основной вкладкой, и закладками).
	runSpeedtestOn := func(servers []node.Node) {
		speedtestBtn.Disable()
		status.SetText("Замер скорости...")
		go func() {
			to := parseIntDefault(timeoutEntry.Text, 5)
			endMsg := func(m string) {
				fyne.Do(func() {
					status.SetText(m)
					speedtestBtn.Enable()
				})
			}
			// одна линия: замеры идут строго по очереди, чтобы серверы не
			// мешали друг другу полосой канала — иначе числа плавают
			lab, err := state.newLab(servers, 1)
			if err != nil {
				endMsg("Ошибка ядра sing-box: " + err.Error())
				return
			}
			defer lab.Close()
			for _, srv := range servers {
				// предпроверка живости: сервер мог умереть между сканами
				if _, err := lab.Delay(context.Background(), srv, engine.DefaultTestURL, time.Duration(to)*time.Second); err != nil {
					if debugflag.Enabled() {
						log.Printf("[speedtest] %s: предпроверка не прошла, пропускаю: %v", srv.Label(), err)
					}
					fyne.Do(func() {
						for _, r := range state.rowsSnapshot() {
							if r.server.ID() == srv.ID() {
								state.mu.Lock()
								r.status = nextStatus(r.status, false)
								r.speedAttempted = true
								state.mu.Unlock()
							}
						}
						refreshTables()
						status.SetText(fmt.Sprintf("%s: перестал отвечать, замер скорости пропущен.", srv.Label()))
					})
					saveSoon()
					continue
				}
				fyne.Do(func() { status.SetText(fmt.Sprintf("Замер скорости: %s...", srv.Label())) })
				down, up, derr, ulErr := lab.Speed(context.Background(), srv, true, 20*time.Second)
				fyne.Do(func() {
					for _, r := range state.rowsSnapshot() {
						if r.server.ID() == srv.ID() {
							state.mu.Lock()
							r.speedAttempted = true
							if derr == nil {
								r.speedMbps = down.Mbps
								r.speedDone = true
								r.ulSpeedAttempted = true
								if ulErr == nil {
									r.ulSpeedMbps = up.Mbps
									r.ulSpeedDone = true
								}
							}
							state.mu.Unlock()
						}
					}
					refreshTables()
					if derr != nil {
						status.SetText(fmt.Sprintf("%s: ошибка замера скорости: %v", srv.Label(), derr))
					}
				})
				saveSoon()
			}
			endMsg("Замер скорости завершён.")
		}()
	}

	speedtestBtn = widget.NewButton("Замер скорости отмеченных ✓", func() {
		var servers []node.Node
		if activeTab == 1 {
			servers = state.selectedBookmarkServers()
		} else {
			servers = state.selectedServers()
		}
		if len(servers) == 0 {
			dialog.ShowInformation("Нет данных", "Отметьте галочками сервера для замера скорости.", w)
			return
		}
		runSpeedtestOn(servers)
	})

	recheckSpeedBtn = widget.NewButton("Перепроверить и измерить скорость", func() {
		var servers []node.Node
		if activeTab == 1 {
			servers = state.bookmarkServers()
		} else {
			servers = state.allServers()
		}
		if len(servers) == 0 {
			dialog.ShowInformation("Нет данных", "Список пуст — нечего перепроверять.", w)
			return
		}
		runBtn.Disable()
		recheckBtn.Disable()
		recheckSpeedBtn.Disable()
		status.SetText(fmt.Sprintf("Перепроверяю %d серверов...", len(servers)))
		progress.Show()
		progress.SetValue(0)
		go func() {
			final := runCheckPhase(servers)
			if len(final) > 0 {
				runSpeedtestOn(final) // именно "всех" прошедших проверку, а не только отмеченных
			}
			fyne.Do(func() { recheckSpeedBtn.Enable() })
		}()
	})

	stopAllBtn = widget.NewButton("Остановить все прокси", func() {
		state.mgr.StopAll()
		for _, r := range state.rowsSnapshot() {
			state.mu.Lock()
			r.running = false
			state.mu.Unlock()
		}
		refreshTables()
		saveSoon()
	})

	minimizeBtn := widget.NewButton("Свернуть в трей", func() {
		if trayDetector.Failed() {
			dialog.ShowInformation("Трей недоступен",
				"На этой машине не удалось инициализировать иконку в системном трее "+
					"(ошибка драйвера/окружения — не то, что можно починить в самой программе).\n\n"+
					"Сворачивание в трей отключено, чтобы окно не стало недоступным без "+
					"завершения процесса через диспетчер задач. Просто сверни окно обычным "+
					"способом (кнопка в заголовке) или оставь его открытым.", w)
			return
		}
		w.Hide()
		go state.saveSettings()
	})

	quitBtn := widget.NewButton("Выход", func() {
		dialog.ShowConfirm("Выход", "Остановить все прокси и закрыть программу?", func(confirmed bool) {
			if !confirmed {
				return
			}
			state.mgr.StopAll()
			state.mu.Lock()
			if state.dnsResolver != nil {
				state.dnsResolver.Stop()
			}
			state.mu.Unlock()
			_ = state.saveSettings()
			a.Quit()
		}, w)
	})

	// --- локальный DNS: toggle через кнопку в строке сервера ---
	// detectExitIPFor определяет выходной IP ОДНОГО сервера в фоне и
	// обновляет соответствующую строку таблицы — используется и при
	// ручном запуске прокси кнопкой "Старт", и при авто-старте
	// сохранённых профилей на запуске программы (выходной IP мог
	// поменяться с прошлой сессии, поэтому обновляем заново, а не
	// полагаемся на значение из settings.json).
	detectExitIPFor := func(srv node.Node) {
		if !exitIPCheck.Checked {
			return
		}
		go func() {
			to := parseIntDefault(timeoutEntry.Text, 5)
			var ip string
			var err error
			if p, running := state.runningPortFor(srv.ID()); running {
				ip, err = engine.ExitIPViaSocks(context.Background(), fmt.Sprintf("127.0.0.1:%d", p), time.Duration(to)*time.Second)
			} else if lab, lerr := state.newLab([]node.Node{srv}, 1); lerr != nil {
				err = lerr
			} else {
				ip, err = lab.ExitIP(context.Background(), srv, time.Duration(to)*time.Second)
				lab.Close()
			}
			if err != nil {
				if debugflag.Enabled() {
					log.Printf("[exitip] %s: %v", srv.Label(), err)
				}
				for _, row := range state.rowsSnapshot() {
					if row.server.ID() == srv.ID() {
						state.mu.Lock()
						row.exitIPAttempted = true
						state.mu.Unlock()
					}
				}
				fyne.Do(refreshTables)
				return
			}
			for _, row := range state.rowsSnapshot() {
				if row.server.ID() == srv.ID() {
					state.mu.Lock()
					row.exitIP = ip
					row.exitIPDone = true
					row.exitIPAttempted = true
					state.mu.Unlock()
				}
			}
			fyne.Do(refreshTables)
			saveSoon()
		}()
	}

	toggleDNS := func(srv node.Node) {
		state.mu.Lock()
		current := state.dnsServerID
		state.mu.Unlock()

		if current == srv.ID() {
			state.mu.Lock()
			if state.dnsResolver != nil {
				state.dnsResolver.Stop()
				state.dnsResolver = nil
			}
			state.dnsServerID = ""
			state.mu.Unlock()
			status.SetText("Локальный DNS остановлен.")
			refreshTables()
			return
		}

		go func() {
			state.mu.Lock()
			if state.dnsResolver != nil {
				state.dnsResolver.Stop()
				state.dnsResolver = nil
			}
			state.mu.Unlock()

			to := parseIntDefault(timeoutEntry.Text, 5)
			port, running := state.runningPortFor(srv.ID())
			if !running {
				fyne.Do(func() {
					status.SetText("Для локального DNS сначала запустите этот прокси.")
				})
				return
			}
			resolver, err := localdns.Start("127.0.0.1:53", fmt.Sprintf("127.0.0.1:%d", port), srv, time.Duration(to)*time.Second)
			if err != nil {
				// именно то поведение, которое просили: не падаем и не
				// уходим в ошибку, просто сообщаем и продолжаем работать
				log.Printf("не удалось запустить локальный DNS (порт 53 занят другой программой?): %v", err)
				fyne.Do(func() {
					status.SetText("Не удалось запустить локальный DNS — порт 53 занят другой программой.")
				})
				return
			}
			state.mu.Lock()
			state.dnsResolver = resolver
			state.dnsServerID = srv.ID()
			state.mu.Unlock()
			fyne.Do(func() {
				status.SetText(fmt.Sprintf("Локальный DNS запущен через %s.", srv.Label()))
				refreshTables()
			})
		}()
	}

	// --- главная таблица (вкладка "Сервера") ---
	// --- сортировка главной таблицы по клику на заголовок столбца ---
	mainSortCol := -1
	mainSortAsc := true
	compareMainCol := func(a, b *rowState, col int) int {
		switch col {
		case 1:
			return cmpStrings(displayName(a), displayName(b))
		case 2:
			return cmpStrings(a.server.Addr(), b.server.Addr())
		case 3:
			return cmpStrings(a.server.Summary(), b.server.Summary())
		case 4:
			return cmpInt(int(a.status), int(b.status))
		case 5:
			return cmpDuration(a.latency, b.latency)
		case 6:
			return cmpFloat(a.speedMbps, b.speedMbps)
		case 7:
			return cmpFloat(a.ulSpeedMbps, b.ulSpeedMbps)
		case 8:
			return cmpStrings(a.exitIP, b.exitIP)
		case 10:
			return cmpBool(a.bookmarked, b.bookmarked)
		case 11:
			return cmpBool(a.running, b.running)
		default:
			return 0
		}
	}
	sortedMainRows := func() []*rowState {
		rows := state.rowsSnapshot()
		out := append([]*rowState(nil), rows...)
		sort.SliceStable(out, func(i, j int) bool {
			// отмеченные галочкой — всегда сверху, независимо от
			// выбранной сортировки столбца
			if out[i].selected != out[j].selected {
				return out[i].selected
			}
			// запущенные прокси — вторым уровнем закрепления, тоже
			// сверху независимо от сортировки (кроме отмеченных выше)
			if out[i].running != out[j].running {
				return out[i].running
			}
			if mainSortCol < 0 {
				return false
			}
			c := compareMainCol(out[i], out[j], mainSortCol)
			if !mainSortAsc {
				c = -c
			}
			return c < 0
		})
		return out
	}

	mainTable = widget.NewTable(
		func() (int, int) { return len(sortedMainRows()) + 1, mainNumCols },
		func() fyne.CanvasObject {
			chk := widget.NewCheck("", nil)
			lbl := widget.NewLabel("")
			lbl.Truncation = fyne.TextTruncateEllipsis
			btn := widget.NewButton("", nil)
			return container.NewStack(chk, lbl, btn)
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			stack := obj.(*fyne.Container)
			chk := stack.Objects[0].(*widget.Check)
			lbl := stack.Objects[1].(*widget.Label)
			btn := stack.Objects[2].(*widget.Button)
			chk.Hide()
			lbl.Hide()
			btn.Hide()

			headers := []string{"✓", "Имя", "Адрес:порт", "Метод", "Статус", "Задержка", "↓", "↑", "IP", "DNS", "★", "Прокси"}
			if id.Row == 0 {
				lbl.Show()
				text := headers[id.Col]
				if id.Col == mainSortCol {
					if mainSortAsc {
						text += " ▲"
					} else {
						text += " ▼"
					}
				}
				lbl.SetText(text)
				lbl.TextStyle = fyne.TextStyle{Bold: true}
				return
			}

			rows := sortedMainRows()
			if id.Row-1 >= len(rows) {
				return
			}
			r := rows[id.Row-1]

			switch id.Col {
			case 0:
				chk.Show()
				// ВАЖНО: SetChecked вызывает OnChanged, если значение
				// отличается от текущего внутреннего состояния виджета —
				// а сам виджет переиспользуется между строками при
				// скролле (виртуализация таблицы). Если сначала вызвать
				// SetChecked, а потом переназначить OnChanged, можем
				// словить СТАРЫЙ колбэк, всё ещё привязанный к предыдущей
				// строке — и он молча испортит чужую галочку. Поэтому
				// сначала обнуляем колбэк, потом меняем значение, потом
				// вешаем новый колбэк.
				chk.OnChanged = nil
				chk.SetChecked(r.selected)
				chk.OnChanged = func(v bool) {
					state.mu.Lock()
					r.selected = v
					state.mu.Unlock()
					saveSoon()
				}
			case 1:
				lbl.Show()
				name := r.server.Name
				if name == "" {
					name = r.server.Label()
				}
				lbl.SetText(name)
			case 2:
				lbl.Show()
				lbl.SetText(r.server.Addr())
			case 3:
				lbl.Show()
				lbl.SetText(r.server.Summary())
			case 4:
				lbl.Show()
				lbl.SetText(r.status.text())
			case 5:
				lbl.Show()
				if r.status == statusAlive {
					lbl.SetText(r.latency.Round(time.Millisecond).String())
				} else {
					lbl.SetText("—")
				}
			case 6:
				lbl.Show()
				switch {
				case r.speedDone:
					lbl.SetText(fmt.Sprintf("%.1f", r.speedMbps))
				case r.speedAttempted:
					lbl.SetText("ошибка")
				default:
					lbl.SetText("—")
				}
			case 7:
				lbl.Show()
				switch {
				case r.ulSpeedDone:
					lbl.SetText(fmt.Sprintf("%.1f", r.ulSpeedMbps))
				case r.ulSpeedAttempted:
					lbl.SetText("ошибка")
				default:
					lbl.SetText("—")
				}
			case 8:
				lbl.Show()
				switch {
				case r.exitIPDone:
					lbl.SetText(r.exitIP)
				case r.exitIPAttempted:
					lbl.SetText("ошибка")
				default:
					lbl.SetText("—")
				}
			case 9:
				btn.Show()
				rCopy := r
				state.mu.Lock()
				isDNS := state.dnsServerID == rCopy.server.ID()
				state.mu.Unlock()
				if isDNS {
					btn.SetText("DNS ✓")
				} else {
					btn.SetText("DNS")
				}
				btn.OnTapped = func() { toggleDNS(rCopy.server) }
			case 10:
				btn.Show()
				rCopy := r
				if rCopy.bookmarked {
					btn.SetText("★")
				} else {
					btn.SetText("☆")
				}
				btn.OnTapped = func() {
					state.mu.Lock()
					rCopy.bookmarked = !rCopy.bookmarked
					state.mu.Unlock()
					refreshTables()
					saveSoon()
				}
			case 11:
				btn.Show()
				rCopy := r
				if rCopy.running {
					btn.SetText(fmt.Sprintf("Стоп (:%d)", rCopy.localPort))
					btn.OnTapped = func() {
						state.mgr.Stop(rCopy.endpointID)
						state.mu.Lock()
						rCopy.running = false
						state.mu.Unlock()
						refreshTables()
						saveSoon()
					}
				} else {
					btn.SetText("Старт")
					btn.OnTapped = func() {
						desired := rCopy.localPort
						if desired <= 0 {
							state.mu.Lock()
							desired = state.startPort
							state.mu.Unlock()
						}
						ep, err := state.mgr.Start(rCopy.server, desired)
						if err != nil {
							dialog.ShowError(err, w)
							return
						}
						state.mu.Lock()
						rCopy.running = true
						rCopy.localPort = ep.LocalPort
						rCopy.endpointID = rCopy.server.ID()
						state.mu.Unlock()
						refreshTables()
						saveSoon()
						detectExitIPFor(rCopy.server)
					}
				}
			}
		},
	)
	mainTable.SetColumnWidth(0, 34)
	mainTable.SetColumnWidth(1, 220)
	mainTable.SetColumnWidth(2, 210)
	mainTable.SetColumnWidth(3, 190)
	mainTable.SetColumnWidth(4, 60)
	mainTable.SetColumnWidth(5, 80)
	mainTable.SetColumnWidth(6, 55)
	mainTable.SetColumnWidth(7, 55)
	mainTable.SetColumnWidth(8, 150)
	mainTable.SetColumnWidth(9, 60)
	mainTable.SetColumnWidth(10, 40)
	mainTable.SetColumnWidth(11, 120)
	mainTable.OnSelected = func(id widget.TableCellID) {
		mainTable.Unselect(id)
		if id.Row != 0 {
			return // сортировка только по клику на заголовок, не на данные
		}
		sortable := map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 10: true, 11: true}
		if !sortable[id.Col] {
			return
		}
		if mainSortCol == id.Col {
			mainSortAsc = !mainSortAsc
		} else {
			mainSortCol = id.Col
			mainSortAsc = true
		}
		mainTable.Refresh()
	}

	// --- таблица закладок (вкладка "Закладки") ---
	bookmarkSortCol := -1
	bookmarkSortAsc := true
	compareBookmarkCol := func(a, b *rowState, col int) int {
		switch col {
		case 1:
			return cmpStrings(displayName(a), displayName(b))
		case 2:
			return cmpStrings(a.server.Addr(), b.server.Addr())
		case 4:
			return cmpInt(int(a.status), int(b.status))
		case 5:
			return cmpDuration(a.latency, b.latency)
		default:
			return 0
		}
	}
	sortedBookmarkRows := func() []*rowState {
		rows := bookmarkedRows()
		out := append([]*rowState(nil), rows...)
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].selected != out[j].selected {
				return out[i].selected
			}
			if bookmarkSortCol < 0 {
				return false
			}
			c := compareBookmarkCol(out[i], out[j], bookmarkSortCol)
			if !bookmarkSortAsc {
				c = -c
			}
			return c < 0
		})
		return out
	}

	bookmarkTable = widget.NewTable(
		func() (int, int) { return len(sortedBookmarkRows()) + 1, bookmarkNumCols },
		func() fyne.CanvasObject {
			chk := widget.NewCheck("", nil)
			lbl := widget.NewLabel("")
			lbl.Truncation = fyne.TextTruncateEllipsis
			btn := widget.NewButton("", nil)
			entry := widget.NewEntry()
			return container.NewStack(chk, lbl, btn, entry)
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			stack := obj.(*fyne.Container)
			chk := stack.Objects[0].(*widget.Check)
			lbl := stack.Objects[1].(*widget.Label)
			btn := stack.Objects[2].(*widget.Button)
			entry := stack.Objects[3].(*widget.Entry)
			chk.Hide()
			lbl.Hide()
			btn.Hide()
			entry.Hide()

			headers := []string{"✓", "Имя", "Адрес:порт", "Комментарий", "Статус", "Задержка", "Прокси", "Убрать"}
			if id.Row == 0 {
				lbl.Show()
				text := headers[id.Col]
				if id.Col == bookmarkSortCol {
					if bookmarkSortAsc {
						text += " ▲"
					} else {
						text += " ▼"
					}
				}
				lbl.SetText(text)
				lbl.TextStyle = fyne.TextStyle{Bold: true}
				return
			}

			rows := sortedBookmarkRows()
			if id.Row-1 >= len(rows) {
				return
			}
			r := rows[id.Row-1]

			switch id.Col {
			case 0:
				chk.Show()
				chk.OnChanged = nil
				chk.SetChecked(r.selected)
				chk.OnChanged = func(v bool) {
					state.mu.Lock()
					r.selected = v
					state.mu.Unlock()
					saveSoon()
				}
			case 1:
				lbl.Show()
				name := r.server.Name
				if name == "" {
					name = r.server.Label()
				}
				lbl.SetText(name)
			case 2:
				lbl.Show()
				lbl.SetText(r.server.Addr())
			case 3:
				entry.Show()
				entry.OnChanged = nil
				entry.SetText(r.comment)
				rCopy := r
				entry.OnChanged = func(v string) {
					state.mu.Lock()
					rCopy.comment = v
					state.mu.Unlock()
				}
				// сохраняем при потере фокуса, а не на каждый символ
				entry.OnSubmitted = func(v string) { saveSoon() }
			case 4:
				lbl.Show()
				lbl.SetText(r.status.text())
			case 5:
				lbl.Show()
				if r.status == statusAlive {
					lbl.SetText(r.latency.Round(time.Millisecond).String())
				} else {
					lbl.SetText("—")
				}
			case 6:
				btn.Show()
				rCopy := r
				if rCopy.running {
					btn.SetText(fmt.Sprintf("Стоп (:%d)", rCopy.localPort))
					btn.OnTapped = func() {
						state.mgr.Stop(rCopy.endpointID)
						state.mu.Lock()
						rCopy.running = false
						state.mu.Unlock()
						refreshTables()
						saveSoon()
					}
				} else {
					btn.SetText("Старт")
					btn.OnTapped = func() {
						desired := rCopy.localPort
						if desired <= 0 {
							state.mu.Lock()
							desired = state.startPort
							state.mu.Unlock()
						}
						ep, err := state.mgr.Start(rCopy.server, desired)
						if err != nil {
							dialog.ShowError(err, w)
							return
						}
						state.mu.Lock()
						rCopy.running = true
						rCopy.localPort = ep.LocalPort
						rCopy.endpointID = rCopy.server.ID()
						state.mu.Unlock()
						refreshTables()
						saveSoon()
						detectExitIPFor(rCopy.server)
					}
				}
			case 7:
				btn.Show()
				btn.SetText("Убрать")
				rCopy := r
				btn.OnTapped = func() {
					state.mu.Lock()
					rCopy.bookmarked = false
					rCopy.comment = ""
					state.mu.Unlock()
					refreshTables()
					saveSoon()
				}
			}
		},
	)
	bookmarkTable.SetColumnWidth(0, 34)
	bookmarkTable.SetColumnWidth(1, 220)
	bookmarkTable.SetColumnWidth(2, 170)
	bookmarkTable.SetColumnWidth(3, 260)
	bookmarkTable.SetColumnWidth(4, 60)
	bookmarkTable.SetColumnWidth(5, 80)
	bookmarkTable.SetColumnWidth(6, 120)
	bookmarkTable.SetColumnWidth(7, 90)
	bookmarkTable.OnSelected = func(id widget.TableCellID) {
		bookmarkTable.Unselect(id)
		if id.Row != 0 {
			return
		}
		sortable := map[int]bool{1: true, 2: true, 4: true, 5: true}
		if !sortable[id.Col] {
			return
		}
		if bookmarkSortCol == id.Col {
			bookmarkSortAsc = !bookmarkSortAsc
		} else {
			bookmarkSortCol = id.Col
			bookmarkSortAsc = true
		}
		bookmarkTable.Refresh()
	}

	settingsRow := container.NewHBox(
		widget.NewLabel("Потоков:"), concurrencyEntry,
		widget.NewLabel("Таймаут (сек):"), timeoutEntry,
		widget.NewLabel("Интервал проверки (сек):"), container.NewGridWrap(fyne.NewSize(60, 34), healthIntervalEntry),
		widget.NewLabel("Стартовый порт:"), container.NewGridWrap(fyne.NewSize(60, 34), startPortEntry),
	)
	checksRow := container.NewHBox(
		sequentialCheck, healthCheck, exitIPCheck, startMinimizedCheck, runBtn, recheckBtn,
	)
	actionsRow := container.NewHBox(exportAllBtn, exportSelectedBtn, speedtestBtn, recheckSpeedBtn, stopAllBtn, minimizeBtn, quitBtn)

	mainTabContent := container.NewBorder(
		container.NewVBox(settingsRow, checksRow, actionsRow, progress, status),
		nil, nil, nil,
		mainTable,
	)

	bookmarksTabContent := container.NewBorder(
		container.NewVBox(actionsRow, progress, status),
		nil, nil, nil,
		bookmarkTable,
	)

	logsTab := container.NewBorder(
		container.NewHBox(widget.NewButton("Очистить", func() {
			lb.mu.Lock()
			lb.lines = nil
			lb.mu.Unlock()
			logText.SetText("")
		})),
		nil, nil, nil,
		container.NewScroll(logText),
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Сервера", mainTabContent),
		container.NewTabItem("Закладки", bookmarksTabContent),
		container.NewTabItem("Логи", logsTab),
	)
	tabs.OnSelected = func(item *container.TabItem) {
		switch item.Text {
		case "Сервера":
			activeTab = 0
		case "Закладки":
			activeTab = 1
			refreshTables()
		case "Логи":
			activeTab = 2
		}
	}
	w.SetContent(tabs)

	// системный трей: сворачиваем в трей вместо закрытия окна
	if desk, ok := a.(desktop.App); ok {
		menu := fyne.NewMenu("Shadowsocks Proxy Checker",
			fyne.NewMenuItem("Показать окно", func() { w.Show() }),
			fyne.NewMenuItem("Остановить все прокси", func() { stopAllBtn.OnTapped() }),
			fyne.NewMenuItem("Выход", func() {
				state.mgr.StopAll()
				state.mu.Lock()
				if state.dnsResolver != nil {
					state.dnsResolver.Stop()
				}
				state.mu.Unlock()
				_ = state.saveSettings()
				a.Quit()
			}),
		)
		desk.SetSystemTrayMenu(menu)
		if icon := appIcon(); icon != nil {
			desk.SetSystemTrayIcon(icon)
		}
		// клик по иконке в трее сразу показывает окно — без этого
		// пришлось бы каждый раз лезть в меню правой кнопкой
		desk.SetSystemTrayWindow(w)
		w.SetCloseIntercept(func() {
			if trayDetector.Failed() {
				// прятать окно некуда — трея реально нет, поэтому
				// крестик ведёт себя как обычное закрытие программы
				// (с тем же подтверждением, что и кнопка "Выход"),
				// а не молча прячет окно в несуществующий трей
				quitBtn.OnTapped()
				return
			}
			w.Hide()
			go state.saveSettings()
		})
	}

	// --- загрузка сохранённых настроек и восстановление прошлой сессии ---
	savedSettings := state.loadSettings()
	healthIntervalEntry.SetText(fmt.Sprintf("%d", state.healthIntervalSec))
	startPortEntry.SetText(fmt.Sprintf("%d", state.startPort))
	exitIPCheck.SetChecked(state.detectExitIP)
	startMinimizedCheck.SetChecked(state.startMinimized)

	// Windows: одно входящее правило файрвола на весь диапазон портов
	go func() {
		rangeStart := state.startPort
		rangeEnd := rangeStart + 99
		if err := firewall.EnsureInboundRule("proxycheck (SOCKS5)", rangeStart, rangeEnd); err != nil {
			log.Printf("не удалось настроить правило файрвола (%d-%d): %v — если нужен доступ из локальной сети, запусти программу от имени администратора", rangeStart, rangeEnd, err)
		} else {
			log.Printf("правило файрвола для портов %d-%d готово", rangeStart, rangeEnd)
		}
	}()

	if len(savedSettings.LastScanServers) > 0 || len(savedSettings.Profiles) > 0 || len(savedSettings.Bookmarks) > 0 {
		state.loadRowsFromSettings(savedSettings)
		refreshTables()
		status.SetText(fmt.Sprintf("Восстановлено из прошлой сессии: %d серверов. Проверяю интернет...", len(savedSettings.LastScanServers)))

		go func() {
			to := parseIntDefault(timeoutEntry.Text, 5)

			if !checkInternet(time.Duration(to) * time.Second) {
				log.Printf("нет прямого соединения с интернетом — пропускаю перепроверку сохранённых серверов (это не значит, что они мертвы)")
				fyne.Do(func() {
					status.SetText("Нет соединения с интернетом — сохранённые сервера не перепроверены (попробуй позже кнопкой «Перепроверить»).")
				})
			} else {
				// перепроверяем "важные" сервера с прошлой сессии —
				// запущенные, в закладках, отмеченные галочкой — статус
				// корректно перейдёт в "умер", если сервер, который был
				// жив, перестал отвечать
				var important []node.Node
				seenImportant := map[string]bool{}
				for _, r := range state.rowsSnapshot() {
					if r.running || r.bookmarked || r.selected {
						if !seenImportant[r.server.ID()] {
							seenImportant[r.server.ID()] = true
							important = append(important, r.server)
						}
					}
				}
				if len(important) > 0 {
					fyne.Do(func() {
						status.SetText(fmt.Sprintf("Интернет есть. Перепроверяю %d сохранённых серверов...", len(important)))
					})
					if lab, lerr := state.newLab(important, 4); lerr != nil {
						log.Printf("[startup-recheck] ядро: %v", lerr)
					} else {
						res := lab.CheckAll(context.Background(), important, 20, time.Duration(to)*time.Second, nil)
						lab.Close()
						for _, r := range res {
							for _, row := range state.rowsSnapshot() {
								if row.server.ID() == r.Node.ID() {
									state.mu.Lock()
									row.status = nextStatus(row.status, r.Alive)
									state.mu.Unlock()
								}
							}
							if r.Alive {
								detectExitIPFor(r.Node)
							} else if debugflag.Enabled() {
								log.Printf("[startup-recheck] %s: %v", r.Node.Label(), r.Err)
							}
						}
					}
					saveSoon()
				}
			}

			// поднимаем сохранённые профили независимо от результата
			// проверки интернета выше — relay.Manager.Start просто
			// занимает локальный порт, для этого интернет не нужен;
			// как только сеть появится, health-мониторинг сам разберётся
			if len(savedSettings.Profiles) > 0 {
				started := 0
				for _, p := range savedSettings.Profiles {
					ep, err := state.mgr.Start(p.Server, p.LocalPort)
					if err != nil {
						log.Printf("не удалось поднять сохранённый профиль %s: %v", p.Server.ID(), err)
						continue
					}
					for _, r := range state.rowsSnapshot() {
						if r.server.ID() == p.Server.ID() {
							state.mu.Lock()
							r.running = true
							r.localPort = ep.LocalPort
							r.endpointID = p.Server.ID()
							r.profileID = p.ID
							state.mu.Unlock()
						}
					}
					started++
				}
				fyne.Do(func() {
					refreshTables()
					if started > 0 {
						status.SetText(fmt.Sprintf("Восстановлено и запущено %d прокси из прошлой сессии.", started))
						if healthCheck.Checked {
							startHealthLoop()
						}
					}
				})
			}
		}()
	} else if opts.AutoStart {
		go func() {
			time.Sleep(200 * time.Millisecond)
			fyne.Do(doScan)
		}()
	}

	startMinimized := opts.StartMinimized || state.startMinimized
	if startMinimized {
		w.Hide()
	} else {
		w.Show()
	}
	a.Run()
}

// logWriterStderr — обёртка, чтобы log-пакет продолжал писать и в
// стандартный поток ошибок, а не только в виджет логов.
type logWriterStderr struct{}

func (logWriterStderr) Write(p []byte) (int, error) {
	return stderrWrite(p)
}

// checkInternet — прямая проверка (БЕЗ какого-либо прокси), есть ли у
// компьютера вообще интернет. Используется перед перепроверкой
// сохранённых серверов на старте: если своего интернета нет, нет
// смысла (и нечестно) помечать все сохранённые прокси "умер" — дело
// не в них, а в том, что сеть ещё не поднялась (например, ноутбук
// только что проснулся, Wi-Fi ещё подключается).
func checkInternet(timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// displayName возвращает имя сервера для отображения — Remarks, если
// заданы, иначе адрес:порт. Используется и при отрисовке, и при
// сортировке по столбцу "Имя", чтобы сортировка совпадала с тем, что
// реально видно в таблице.
func displayName(r *rowState) string {
	if r.server.Name != "" {
		return r.server.Name
	}
	return r.server.Label()
}

func cmpStrings(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func cmpFloat(a, b float64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func cmpDuration(a, b time.Duration) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// cmpBool сортирует true перед false (например, закладки — сверху).
func cmpBool(a, b bool) int {
	if a == b {
		return 0
	}
	if a {
		return -1
	}
	return 1
}

func parseIntDefault(s string, def int) int {
	n := 0
	started := false
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		started = true
		n = n*10 + int(c-'0')
	}
	if !started || n <= 0 {
		return def
	}
	return n
}
