package gui

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"proxycheck/internal/engine"
	"proxycheck/internal/localdns"
	"proxycheck/internal/node"
	"proxycheck/internal/relay"
	"proxycheck/internal/settings"
)

// liveStatus — три состояния сервера вместо простого "жив/мёртв":
// это даёт видимость деградации — если сервер работал и перестал,
// пользователь сразу это видит, а не просто "мёртв" как у любого
// никогда не проверявшегося сервера.
type liveStatus int

const (
	statusUnknown liveStatus = iota // ещё ни разу не проверялся
	statusAlive                     // проверен, работает
	statusDead                      // проверен, никогда не был живым
	statusDied                      // БЫЛ живым, при повторной проверке перестал отвечать
)

func (s liveStatus) text() string {
	switch s {
	case statusAlive:
		return "жив"
	case statusDead:
		return "мёртв"
	case statusDied:
		return "умер"
	default:
		return "—"
	}
}

// nextStatus вычисляет новый статус по факту свежей проверки alive —
// именно тут рождается "умер": если раньше сервер был жив, а сейчас
// проверка провалилась, это не просто "мёртв", а деградация.
func nextStatus(prev liveStatus, aliveNow bool) liveStatus {
	if aliveNow {
		return statusAlive
	}
	if prev == statusAlive || prev == statusDied {
		return statusDied
	}
	return statusDead
}

func statusToString(s liveStatus) string {
	switch s {
	case statusAlive:
		return "alive"
	case statusDead:
		return "dead"
	case statusDied:
		return "died"
	default:
		return ""
	}
}

func statusFromString(s string, fallbackAlive bool) liveStatus {
	switch s {
	case "alive":
		return statusAlive
	case "dead":
		return statusDead
	case "died":
		return statusDied
	case "":
		// старый settings.json без поля Status — восстанавливаем из
		// булева Alive как раньше (без "умер", это нормально: у нас
		// просто ещё нет истории по этой записи)
		if fallbackAlive {
			return statusAlive
		}
		return statusDead
	default:
		return statusUnknown
	}
}

// rowState — состояние одной строки таблицы (один сервер). Одна и та
// же строка используется и на вкладке "Сервера" (все строки), и на
// вкладке "Закладки" (только помеченные bookmarked=true) — это единый
// источник данных, вкладки просто по-разному его отображают/фильтруют.
type rowState struct {
	server  node.Node
	status  liveStatus
	latency time.Duration

	selected bool // отмечен галочкой (для экспорта/замера скорости/перепроверки)

	running    bool // сейчас поднят локальный SOCKS5-вход на этот сервер
	localPort  int
	endpointID string // = server.ID(), используется для relay.Manager.Stop
	profileID  int    // стабильный ID профиля для settings.json (0 = ещё не назначен)

	speedMbps        float64 // скорость скачивания (download)
	speedDone        bool
	speedAttempted   bool    // была попытка (нужно отличать "ещё не мерили" от "мерили, но не вышло")
	ulSpeedMbps      float64 // скорость отдачи (upload)
	ulSpeedDone      bool
	ulSpeedAttempted bool

	exitIP          string
	exitIPDone      bool
	exitIPAttempted bool

	bookmarked bool
	comment    string
}

// appState — потокобезопасное хранилище состояния GUI.
type appState struct {
	mu   sync.Mutex
	rows []*rowState

	mgr *relay.Manager

	settingsPath      string
	nextProfileID     int
	healthIntervalSec int
	startPort         int
	startMinimized    bool
	detectExitIP      bool

	dnsResolver *localdns.Resolver
	dnsServerID string

	engCfg engine.Config
}

// newLab запускает ядро с серверами nodes для пакетной проверки.
func (s *appState) newLab(nodes []node.Node, lanes int) (*engine.Lab, error) {
	cfg, err := s.engineConfig()
	if err != nil {
		return nil, err
	}
	return engine.NewLab(cfg, nodes, lanes)
}

// engineConfig находит sing-box и готовит рабочий каталог.
func (s *appState) engineConfig() (engine.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engCfg.Binary == "" {
		bin, err := engine.FindBinary()
		if err != nil {
			return engine.Config{}, err
		}
		s.engCfg = engine.Config{
			Binary:  bin,
			WorkDir: filepath.Join(os.TempDir(), "proxycheck-sb"),
			Logf:    log.Printf,
		}
		s.mgr.SetEngine(s.engCfg)
	}
	return s.engCfg, nil
}

func newAppState() *appState {
	return &appState{
		mgr:               relay.NewManager(nil, 5*time.Second),
		settingsPath:      settings.DefaultPath(),
		nextProfileID:     1,
		healthIntervalSec: 20,
		startPort:         1080,
		detectExitIP:      true,
	}
}

// loadSettings читает settings.json (если есть) и возвращает
// разобранные данные — сама загрузка строк таблицы делается в gui.go.
func (s *appState) loadSettings() settings.Settings {
	st, err := settings.Load(s.settingsPath)
	if err != nil {
		return settings.Settings{DefaultHealthIntervalSec: 20, StartPort: 1080}
	}
	s.mu.Lock()
	if st.NextProfileID > 0 {
		s.nextProfileID = st.NextProfileID
	}
	if st.DefaultHealthIntervalSec > 0 {
		s.healthIntervalSec = st.DefaultHealthIntervalSec
	}
	if st.StartPort > 0 {
		s.startPort = st.StartPort
	}
	s.startMinimized = st.StartMinimized
	// DetectExitIP по умолчанию true при первом запуске (файла настроек
	// ещё не было) — дальше берём сохранённое значение как есть, даже
	// если пользователь его выключил.
	if fileExists(s.settingsPath) {
		s.detectExitIP = st.DetectExitIP
	} else {
		s.detectExitIP = true
	}
	s.mu.Unlock()
	return st
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// saveSettings сохраняет текущее состояние таблицы (сканы + активные
// профили + закладки) в settings.json.
func (s *appState) saveSettings() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := settings.Settings{
		NextProfileID:            s.nextProfileID,
		DefaultHealthIntervalSec: s.healthIntervalSec,
		StartPort:                s.startPort,
		StartMinimized:           s.startMinimized,
		DetectExitIP:             s.detectExitIP,
	}
	for _, r := range s.rows {
		out.LastScanServers = append(out.LastScanServers, settings.ScanRow{
			Server:           r.server,
			Alive:            r.status == statusAlive,
			Status:           statusToString(r.status),
			LatencyMs:        r.latency.Milliseconds(),
			Selected:         r.selected,
			ExitIP:           r.exitIP,
			SpeedMbps:        r.speedMbps,
			SpeedDone:        r.speedDone,
			SpeedAttempted:   r.speedAttempted,
			UlSpeedMbps:      r.ulSpeedMbps,
			UlSpeedDone:      r.ulSpeedDone,
			UlSpeedAttempted: r.ulSpeedAttempted,
		})
		if r.running {
			if r.profileID == 0 {
				r.profileID = s.nextProfileID
				s.nextProfileID++
			}
			out.Profiles = append(out.Profiles, settings.Profile{
				ID:        r.profileID,
				Server:    r.server,
				LocalPort: r.localPort,
				Enabled:   true,
			})
		}
		if r.bookmarked {
			out.Bookmarks = append(out.Bookmarks, settings.Bookmark{
				Server:  r.server,
				Comment: r.comment,
			})
		}
	}
	return settings.Save(s.settingsPath, out)
}

// loadRowsFromSettings восстанавливает строки таблицы из сохранённого
// скана (LastScanServers), помечая profileID/localPort у тех, что
// упомянуты в Profiles, и bookmarked/comment у тех, что есть в
// Bookmarks. НЕ поднимает сами прокси — это делает вызывающий код в
// gui.go, чтобы отследить ошибки Start по каждой отдельно.
func (s *appState) loadRowsFromSettings(st settings.Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()

	profileByID := make(map[string]settings.Profile, len(st.Profiles))
	for _, p := range st.Profiles {
		profileByID[p.Server.ID()] = p
	}
	bookmarkByID := make(map[string]settings.Bookmark, len(st.Bookmarks))
	for _, b := range st.Bookmarks {
		bookmarkByID[b.Server.ID()] = b
	}

	rows := make([]*rowState, 0, len(st.LastScanServers))
	seen := make(map[string]bool)
	for _, sr := range st.LastScanServers {
		r := &rowState{
			server:           sr.Server,
			status:           statusFromString(sr.Status, sr.Alive),
			latency:          time.Duration(sr.LatencyMs) * time.Millisecond,
			selected:         sr.Selected,
			exitIP:           sr.ExitIP,
			exitIPDone:       sr.ExitIP != "",
			exitIPAttempted:  sr.ExitIPAttempted || sr.ExitIP != "",
			speedMbps:        sr.SpeedMbps,
			speedDone:        sr.SpeedDone,
			speedAttempted:   sr.SpeedAttempted || sr.SpeedDone,
			ulSpeedMbps:      sr.UlSpeedMbps,
			ulSpeedDone:      sr.UlSpeedDone,
			ulSpeedAttempted: sr.UlSpeedAttempted || sr.UlSpeedDone,
		}
		if p, ok := profileByID[sr.Server.ID()]; ok {
			r.profileID = p.ID
			r.localPort = p.LocalPort
		}
		if b, ok := bookmarkByID[sr.Server.ID()]; ok {
			r.bookmarked = true
			r.comment = b.Comment
		}
		rows = append(rows, r)
		seen[sr.Server.ID()] = true
	}
	// добавляем профили и закладки, которых почему-то не было в
	// LastScanServers (например, файл настроек правили руками, или
	// закладка добавлена в сессии, где сервер не входил в свежий скан)
	for _, p := range st.Profiles {
		if seen[p.Server.ID()] {
			continue
		}
		rows = append(rows, &rowState{server: p.Server, profileID: p.ID, localPort: p.LocalPort})
		seen[p.Server.ID()] = true
	}
	for _, b := range st.Bookmarks {
		if seen[b.Server.ID()] {
			continue
		}
		rows = append(rows, &rowState{server: b.Server, bookmarked: true, comment: b.Comment})
		seen[b.Server.ID()] = true
	}

	s.rows = rows
	s.syncPool()
}

// syncPool обновляет резервный пул менеджера всеми живыми серверами —
// вызывать под уже захваченным s.mu.
func (s *appState) syncPool() {
	var pool []node.Node
	for _, r := range s.rows {
		if r.status == statusAlive {
			pool = append(pool, r.server)
		}
	}
	s.mgr.SetPool(pool)
}

func (s *appState) rowsSnapshot() []*rowState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*rowState, len(s.rows))
	copy(out, s.rows)
	return out
}

func (s *appState) selectedServers() []node.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []node.Node
	for _, r := range s.rows {
		if r.selected {
			out = append(out, r.server)
		}
	}
	return out
}

// selectedBookmarkServers — то же самое, но только среди закладок
// (используется вкладко-зависимой кнопкой замера скорости/перепроверки).
func (s *appState) selectedBookmarkServers() []node.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []node.Node
	for _, r := range s.rows {
		if r.bookmarked && r.selected {
			out = append(out, r.server)
		}
	}
	return out
}

// bookmarkServers — все сервера из закладок (для перепроверки без выбора).
func (s *appState) bookmarkServers() []node.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []node.Node
	for _, r := range s.rows {
		if r.bookmarked {
			out = append(out, r.server)
		}
	}
	return out
}

// allServers возвращает все сервера, сейчас отображённые в таблице —
// используется кнопкой "Перепроверить" (перечекать уже загруженный
// список без повторной загрузки источников).
func (s *appState) allServers() []node.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]node.Node, 0, len(s.rows))
	for _, r := range s.rows {
		out = append(out, r.server)
	}
	return out
}

// bookmarkedServersForMerge возвращает сервера из закладок, которые
// нужно ПОДМЕШАТЬ к свежесобранному списку из источников перед сканом
// — так закладки всегда остаются актуальными (перепроверяются вместе
// со всеми) и не "вымываются", даже если сервер пропал из источников.
func (s *appState) bookmarkedServersForMerge() []node.Node {
	return s.bookmarkServers()
}

// runningPortFor возвращает локальный порт уже запущенного (через
// кнопку "Старт" в таблице) прокси для данного сервера, если он есть.
// Используется замером скорости, чтобы не пытаться поднять второй
// (временный) endpoint поверх уже существующего.
func (s *appState) runningPortFor(serverID string) (port int, running bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.server.ID() == serverID && r.running {
			return r.localPort, true
		}
	}
	return 0, false
}

// findServerByID ищет сервер (node.Node) по ID среди текущих строк
// — используется при запуске локального DNS через конкретный сервер.
func (s *appState) findServerByID(id string) (node.Node, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.server.ID() == id {
			return r.server, true
		}
	}
	return node.Node{}, false
}

// setFromResults принимает ПОЛНЫЙ список результатов проверки (и живых,
// и мёртвых — не предфильтрованный). Для "важных" строк (уже запущен
// прокси, в закладках, или была отмечена галочкой в прошлый раз) —
// сохраняем даже если сервер сейчас не отвечает, с явным статусом
// "умер" (если раньше был жив) — это то самое отслеживание деградации,
// а не просто "мёртв", как у всех остальных мёртвых из массового скана,
// которых мы по-прежнему не держим в таблице (иначе список из
// публичных источников был бы завален шумом).
func (s *appState) setFromResults(results []engine.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevByID := make(map[string]*rowState, len(s.rows))
	for _, r := range s.rows {
		prevByID[r.server.ID()] = r
	}

	rows := make([]*rowState, 0, len(results))
	seen := make(map[string]bool, len(results))
	for _, r := range results {
		prev, hadPrev := prevByID[r.Node.ID()]
		important := hadPrev && (prev.running || prev.bookmarked || prev.selected)

		if !r.Alive && !important {
			seen[r.Node.ID()] = true // просмотрен, но не нужен в таблице
			continue
		}

		row := &rowState{
			server:  r.Node,
			latency: r.Latency,
		}
		prevStatus := statusUnknown
		if hadPrev {
			prevStatus = prev.status
			row.running = prev.running
			row.localPort = prev.localPort
			row.endpointID = prev.endpointID
			row.profileID = prev.profileID
			row.selected = prev.selected
			row.bookmarked = prev.bookmarked
			row.comment = prev.comment
			row.exitIP = prev.exitIP
			row.exitIPDone = prev.exitIPDone
		}
		row.status = nextStatus(prevStatus, r.Alive)
		rows = append(rows, row)
		seen[r.Node.ID()] = true
	}
	// добавляем запущенные прокси и закладки, которых вообще не было в
	// переданных результатах (например, метод не поддерживается и они
	// были отфильтрованы ещё до проверки) — не теряем их из виду
	for id, prev := range prevByID {
		if seen[id] {
			continue
		}
		if prev.running || prev.bookmarked {
			rows = append(rows, prev)
		}
	}

	s.rows = rows
	s.syncPool()
}
