// Package app — ядро приложения без интерфейса: список серверов, состояние
// «чем занят», запуск проверок, линий и замера скорости. Его используют все
// интерфейсы (веб, нативное окно Windows), сами они логики не содержат.
package app

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxycheck/internal/engine"
	"proxycheck/internal/geo"
	"proxycheck/internal/node"
	"proxycheck/internal/relay"
	"proxycheck/internal/settings"
	"proxycheck/internal/sources"
)

// Статусы сервера.
const (
	StatusUnknown = "unknown"
	StatusAlive   = "alive"
	StatusDead    = "dead"
	StatusDied    = "died" // был жив, при проверке перестал отвечать
)

// Состояния активности.
const (
	Idle     = "idle"
	Loading  = "loading"
	Checking = "checking"
	ExitIP   = "exitip"
	Speed    = "speed"
	Starting = "starting"
)

// Row — строка таблицы.
type Row struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Proto     string  `json:"proto"`
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	Status    string  `json:"status"`
	LatencyMs int64   `json:"latency_ms"`
	ExitIP    string  `json:"exit_ip,omitempty"`
	ExitErr   string  `json:"exit_err,omitempty"` // почему IP не определён
	SpeedErr  string  `json:"speed_err,omitempty"`
	Summary   string  `json:"summary"`
	Country   string  `json:"country,omitempty"` // ISO-код (по флагу в имени; позже — по базе IP)
	Running   bool    `json:"running"`
	LocalPort int     `json:"local_port,omitempty"`
	Selected  bool    `json:"selected"`
	SpeedMbps float64 `json:"speed_mbps,omitempty"`
	UlMbps    float64 `json:"ul_mbps,omitempty"`
	Pinned    bool    `json:"pinned,omitempty"`

	node node.Node
}

// Activity — чем приложение занято прямо сейчас.
type Activity struct {
	State  string    `json:"state"`
	Detail string    `json:"detail"`
	Done   int       `json:"done"`
	Total  int       `json:"total"`
	Since  time.Time `json:"since"`
}

// Line — активная линия (локальный порт -> сервер).
type Line struct {
	ID        string `json:"id"`
	LocalPort int    `json:"local_port"`
	Name      string `json:"name"`
	Current   string `json:"current_id"`
	Alive     bool   `json:"alive"`
}

// Snapshot — всё состояние для интерфейса одним объектом.
type Snapshot struct {
	Rows     []Row    `json:"rows"`
	Lines    []Line   `json:"lines"`
	Activity Activity `json:"activity"`
	Log      []string `json:"log"`
	Core     string   `json:"core"` // путь к sing-box или текст ошибки
	CoreOK   bool     `json:"core_ok"`
}

// App — состояние приложения. Потокобезопасно.
type App struct {
	mu   sync.Mutex
	rows []*Row
	act  Activity
	logs []string

	cancel   context.CancelFunc
	mgr      *relay.Manager
	engCfg   engine.Config
	coreErr  string
	settings settings.Settings
	path     string

	// Параметры проверки (из настроек интерфейса).
	Concurrency int
	TimeoutSec  int
	DetectExit  bool
}

// New создаёт приложение и загружает сохранённые настройки из path.
func New(settingsPath string) *App {
	a := &App{path: settingsPath, Concurrency: 50, TimeoutSec: 5, DetectExit: true,
		act: Activity{State: Idle, Since: time.Now()}}
	a.mgr = relay.NewManager(nil, 5*time.Second)
	st, err := settings.Load(settingsPath)
	if err == nil {
		a.settings = st
	} else {
		a.settings = settings.Settings{DefaultHealthIntervalSec: 20, StartPort: 1080}
	}
	for _, sr := range a.settings.LastScanServers {
		r := &Row{node: sr.Server, Status: normStatus(sr), LatencyMs: sr.LatencyMs, ExitIP: sr.ExitIP,
			Selected: sr.Selected, SpeedMbps: sr.SpeedMbps, UlMbps: sr.UlSpeedMbps, Pinned: sr.Pinned}
		fill(r)
		a.rows = append(a.rows, r)
	}
	if bin, err := engine.FindBinary(); err == nil {
		a.engCfg = engine.Config{Binary: bin, WorkDir: filepath.Join(os.TempDir(), "proxycheck-sb"), Logf: a.Logf}
		a.mgr.SetEngine(a.engCfg)
	} else {
		a.coreErr = err.Error()
	}
	a.mgr.Listen = "127.0.0.1"
	if a.settings.LinesLAN {
		a.mgr.Listen = "0.0.0.0"
	}
	return a
}

func normStatus(sr settings.ScanRow) string {
	switch sr.Status {
	case "alive", "dead", "died":
		return sr.Status
	}
	if sr.Alive {
		return StatusAlive
	}
	return StatusUnknown
}

func fill(r *Row) {
	r.ID, r.Name, r.Proto, r.Host, r.Port = r.node.ID(), r.node.Label(), r.node.Proto, r.node.Host, r.node.Port
	r.Summary = r.node.Summary()
	r.Country = geo.CodeFromName(r.node.Name)
}

// Logf пишет строку в журнал (последние 200 строк).
func (a *App) Logf(format string, args ...interface{}) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, args...)
	a.mu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > 200 {
		a.logs = a.logs[len(a.logs)-200:]
	}
	a.mu.Unlock()
}

// Snapshot возвращает копию состояния.
func (a *App) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Activity: a.act, Log: append([]string(nil), a.logs...), Core: a.engCfg.Binary}
	s.CoreOK = a.engCfg.Binary != ""
	if !s.CoreOK {
		s.Core = a.coreErr
	}
	for _, r := range a.rows {
		s.Rows = append(s.Rows, *r)
	}
	for _, ep := range a.mgr.Endpoints() {
		cur := ep.CurrentServer()
		s.Lines = append(s.Lines, Line{ID: ep.ID, LocalPort: ep.LocalPort, Name: cur.Label(), Current: cur.ID(), Alive: ep.Alive()})
	}
	sort.Slice(s.Lines, func(i, j int) bool { return s.Lines[i].LocalPort < s.Lines[j].LocalPort })
	return s
}

// ErrBusy возвращается, если уже выполняется другая задача.
var ErrBusy = fmt.Errorf("приложение занято другой задачей")

// begin занимает «слот» задачи; возвращает контекст отмены.
func (a *App) begin(state, detail string) (context.Context, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.act.State != Idle {
		return nil, ErrBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.act = Activity{State: state, Detail: detail, Since: time.Now()}
	return ctx, nil
}

func (a *App) setAct(state, detail string, done, total int) {
	a.mu.Lock()
	a.act.State, a.act.Detail, a.act.Done, a.act.Total = state, detail, done, total
	a.mu.Unlock()
}

func (a *App) end() {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.act = Activity{State: Idle, Since: time.Now()}
	a.mu.Unlock()
}

// Cancel прерывает текущую задачу.
func (a *App) Cancel() {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()
}

func (a *App) newLab(nodes []node.Node, lanes int) (*engine.Lab, error) {
	if a.engCfg.Binary == "" {
		return nil, fmt.Errorf("%s", a.coreErr)
	}
	return engine.NewLab(a.engCfg, nodes, lanes)
}

// seedSubs заполняет подписки встроенным списком при первом запуске.
func (a *App) seedSubs() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.settings.Subscriptions) == 0 {
		for _, src := range sources.Default {
			a.settings.Subscriptions = append(a.settings.Subscriptions, settings.Subscription{URL: src.URL, Name: src.Name, Enabled: true})
		}
	}
}

// Scan загружает подписки (кроме устаревших) и проверяет все найденные серверы.
func (a *App) Scan() error {
	a.seedSubs()
	ctx, err := a.begin(Loading, "проверка дат обновления источников")
	if err != nil {
		return err
	}
	go func() {
		defer a.end()
		a.refreshRemote(ctx, false)
		a.setAct(Loading, "загрузка источников", 0, 0)

		a.mu.Lock()
		var list []sources.Source
		for _, sub := range a.settings.Subscriptions {
			if sub.Enabled && !sub.Stale {
				list = append(list, sources.Source{Name: sub.Name, URL: sub.URL})
			}
		}
		a.mu.Unlock()
		fetched := sources.FetchAll(list, 20*time.Second)

		seen := map[string]bool{}
		var all []node.Node
		perSub := map[string]map[string]bool{}
		fetchErr := map[string]string{}
		for _, fr := range fetched {
			if fr.Err != nil {
				a.Logf("источник %s: %v", fr.Source.Name, fr.Err)
				fetchErr[fr.Source.URL] = fr.Err.Error()
				continue
			}
			ids := map[string]bool{}
			for _, n := range node.ExtractAll(fr.Body) {
				ids[n.ID()] = true
				if !seen[n.ID()] {
					seen[n.ID()] = true
					all = append(all, n)
				}
			}
			perSub[fr.Source.URL] = ids
		}
		a.mu.Lock()
		now := time.Now().Unix()
		for i := range a.settings.Subscriptions {
			sub := &a.settings.Subscriptions[i]
			if ids, ok := perSub[sub.URL]; ok {
				sub.Count, sub.LastFetch, sub.LastError = len(ids), now, ""
			} else if e, bad := fetchErr[sub.URL]; bad {
				sub.LastError = e
			}
		}
		for _, r := range a.rows { // важные строки освежаем вместе со всеми
			if (r.Running || r.Selected || r.Pinned) && !seen[r.ID] {
				seen[r.ID] = true
				all = append(all, r.node)
			}
		}
		a.mu.Unlock()
		a.Logf("получено %d серверов из %d источников", len(all), len(perSub))
		results := a.check(ctx, all)
		if results != nil {
			alive := map[string]bool{}
			for _, r := range results {
				if r.Alive {
					alive[r.Node.ID()] = true
				}
			}
			a.mu.Lock()
			for i := range a.settings.Subscriptions {
				sub := &a.settings.Subscriptions[i]
				if ids, ok := perSub[sub.URL]; ok {
					n := 0
					for id := range ids {
						if alive[id] {
							n++
						}
					}
					sub.Alive = n
				}
			}
			a.mu.Unlock()
			a.save()
		}
	}()
	return nil
}

// refreshRemote узнаёт даты обновления источников на удалённой стороне и
// помечает устаревшие. force — игнорировать кэш (10 минут).
func (a *App) refreshRemote(ctx context.Context, force bool) {
	a.mu.Lock()
	type job struct {
		i   int
		url string
	}
	var jobs []job
	for i, sub := range a.settings.Subscriptions {
		if !sub.Enabled {
			continue
		}
		if !force && time.Now().Unix()-sub.RemoteChecked < 600 && sub.RemoteUpdated != 0 {
			continue
		}
		jobs = append(jobs, job{i, sub.URL})
	}
	a.mu.Unlock()

	type res struct {
		t   time.Time
		src string
		err error
	}
	out := make([]res, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for k, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(k int, url string) {
			defer wg.Done()
			defer func() { <-sem }()
			t, src, err := sources.RemoteDate(ctx, url)
			out[k] = res{t, src, err}
		}(k, j.url)
	}
	wg.Wait()

	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, j := range jobs {
		if j.i >= len(a.settings.Subscriptions) || a.settings.Subscriptions[j.i].URL != j.url {
			continue // список изменили во время проверки
		}
		sub := &a.settings.Subscriptions[j.i]
		sub.RemoteChecked = now.Unix()
		if out[k].err == nil {
			sub.RemoteUpdated, sub.RemoteSource = out[k].t.Unix(), out[k].src
		}
	}
	for i := range a.settings.Subscriptions {
		sub := &a.settings.Subscriptions[i]
		was := sub.Stale
		sub.Stale = sub.Enabled && sub.MaxAgeDays > 0 && sub.RemoteUpdated != 0 &&
			now.Sub(time.Unix(sub.RemoteUpdated, 0)) > time.Duration(sub.MaxAgeDays)*24*time.Hour
		if sub.Stale && !was {
			go a.Logf("источник %s не обновлялся более %d дн. — не загружаю, пока не обновится", sub.Name, sub.MaxAgeDays)
		}
	}
}

// RefreshSubs обновляет только даты источников (без загрузки списков).
func (a *App) RefreshSubs() error {
	a.seedSubs()
	ctx, err := a.begin(Loading, "проверка дат обновления источников")
	if err != nil {
		return err
	}
	go func() {
		defer a.end()
		a.refreshRemote(ctx, true)
		a.save()
	}()
	return nil
}

// Subscriptions возвращает текущие источники.
func (a *App) Subscriptions() []settings.Subscription {
	a.seedSubs()
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]settings.Subscription(nil), a.settings.Subscriptions...)
}

// SetSubscriptions заменяет список источников. Правятся только URL, имя,
// «включён» и максимальный возраст; статистика сохраняется по совпадению URL.
func (a *App) SetSubscriptions(in []settings.Subscription) error {
	if len(in) > 100 {
		return fmt.Errorf("слишком много источников (максимум 100)")
	}
	a.mu.Lock()
	old := map[string]settings.Subscription{}
	for _, s := range a.settings.Subscriptions {
		old[s.URL] = s
	}
	seen := map[string]bool{}
	var out []settings.Subscription
	for _, s := range in {
		s.URL = strings.TrimSpace(s.URL)
		u, err := url.Parse(s.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			a.mu.Unlock()
			return fmt.Errorf("некорректная ссылка: %q (нужен http:// или https://)", s.URL)
		}
		if seen[s.URL] {
			continue
		}
		seen[s.URL] = true
		if s.MaxAgeDays < 0 {
			s.MaxAgeDays = 0
		}
		if strings.TrimSpace(s.Name) == "" {
			s.Name = u.Host + u.Path
		}
		if o, ok := old[s.URL]; ok {
			s.LastFetch, s.RemoteUpdated, s.RemoteChecked, s.RemoteSource = o.LastFetch, o.RemoteUpdated, o.RemoteChecked, o.RemoteSource
			s.Count, s.Alive, s.LastError, s.Stale = o.Count, o.Alive, o.LastError, o.Stale
		}
		out = append(out, s)
	}
	a.settings.Subscriptions = out
	st := a.settings
	a.mu.Unlock()
	return settings.Save(a.path, st)
}

// AutoSettings — параметры автозагрузки.
type AutoSettings struct {
	ScanMin     int  `json:"scan_min"`
	ScanOnStart bool `json:"scan_on_start"`
}

// Auto возвращает параметры автозагрузки.
func (a *App) Auto() AutoSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AutoSettings{a.settings.AutoScanMin, a.settings.AutoScanOnStart}
}

// SetAuto сохраняет параметры автозагрузки.
func (a *App) SetAuto(v AutoSettings) error {
	if v.ScanMin < 0 || v.ScanMin > 7*24*60 {
		return fmt.Errorf("период должен быть от 0 до 10080 минут")
	}
	if v.ScanMin > 0 && v.ScanMin < 5 {
		return fmt.Errorf("минимальный период автопроверки — 5 минут")
	}
	a.UpdateSettings(func(s *settings.Settings) { s.AutoScanMin, s.AutoScanOnStart = v.ScanMin, v.ScanOnStart })
	return nil
}

// RunScheduler выполняет автозагрузку по расписанию до закрытия stop.
func (a *App) RunScheduler(stop <-chan struct{}) {
	if a.Auto().ScanOnStart {
		select {
		case <-time.After(3 * time.Second):
			if err := a.Scan(); err != nil {
				a.Logf("автозапуск проверки: %v", err)
			}
		case <-stop:
			return
		}
	}
	last := time.Now()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m := a.Auto().ScanMin
			if m > 0 && time.Since(last) >= time.Duration(m)*time.Minute {
				if err := a.Scan(); err == nil {
					last = time.Now()
				}
			}
		}
	}
}

// AddManual добавляет сервер, заполненный вручную (форма). Ссылка строится из
// полей; параметры, которых в ссылке нет (UoT, мультиплексирование, JSON
// outbound), сохраняются в самом сервере. replaceID != "" — это редактирование:
// старый сервер заменяется новым (линия на нём останавливается).
func (a *App) AddManual(n node.Node, replaceID string) (string, error) {
	n.Raw = ""
	n.Host = strings.TrimSpace(n.Host)
	if n.Name == "" {
		n.Name = n.Host
	}
	if n.Proto == node.SS && n.Method == "" {
		return "", fmt.Errorf("укажите шифр")
	}
	if err := node.Validate(n); err != nil {
		return "", err
	}
	n.Raw = node.Encode(n)
	back, err := node.Parse(n.Raw)
	if err != nil {
		return "", fmt.Errorf("параметры не складываются в корректную ссылку: %v", err)
	}
	back.Name = n.Name
	back.Extra = n.Extra // Parse не знает про UoT/mux/JSON — берём из формы
	if replaceID != "" {
		if err := a.Delete(replaceID); err != nil {
			return "", err
		}
	}
	res := a.addNodes([]node.Node{back}, true)
	if len(res.IDs) == 0 {
		return "", fmt.Errorf("сервер не добавлен")
	}
	return res.IDs[0], nil
}

// Recheck перепроверяет уже известные серверы без загрузки источников.
func (a *App) Recheck() error {
	ctx, err := a.begin(Checking, "перепроверка")
	if err != nil {
		return err
	}
	a.mu.Lock()
	var all []node.Node
	for _, r := range a.rows {
		all = append(all, r.node)
	}
	a.mu.Unlock()
	go func() {
		defer a.end()
		a.check(ctx, all)
	}()
	return nil
}

func (a *App) check(ctx context.Context, all []node.Node) []engine.Result {
	var valid []node.Node
	for _, n := range all {
		if node.Validate(n) == nil {
			valid = append(valid, n)
		}
	}
	if len(valid) == 0 {
		a.Logf("нет серверов для проверки")
		return nil
	}
	a.setAct(Starting, fmt.Sprintf("запуск ядра, загрузка %d серверов", len(valid)), 0, 0)
	lab, err := a.newLab(valid, 8)
	if err != nil {
		a.Logf("ядро: %v", err)
		return nil
	}
	defer lab.Close()
	to := time.Duration(a.TimeoutSec) * time.Second
	a.setAct(Checking, "проверка серверов", 0, len(valid))
	results := lab.CheckAll(ctx, valid, a.Concurrency, to, func(done, total int, _ engine.Result) {
		a.setAct(Checking, "проверка серверов", done, total)
	})
	if ctx.Err() != nil {
		a.Logf("проверка прервана")
		return nil
	}
	a.applyResults(results)
	if a.DetectExit {
		var alive []node.Node
		for _, r := range results {
			if r.Alive {
				alive = append(alive, r.Node)
			}
		}
		a.exitIPs(ctx, lab, alive, to)
	}
	a.save()
	a.Logf("готово: живых %d из %d", countAlive(results), len(results))
	return results
}

func countAlive(rs []engine.Result) int {
	n := 0
	for _, r := range rs {
		if r.Alive {
			n++
		}
	}
	return n
}

func (a *App) applyResults(results []engine.Result) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := map[string]*Row{}
	for _, r := range a.rows {
		prev[r.ID] = r
	}
	var rows []*Row
	var pool []node.Node
	seen := map[string]bool{}
	for _, res := range results {
		id := res.Node.ID()
		p := prev[id]
		important := p != nil && (p.Running || p.Selected || p.Pinned || p.Status == StatusAlive || p.Status == StatusDied)
		seen[id] = true
		if !res.Alive && !important {
			continue
		}
		r := &Row{node: res.Node, LatencyMs: res.Latency.Milliseconds()}
		fill(r)
		prevStatus := StatusUnknown
		if p != nil {
			prevStatus = p.Status
			r.Running, r.LocalPort, r.Selected, r.Pinned = p.Running, p.LocalPort, p.Selected, p.Pinned
			r.ExitIP, r.SpeedMbps, r.UlMbps = p.ExitIP, p.SpeedMbps, p.UlMbps
		}
		r.Status = nextStatus(prevStatus, res.Alive)
		if res.Alive {
			pool = append(pool, res.Node)
		}
		rows = append(rows, r)
	}
	for id, p := range prev { // линии и отмеченные не теряем, даже если не попали в проверку
		if !seen[id] && (p.Running || p.Selected || p.Pinned) {
			rows = append(rows, p)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := rows[i].Status == StatusAlive, rows[j].Status == StatusAlive
		if ai != aj {
			return ai
		}
		return rows[i].LatencyMs < rows[j].LatencyMs
	})
	a.rows = rows
	a.mgr.SetPool(pool)
}

func nextStatus(prev string, alive bool) string {
	if alive {
		return StatusAlive
	}
	if prev == StatusAlive || prev == StatusDied {
		return StatusDied
	}
	return StatusDead
}

func (a *App) exitIPs(ctx context.Context, lab *engine.Lab, nodes []node.Node, to time.Duration) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	var cnt int
	var cmu sync.Mutex
	for _, n := range nodes {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(n node.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			// IP-сервисы медленнее generate_204 (TLS + запрос), берём запас по времени
			ip, err := lab.ExitIP(ctx, n, to*2)
			a.mu.Lock()
			if r, ok := a.find(n.ID()); ok {
				if err == nil {
					r.ExitIP, r.ExitErr = ip, ""
				} else {
					r.ExitErr = err.Error()
				}
			}
			a.mu.Unlock()
			cmu.Lock()
			cnt++
			c := cnt
			cmu.Unlock()
			a.setAct(ExitIP, "определение выходного IP", c, len(nodes))
		}(n)
	}
	wg.Wait()
}

func (a *App) save() {
	a.mu.Lock()
	st := a.settings
	st.LastScanServers = nil
	for _, r := range a.rows {
		st.LastScanServers = append(st.LastScanServers, settings.ScanRow{Server: r.node, Status: r.Status,
			Alive: r.Status == StatusAlive, LatencyMs: r.LatencyMs, Selected: r.Selected, ExitIP: r.ExitIP,
			SpeedMbps: r.SpeedMbps, SpeedDone: r.SpeedMbps > 0, UlSpeedMbps: r.UlMbps, UlSpeedDone: r.UlMbps > 0, Pinned: r.Pinned})
	}
	a.settings = st
	a.mu.Unlock()
	if err := settings.Save(a.path, st); err != nil {
		a.Logf("не удалось сохранить настройки: %v", err)
	}
}

// Select отмечает/снимает отметку сервера.
func (a *App) Select(id string, on bool) {
	a.mu.Lock()
	for _, r := range a.rows {
		if r.ID == id {
			r.Selected = on
		}
	}
	a.mu.Unlock()
	a.save()
}

func (a *App) find(id string) (*Row, bool) {
	for _, r := range a.rows {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}

// StartLine поднимает локальную линию (порт) на сервер id.
func (a *App) StartLine(id string, port int) (int, error) {
	a.mu.Lock()
	r, ok := a.find(id)
	var n node.Node
	if ok {
		n = r.node
	}
	a.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("сервер не найден")
	}
	if port <= 0 {
		port = a.settings.StartPort
	}
	ep, err := a.mgr.Start(n, port)
	if err != nil {
		return 0, err
	}
	a.mu.Lock()
	if r, ok := a.find(id); ok {
		r.Running, r.LocalPort = true, ep.LocalPort
	}
	a.mu.Unlock()
	a.Logf("линия %d -> %s", ep.LocalPort, n.Label())
	a.saveProfiles()
	return ep.LocalPort, nil
}

// StopLine останавливает линию сервера id.
func (a *App) StopLine(id string) error {
	if err := a.mgr.Stop(id); err != nil {
		return err
	}
	a.mu.Lock()
	if r, ok := a.find(id); ok {
		r.Running, r.LocalPort = false, 0
	}
	a.mu.Unlock()
	a.saveProfiles()
	return nil
}

// SpeedTest измеряет скорость у серверов ids (строго по очереди).
func (a *App) SpeedTest(ids []string) error {
	a.mu.Lock()
	var nodes []node.Node
	for _, id := range ids {
		if r, ok := a.find(id); ok {
			nodes = append(nodes, r.node)
		}
	}
	a.mu.Unlock()
	if len(nodes) == 0 {
		return fmt.Errorf("не выбрано ни одного сервера")
	}
	ctx, err := a.begin(Starting, "запуск ядра для замера скорости")
	if err != nil {
		return err
	}
	go func() {
		defer a.end()
		lab, err := a.newLab(nodes, 1)
		if err != nil {
			a.Logf("ядро: %v", err)
			return
		}
		defer lab.Close()
		for i, n := range nodes {
			if ctx.Err() != nil {
				return
			}
			a.setAct(Speed, "замер скорости: "+n.Label(), i, len(nodes))
			down, up, derr, uerr := lab.Speed(ctx, n, true, 20*time.Second)
			a.mu.Lock()
			if r, ok := a.find(n.ID()); ok {
				if derr == nil {
					r.SpeedMbps = down.Mbps
				}
				if uerr == nil {
					r.UlMbps = up.Mbps
				}
			}
			a.mu.Unlock()
			a.mu.Lock()
			if r, ok := a.find(n.ID()); ok {
				r.SpeedErr = ""
				if derr != nil {
					r.SpeedErr = derr.Error()
				}
			}
			a.mu.Unlock()
			if derr != nil {
				a.Logf("%s: ошибка замера: %v", n.Label(), derr)
			} else {
				a.Logf("%s: ↓ %.1f Мбит/с", n.Label(), down.Mbps)
			}
		}
		a.save()
	}()
	return nil
}

// Shutdown останавливает линии и ядро.
func (a *App) Shutdown() {
	a.Cancel()
	a.mgr.StopAll()
	a.save()
}

// Settings возвращает копию настроек (для веб-сервера: пароль и т.п.).
func (a *App) Settings() settings.Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

// UpdateSettings применяет функцию к настройкам и сохраняет их.
func (a *App) UpdateSettings(f func(*settings.Settings)) {
	a.mu.Lock()
	f(&a.settings)
	st := a.settings
	a.mu.Unlock()
	_ = settings.Save(a.path, st)
}

// ConfigInfo — конфиг сервера для показа/копирования.
type ConfigInfo struct {
	ID      string            `json:"id"`
	Link    string            `json:"link"`
	Fields  map[string]string `json:"fields"`
	Skipped string            `json:"skipped,omitempty"` // почему ядро не сможет его использовать
	Node    node.Node         `json:"node"`              // для формы редактирования
}

// Config возвращает ссылку и разобранные поля сервера id.
func (a *App) Config(id string) (ConfigInfo, error) {
	a.mu.Lock()
	r, ok := a.find(id)
	var n node.Node
	if ok {
		n = r.node
	}
	a.mu.Unlock()
	if !ok {
		return ConfigInfo{}, fmt.Errorf("сервер не найден")
	}
	ci := ConfigInfo{ID: id, Link: n.Raw, Fields: map[string]string{}, Node: n}
	add := func(k, v string) {
		if v != "" {
			ci.Fields[k] = v
		}
	}
	add("Протокол", n.Proto)
	add("Имя", n.Name)
	add("Адрес", n.Addr())
	add("Пользователь", n.Username)
	add("Пароль", n.Password)
	add("UUID", n.UUID)
	add("Шифр/метод", n.Method)
	add("Flow", n.Flow)
	add("Транспорт", n.Network)
	add("Путь", n.Path)
	add("Host", n.HostHeader)
	add("Служба gRPC", n.ServiceName)
	add("Безопасность", n.Security)
	add("SNI", n.SNI)
	add("Fingerprint", n.Fingerprint)
	add("Reality ключ", n.PublicKey)
	add("Reality short id", n.ShortID)
	add("Плагин", n.Plugin)
	if n.Insecure {
		add("Проверка сертификата", "отключена")
	}
	for k, v := range n.Extra {
		add(k, v)
	}
	if err := node.Validate(n); err != nil {
		ci.Skipped = err.Error()
	}
	return ci, nil
}

// ImportResult — итог вставки конфигов.
type ImportResult struct {
	Added      int      `json:"added"`
	Existing   int      `json:"existing"`
	Rejected   int      `json:"rejected"`
	IDs        []string `json:"ids"`
	Rejections []string `json:"rejections,omitempty"`
}

// Import добавляет серверы из текста: ссылки по строкам, base64-подписка или
// одна ссылка. Добавленные вручную серверы закрепляются (не удаляются проверкой).
func (a *App) Import(text string) ImportResult {
	var res ImportResult
	nodes := node.ExtractAll(text)
	if len(nodes) == 0 { // одиночная ссылка нестандартного вида
		if n, err := node.Parse(text); err == nil {
			nodes = []node.Node{n}
		}
	}
	// строки, которые похожи на ссылку, но не разобрались, — покажем причину
	known := map[string]bool{}
	for _, n := range nodes {
		known[strings.TrimSpace(n.Raw)] = true
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || known[line] || !strings.Contains(line, "://") {
			continue
		}
		if _, err := node.Parse(line); err != nil {
			res.Rejected++
			if len(res.Rejections) < 5 {
				res.Rejections = append(res.Rejections, err.Error())
			}
		}
	}
	r2 := a.addNodes(nodes, false)
	res.Added, res.Existing, res.IDs, res.Rejected = r2.Added, r2.Existing, r2.IDs, res.Rejected+r2.Rejected
	res.Rejections = append(res.Rejections, r2.Rejections...)
	return res
}

// addNodes добавляет готовые серверы закреплёнными. overwrite — заменить
// параметры уже существующего сервера (для ручного ввода/редактирования).
func (a *App) addNodes(nodes []node.Node, overwrite bool) ImportResult {
	var res ImportResult
	a.mu.Lock()
	existing := map[string]*Row{}
	for _, r := range a.rows {
		existing[r.ID] = r
	}
	for _, n := range nodes {
		if err := node.Validate(n); err != nil {
			res.Rejected++
			if len(res.Rejections) < 5 {
				res.Rejections = append(res.Rejections, n.Label()+": "+err.Error())
			}
			continue
		}
		res.IDs = append(res.IDs, n.ID())
		if r, ok := existing[n.ID()]; ok {
			r.Pinned = true
			if overwrite {
				r.node = n
				fill(r)
			}
			res.Existing++
			continue
		}
		r := &Row{node: n, Status: StatusUnknown, Pinned: true}
		fill(r)
		a.rows = append(a.rows, r)
		existing[r.ID] = r
		res.Added++
	}
	a.mu.Unlock()
	a.save()
	a.Logf("добавление: новых %d, уже было %d, отклонено %d", res.Added, res.Existing, res.Rejected)
	return res
}

// Delete удаляет сервер из списка (линия на нём останавливается).
func (a *App) Delete(id string) error {
	a.mu.Lock()
	r, ok := a.find(id)
	running := ok && r.Running
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("сервер не найден")
	}
	if running {
		if err := a.StopLine(id); err != nil {
			return err
		}
	}
	a.mu.Lock()
	rows := a.rows[:0:0]
	for _, x := range a.rows {
		if x.ID != id {
			rows = append(rows, x)
		}
	}
	a.rows = rows
	a.mu.Unlock()
	a.save()
	return nil
}

// CheckIDs проверяет только указанные серверы (например, только что вставленные).
func (a *App) CheckIDs(ids []string) error {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	a.mu.Lock()
	var nodes []node.Node
	for _, r := range a.rows {
		if want[r.ID] {
			nodes = append(nodes, r.node)
		}
	}
	a.mu.Unlock()
	if len(nodes) == 0 {
		return fmt.Errorf("нет серверов для проверки")
	}
	ctx, err := a.begin(Checking, "проверка выбранных серверов")
	if err != nil {
		return err
	}
	go func() {
		defer a.end()
		a.checkPartial(ctx, nodes)
	}()
	return nil
}

// checkPartial проверяет часть серверов и обновляет только их строки.
func (a *App) checkPartial(ctx context.Context, nodes []node.Node) {
	a.setAct(Starting, "запуск ядра", 0, 0)
	lab, err := a.newLab(nodes, 4)
	if err != nil {
		a.Logf("ядро: %v", err)
		return
	}
	defer lab.Close()
	to := time.Duration(a.TimeoutSec) * time.Second
	a.setAct(Checking, "проверка выбранных серверов", 0, len(nodes))
	results := lab.CheckAll(ctx, nodes, a.Concurrency, to, func(done, total int, _ engine.Result) {
		a.setAct(Checking, "проверка выбранных серверов", done, total)
	})
	if ctx.Err() != nil {
		return
	}
	a.mu.Lock()
	for _, res := range results {
		if r, ok := a.find(res.Node.ID()); ok {
			r.Status = nextStatus(r.Status, res.Alive)
			r.LatencyMs = res.Latency.Milliseconds()
		}
	}
	a.mu.Unlock()
	if a.DetectExit {
		var alive []node.Node
		for _, res := range results {
			if res.Alive {
				alive = append(alive, res.Node)
			}
		}
		a.exitIPs(ctx, lab, alive, to)
	}
	a.save()
}

// saveProfiles запоминает запущенные линии, чтобы поднять их при следующем старте.
func (a *App) saveProfiles() {
	var profs []settings.Profile
	for i, ep := range a.mgr.Endpoints() {
		profs = append(profs, settings.Profile{ID: i + 1, Server: ep.CurrentServer(), LocalPort: ep.LocalPort, Enabled: true})
	}
	sort.Slice(profs, func(i, j int) bool { return profs[i].LocalPort < profs[j].LocalPort })
	a.UpdateSettings(func(s *settings.Settings) { s.Profiles = profs })
}

// RestoreLines поднимает сохранённые линии (одним запуском ядра).
func (a *App) RestoreLines() {
	a.mu.Lock()
	var profs []settings.Profile
	for _, p := range a.settings.Profiles {
		if p.Enabled {
			profs = append(profs, p)
		}
	}
	a.mu.Unlock()
	if len(profs) == 0 {
		return
	}
	var nodes []node.Node
	var ports []int
	for _, p := range profs {
		nodes = append(nodes, p.Server)
		ports = append(ports, p.LocalPort)
	}
	eps, errs := a.mgr.StartMany(nodes, ports)
	a.mu.Lock()
	for i, n := range nodes {
		if errs[i] != nil {
			a.logfLocked("не удалось восстановить линию %s: %v", n.Label(), errs[i])
			continue
		}
		r, ok := a.find(n.ID())
		if !ok {
			r = &Row{node: n, Status: StatusUnknown, Pinned: true}
			fill(r)
			a.rows = append(a.rows, r)
		}
		r.Running, r.LocalPort = true, eps[i].LocalPort
	}
	a.mu.Unlock()
	a.Logf("восстановлено линий: %d", len(profs))
}

func (a *App) logfLocked(format string, args ...interface{}) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, args...)
	a.logs = append(a.logs, line)
	if len(a.logs) > 200 {
		a.logs = a.logs[len(a.logs)-200:]
	}
}

// Run запускает фоновую работу: восстановление линий, health-мониторинг с
// заменой упавших серверов и автозагрузку по расписанию. Блокируется до stop.
func (a *App) Run(stop <-chan struct{}) {
	a.RestoreLines()
	go a.mgr.RunHealthLoop(20*time.Second, time.Duration(a.TimeoutSec)*time.Second, 2, stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case ev := <-a.mgr.Events():
				a.Logf("[линия] %s", ev.Message)
			}
		}
	}()
	a.RunScheduler(stop)
}

// LinesLAN сообщает, открыты ли линии для локальной сети.
func (a *App) LinesLAN() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings.LinesLAN
}

// SetLinesLAN открывает или закрывает линии для локальной сети.
func (a *App) SetLinesLAN(on bool) error {
	addr := "127.0.0.1"
	if on {
		addr = "0.0.0.0"
	}
	if err := a.mgr.SetListen(addr); err != nil {
		return err
	}
	a.UpdateSettings(func(s *settings.Settings) { s.LinesLAN = on })
	return nil
}
