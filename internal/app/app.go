// Package app — ядро приложения без интерфейса: список серверов, состояние
// «чем занят», запуск проверок, линий и замера скорости. Его используют все
// интерфейсы (веб, нативное окно Windows), сами они логики не содержат.
package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"proxycheck/internal/engine"
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
	Running   bool    `json:"running"`
	LocalPort int     `json:"local_port,omitempty"`
	Selected  bool    `json:"selected"`
	SpeedMbps float64 `json:"speed_mbps,omitempty"`
	UlMbps    float64 `json:"ul_mbps,omitempty"`

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
			Selected: sr.Selected, SpeedMbps: sr.SpeedMbps, UlMbps: sr.UlSpeedMbps}
		fill(r)
		a.rows = append(a.rows, r)
	}
	if bin, err := engine.FindBinary(); err == nil {
		a.engCfg = engine.Config{Binary: bin, WorkDir: filepath.Join(os.TempDir(), "proxycheck-sb"), Logf: a.Logf}
		a.mgr.SetEngine(a.engCfg)
	} else {
		a.coreErr = err.Error()
	}
	a.mgr.Listen = "0.0.0.0"
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

// Scan загружает источники и проверяет все найденные серверы (в фоне).
func (a *App) Scan() error {
	ctx, err := a.begin(Loading, "загрузка источников")
	if err != nil {
		return err
	}
	go func() {
		defer a.end()
		fetched := sources.FetchAll(sources.Default, 20*time.Second)
		seen := map[string]bool{}
		var all []node.Node
		for _, fr := range fetched {
			if fr.Err != nil {
				a.Logf("источник %s: %v", fr.Source.Name, fr.Err)
				continue
			}
			for _, n := range node.ExtractAll(fr.Body) {
				if !seen[n.ID()] {
					seen[n.ID()] = true
					all = append(all, n)
				}
			}
		}
		a.mu.Lock()
		for _, r := range a.rows { // важные строки освежаем вместе со всеми
			if (r.Running || r.Selected) && !seen[r.ID] {
				seen[r.ID] = true
				all = append(all, r.node)
			}
		}
		a.mu.Unlock()
		a.Logf("получено %d серверов", len(all))
		a.check(ctx, all)
	}()
	return nil
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

func (a *App) check(ctx context.Context, all []node.Node) {
	var valid []node.Node
	for _, n := range all {
		if node.Validate(n) == nil {
			valid = append(valid, n)
		}
	}
	if len(valid) == 0 {
		a.Logf("нет серверов для проверки")
		return
	}
	a.setAct(Starting, fmt.Sprintf("запуск ядра, загрузка %d серверов", len(valid)), 0, 0)
	lab, err := a.newLab(valid, 8)
	if err != nil {
		a.Logf("ядро: %v", err)
		return
	}
	defer lab.Close()
	to := time.Duration(a.TimeoutSec) * time.Second
	a.setAct(Checking, "проверка серверов", 0, len(valid))
	results := lab.CheckAll(ctx, valid, a.Concurrency, to, func(done, total int, _ engine.Result) {
		a.setAct(Checking, "проверка серверов", done, total)
	})
	if ctx.Err() != nil {
		a.Logf("проверка прервана")
		return
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
		important := p != nil && (p.Running || p.Selected || p.Status == StatusAlive || p.Status == StatusDied)
		seen[id] = true
		if !res.Alive && !important {
			continue
		}
		r := &Row{node: res.Node, LatencyMs: res.Latency.Milliseconds()}
		fill(r)
		prevStatus := StatusUnknown
		if p != nil {
			prevStatus = p.Status
			r.Running, r.LocalPort, r.Selected = p.Running, p.LocalPort, p.Selected
			r.ExitIP, r.SpeedMbps, r.UlMbps = p.ExitIP, p.SpeedMbps, p.UlMbps
		}
		r.Status = nextStatus(prevStatus, res.Alive)
		if res.Alive {
			pool = append(pool, res.Node)
		}
		rows = append(rows, r)
	}
	for id, p := range prev { // линии и отмеченные не теряем, даже если не попали в проверку
		if !seen[id] && (p.Running || p.Selected) {
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
			ip, err := lab.ExitIP(ctx, n, to)
			if err == nil {
				a.mu.Lock()
				for _, r := range a.rows {
					if r.ID == n.ID() {
						r.ExitIP = ip
					}
				}
				a.mu.Unlock()
			}
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
			SpeedMbps: r.SpeedMbps, SpeedDone: r.SpeedMbps > 0, UlSpeedMbps: r.UlMbps, UlSpeedDone: r.UlMbps > 0})
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
			if derr != nil {
				a.Logf("%s: ошибка замера: %v", n.Label(), derr)
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
