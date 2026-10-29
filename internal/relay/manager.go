// Package relay поднимает локальные входы (SOCKS5+HTTP, порт на линию) поверх
// ядра sing-box. ВСЕ линии работают в ОДНОМ процессе sing-box: у каждой линии
// свой вход и свой selector, поэтому смена апстрима (failover) выполняется
// через API без перезапуска, а перезапуск нужен только при добавлении или
// удалении линии. Сторож перезапускает процесс, если он упал.
package relay

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"proxycheck/internal/engine"
	"proxycheck/internal/netutil"
	"proxycheck/internal/node"
	"proxycheck/internal/singbox"
)

// Event — событие для подписчиков (GUI/CLI-лог).
type Event struct {
	EndpointID string
	Message    string
	Time       time.Time
}

// Endpoint — одна активная локальная линия (порт -> внешний сервер).
type Endpoint struct {
	ID        string // исходный node.ID(), под которым линия создана
	LocalPort int

	mu               sync.RWMutex
	current          node.Node
	alive            bool
	consecutiveFails int
}

// CurrentServer возвращает сервер, на который линия сейчас проксирует.
func (e *Endpoint) CurrentServer() node.Node {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.current
}

// Alive — статус по данным последней health-проверки.
func (e *Endpoint) Alive() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.alive
}

func (e *Endpoint) setAlive(v bool) { e.mu.Lock(); e.alive = v; e.mu.Unlock() }

func (e *Endpoint) swapServer(s node.Node) {
	e.mu.Lock()
	e.current = s
	e.alive = true
	e.consecutiveFails = 0
	e.mu.Unlock()
}

// Manager управляет линиями и резервным пулом для замены упавших серверов.
type Manager struct {
	mu        sync.Mutex
	endpoints map[string]*Endpoint
	pool      []node.Node

	dialTimeout time.Duration
	Listen      string // адрес входов; по умолчанию 0.0.0.0 (как раньше, с правилом файрвола)
	cfg         engine.Config

	proc   *singbox.Process
	api    *singbox.API
	clash  string
	secret string
	loaded map[string]bool // node.ID() серверов, загруженных в текущий процесс

	// FailoverPick, если задана, выбирает замену для упавшего сервера из
	// кандидатов (например, ближайшего по гео). Возвращает false — нет замены.
	FailoverPick func(dead node.Node, candidates []node.Node) (node.Node, bool)

	events chan Event
}

// NewManager создаёт менеджер. pool — кандидаты на замену (может быть пустым).
func NewManager(pool []node.Node, dialTimeout time.Duration) *Manager {
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	return &Manager{
		endpoints:   map[string]*Endpoint{},
		pool:        pool,
		dialTimeout: dialTimeout,
		Listen:      "0.0.0.0",
		events:      make(chan Event, 100),
	}
}

// SetEngine задаёт путь к sing-box и рабочий каталог (вызвать до Start).
func (m *Manager) SetEngine(cfg engine.Config) {
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
}

// Events — канал событий (буферизован; при переполнении старые теряются).
func (m *Manager) Events() <-chan Event { return m.events }

func (m *Manager) emit(id, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[relay:%s] %s", id, msg)
	select {
	case m.events <- Event{EndpointID: id, Message: msg, Time: time.Now()}:
	default:
	}
}

// SetPool обновляет резервный пул. Процесс не перезапускается: новые кандидаты
// подгружаются в ядро при следующем изменении набора линий или при failover.
func (m *Manager) SetPool(pool []node.Node) {
	m.mu.Lock()
	m.pool = pool
	m.mu.Unlock()
}

// Start поднимает новую линию на server. desiredPort — желаемый порт; если он
// занят, берётся следующий свободный (смотрите ep.LocalPort).
func (m *Manager) Start(server node.Node, desiredPort int) (*Endpoint, error) {
	eps, errs := m.StartMany([]node.Node{server}, []int{desiredPort})
	return eps[0], errs[0]
}

// StartMany поднимает сразу несколько линий одним перезапуском ядра
// (при старте программы это быстрее, чем по одной).
func (m *Manager) StartMany(servers []node.Node, desiredPorts []int) ([]*Endpoint, []error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	eps := make([]*Endpoint, len(servers))
	errs := make([]error, len(servers))
	var added []*Endpoint
	for i, s := range servers {
		if _, ok := m.endpoints[s.ID()]; ok {
			errs[i] = fmt.Errorf("линия для %s уже запущена", s.Label())
			continue
		}
		if err := node.Validate(s); err != nil {
			errs[i] = err
			continue
		}
		port, err := m.freePortLocked(desiredPorts[i])
		if err != nil {
			errs[i] = err
			continue
		}
		if desiredPorts[i] > 0 && port != desiredPorts[i] {
			m.emit(s.ID(), "порт %d занят, использую %d", desiredPorts[i], port)
		}
		ep := &Endpoint{ID: s.ID(), LocalPort: port, current: s, alive: true}
		m.endpoints[s.ID()] = ep
		eps[i] = ep
		added = append(added, ep)
	}
	if len(added) == 0 {
		return eps, errs
	}
	if err := m.rebuildLocked(); err != nil {
		for _, ep := range added {
			delete(m.endpoints, ep.ID)
		}
		for i := range eps {
			if eps[i] != nil {
				eps[i] = nil
				errs[i] = err
			}
		}
		// вернуть остальные линии в рабочее состояние
		_ = m.rebuildLocked()
		return eps, errs
	}
	for _, ep := range added {
		m.emit(ep.ID, "запущена на %s:%d -> %s", m.Listen, ep.LocalPort, ep.CurrentServer().Label())
	}
	return eps, errs
}

func (m *Manager) freePortLocked(desired int) (int, error) {
	used := map[int]bool{}
	for _, ep := range m.endpoints {
		used[ep.LocalPort] = true
	}
	port := desired
	if port <= 0 {
		port = 1080
	}
	for i := 0; i < 200; i++ {
		c := port + i
		if used[c] || c > 65535 {
			continue
		}
		// Порты, на которых сейчас слушает наш процесс, пробой не поймать —
		// их мы уже учли через endpoints. Остальные проверяем реальным bind.
		l, err := netutil.ListenExclusiveTCP(fmt.Sprintf("%s:%d", m.Listen, c))
		if err == nil {
			l.Close()
			return c, nil
		}
	}
	return 0, fmt.Errorf("не удалось найти свободный локальный порт начиная с %d", port)
}

// rebuildLocked пересобирает конфиг из endpoints+pool и перезапускает ядро.
func (m *Manager) rebuildLocked() error {
	if m.proc != nil {
		m.proc.Stop()
		m.proc = nil
	}
	if len(m.endpoints) == 0 {
		m.loaded = nil
		return nil
	}
	if m.cfg.Binary == "" {
		bin, err := engine.FindBinary()
		if err != nil {
			return err
		}
		m.cfg.Binary = bin
	}
	if m.cfg.WorkDir == "" {
		return fmt.Errorf("relay: не задан рабочий каталог (SetEngine)")
	}
	var nodes []node.Node
	var lines []singbox.Line
	seen := map[string]bool{}
	add := func(n node.Node) {
		if !seen[n.ID()] {
			seen[n.ID()] = true
			nodes = append(nodes, n)
		}
	}
	for _, ep := range m.endpoints {
		cur := ep.CurrentServer()
		add(cur)
		lines = append(lines, singbox.Line{Port: ep.LocalPort, NodeID: cur.ID()})
	}
	for _, n := range m.pool {
		add(n)
	}
	if m.clash == "" {
		p, err := engine.FreePort()
		if err != nil {
			return err
		}
		m.clash = "127.0.0.1:" + strconv.Itoa(p)
		m.secret = fmt.Sprintf("%x", time.Now().UnixNano())
		m.api = &singbox.API{Addr: m.clash, Secret: m.secret}
	}
	cfg, skipped, err := singbox.BuildConfig(singbox.Spec{Nodes: nodes, Lines: lines, Listen: m.Listen, ClashAddr: m.clash, Secret: m.secret})
	if err != nil {
		return err
	}
	for _, ep := range m.endpoints {
		if e, bad := skipped[ep.CurrentServer().ID()]; bad {
			return fmt.Errorf("сервер %s непригоден для ядра: %v", ep.CurrentServer().Label(), e)
		}
	}
	proc := &singbox.Process{Binary: m.cfg.Binary, WorkDir: m.cfg.WorkDir + "/relay", Logf: m.cfg.Logf}
	if err := proc.Start(cfg); err != nil {
		return err
	}
	if err := singbox.WaitReady(context.Background(), m.clash, 20*time.Second); err != nil {
		proc.Stop()
		return err
	}
	m.proc = proc
	m.loaded = map[string]bool{}
	for _, n := range nodes {
		if _, bad := skipped[n.ID()]; !bad {
			m.loaded[n.ID()] = true
		}
	}
	return nil
}

// Stop останавливает линию по исходному ID сервера.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.endpoints[id]; !ok {
		return fmt.Errorf("линия %s не найдена", id)
	}
	delete(m.endpoints, id)
	err := m.rebuildLocked()
	m.emit(id, "остановлена")
	return err
}

// StopAll останавливает все линии и процесс ядра.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.endpoints {
		delete(m.endpoints, id)
		m.emit(id, "остановлена")
	}
	if m.proc != nil {
		m.proc.Stop()
		m.proc = nil
	}
}

// Endpoints возвращает снимок линий.
func (m *Manager) Endpoints() []*Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Endpoint, 0, len(m.endpoints))
	for _, ep := range m.endpoints {
		out = append(out, ep)
	}
	return out
}

// RunHealthLoop периодически проверяет все линии. После failThreshold неудач
// подряд линия переключается (без перезапуска ядра) на живую замену из пула.
func (m *Manager) RunHealthLoop(interval, checkTimeout time.Duration, failThreshold int, stop <-chan struct{}) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if failThreshold <= 0 {
		failThreshold = 2
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			for _, ep := range m.Endpoints() {
				m.healthCheckOne(ep, checkTimeout, failThreshold)
			}
		}
	}
}

func (m *Manager) delay(n node.Node, timeout time.Duration) (time.Duration, error) {
	m.mu.Lock()
	api := m.api
	ok := m.loaded[n.ID()]
	m.mu.Unlock()
	if api == nil || !ok {
		return 0, fmt.Errorf("сервер не загружен в ядро")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
	defer cancel()
	return api.Delay(ctx, singbox.Tag(n), engine.DefaultTestURL, timeout)
}

func (m *Manager) healthCheckOne(ep *Endpoint, checkTimeout time.Duration, failThreshold int) {
	server := ep.CurrentServer()
	d, err := m.delay(server, checkTimeout)
	if err == nil {
		if !ep.Alive() {
			m.emit(ep.ID, "сервер %s снова жив", server.Label())
		}
		ep.mu.Lock()
		ep.alive = true
		ep.consecutiveFails = 0
		ep.mu.Unlock()
		_ = d
		return
	}
	ep.mu.Lock()
	ep.consecutiveFails++
	fails := ep.consecutiveFails
	ep.mu.Unlock()
	m.emit(ep.ID, "проверка не прошла (%d/%d): %v", fails, failThreshold, err)
	if fails < failThreshold {
		return
	}
	ep.setAlive(false)
	m.emit(ep.ID, "сервер %s считается мёртвым, ищу замену...", server.Label())

	cands := m.candidates(server.ID())
	for len(cands) > 0 {
		var repl node.Node
		var ok bool
		if m.FailoverPick != nil {
			repl, ok = m.FailoverPick(server, cands)
		} else {
			repl, ok = cands[0], true
		}
		if !ok {
			break
		}
		cands = removeNode(cands, repl.ID())
		lat, err := m.delay(repl, checkTimeout)
		if err != nil {
			continue
		}
		if err := m.switchLine(ep, repl); err != nil {
			m.emit(ep.ID, "не удалось переключить на %s: %v", repl.Label(), err)
			continue
		}
		m.emit(ep.ID, "переключена на %s (задержка %v)", repl.Label(), lat.Round(time.Millisecond))
		return
	}
	m.emit(ep.ID, "замена не найдена (резерв пуст, недоступен или занят)")
}

// candidates — серверы пула, не занятые другими линиями и уже загруженные в ядро.
func (m *Manager) candidates(excludeID string) []node.Node {
	m.mu.Lock()
	defer m.mu.Unlock()
	inUse := map[string]bool{excludeID: true}
	for _, ep := range m.endpoints {
		inUse[ep.CurrentServer().ID()] = true
	}
	var out []node.Node
	for _, c := range m.pool {
		if !inUse[c.ID()] && m.loaded[c.ID()] {
			out = append(out, c)
		}
	}
	return out
}

func (m *Manager) switchLine(ep *Endpoint, to node.Node) error {
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()
	if api == nil {
		return fmt.Errorf("ядро не запущено")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := api.Select(ctx, singbox.SelectorTag(ep.LocalPort), singbox.Tag(to)); err != nil {
		return err
	}
	ep.swapServer(to)
	return nil
}

func removeNode(a []node.Node, id string) []node.Node {
	out := a[:0:0]
	for _, n := range a {
		if n.ID() != id {
			out = append(out, n)
		}
	}
	return out
}

// Traffic возвращает суммарный трафик (байт) по портам линий по данным активных
// соединений ядра. Это оценка: закрытые соединения в Clash API не учитываются.
func (m *Manager) Traffic(ctx context.Context) (map[int][2]int64, error) {
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()
	if api == nil {
		return nil, fmt.Errorf("ядро не запущено")
	}
	conns, _, _, err := api.Connections(ctx)
	if err != nil {
		return nil, err
	}
	out := map[int][2]int64{}
	for _, c := range conns {
		p, _ := strconv.Atoi(c.Metadata.InboundPort)
		if p == 0 {
			continue
		}
		v := out[p]
		v[0] += c.Upload
		v[1] += c.Download
		out[p] = v
	}
	return out, nil
}
