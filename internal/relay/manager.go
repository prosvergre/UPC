// Package relay поднимает локальные SOCKS5-входы поверх реализации
// Shadowsocks-клиента (internal/ssclient) — по одному TCP-листенеру на
// каждый выбранный внешний сервер, плюс фоновый health-мониторинг с
// точечной заменой упавшего сервера на живой из резервного пула
// (без полного пересканирования).
package relay

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"proxycheck/internal/checker"
	"proxycheck/internal/debugflag"
	"proxycheck/internal/netutil"
	"proxycheck/internal/socks5"
	"proxycheck/internal/ssclient"
	"proxycheck/internal/ssuri"
)

// Event — событие для подписчиков (GUI/CLI-лог).
type Event struct {
	EndpointID string
	Message    string
	Time       time.Time
}

// Endpoint — один активный локальный вход (SOCKS5-порт -> внешний сервер).
type Endpoint struct {
	ID        string // исходный server.ID(), под которым endpoint был создан
	LocalPort int

	mu               sync.RWMutex
	current          ssuri.Server // сервер, на который сейчас реально идёт трафик (может смениться при failover)
	alive            bool
	consecutiveFails int

	listener net.Listener
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// CurrentServer возвращает сервер, на который endpoint сейчас проксирует.
func (e *Endpoint) CurrentServer() ssuri.Server {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.current
}

// Alive сообщает текущий статус (по данным последнего health-чека).
func (e *Endpoint) Alive() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.alive
}

func (e *Endpoint) setAlive(v bool) {
	e.mu.Lock()
	e.alive = v
	e.mu.Unlock()
}

func (e *Endpoint) swapServer(s ssuri.Server) {
	e.mu.Lock()
	e.current = s
	e.alive = true
	e.consecutiveFails = 0
	e.mu.Unlock()
}

// Manager управляет набором Endpoint'ов и резервным пулом кандидатов
// на замену (обычно — полный последний результат сканирования).
type Manager struct {
	mu          sync.Mutex
	endpoints   map[string]*Endpoint // по ID локального порта-владельца (исходный server.ID())
	pool        []ssuri.Server       // резервные кандидаты для failover
	dialTimeout time.Duration

	events chan Event
}

// NewManager создаёт менеджер. pool — список проверенных серверов,
// которые можно использовать как замену при падении активного
// (обычно результат последнего полного скана; может быть пустым —
// тогда failover просто не будет находить замену).
func NewManager(pool []ssuri.Server, dialTimeout time.Duration) *Manager {
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	return &Manager{
		endpoints:   make(map[string]*Endpoint),
		pool:        pool,
		dialTimeout: dialTimeout,
		events:      make(chan Event, 100),
	}
}

// Events возвращает канал событий (логи для GUI/CLI). Читать
// не обязательно — канал буферизован, старые события просто теряются
// при переполнении, если никто не читает.
func (m *Manager) Events() <-chan Event {
	return m.events
}

func (m *Manager) emit(id, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[relay:%s] %s", id, msg)
	select {
	case m.events <- Event{EndpointID: id, Message: msg, Time: time.Now()}:
	default:
	}
}

// SetPool обновляет резервный пул кандидатов (например, после нового
// полного скана).
func (m *Manager) SetPool(pool []ssuri.Server) {
	m.mu.Lock()
	m.pool = pool
	m.mu.Unlock()
}

// Start поднимает новый локальный SOCKS5-вход, проксирующий на server.
// desiredPort — предпочитаемый локальный порт; если он занят (другой
// программой ИЛИ уже используется нашим же endpoint'ом), Start
// автоматически подбирает следующий свободный порт (desiredPort+1,
// +2, ...) и возвращает endpoint с этим фактическим портом — проверяй
// ep.LocalPort, а не переданный аргумент. Если для этого server.ID()
// уже есть endpoint — возвращает ошибку (сначала Stop).
func (m *Manager) Start(server ssuri.Server, desiredPort int) (*Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.endpoints[server.ID()]; exists {
		return nil, fmt.Errorf("endpoint для %s уже запущен", server.ID())
	}

	usedByUs := make(map[int]bool, len(m.endpoints))
	for _, ep := range m.endpoints {
		usedByUs[ep.LocalPort] = true
	}

	var ln net.Listener
	var localPort int
	port := desiredPort
	if port <= 0 {
		port = 1080
	}
	const maxAttempts = 200
	for i := 0; i < maxAttempts; i++ {
		candidate := port + i
		if usedByUs[candidate] {
			continue
		}
		l, err := netutil.ListenExclusiveTCP(fmt.Sprintf("0.0.0.0:%d", candidate))
		if err == nil {
			ln = l
			localPort = candidate
			break
		}
	}
	if ln == nil {
		return nil, fmt.Errorf("не удалось найти свободный локальный порт начиная с %d (перебрано %d вариантов)", port, maxAttempts)
	}
	if localPort != desiredPort && desiredPort > 0 {
		m.emit(server.ID(), "порт %d занят, использую %d", desiredPort, localPort)
	}

	ep := &Endpoint{
		ID:        server.ID(),
		LocalPort: localPort,
		current:   server,
		alive:     true,
		listener:  ln,
		stopCh:    make(chan struct{}),
	}

	ep.wg.Add(1)
	go m.acceptLoop(ep)

	m.endpoints[server.ID()] = ep
	m.emit(ep.ID, "запущен на 0.0.0.0:%d -> %s", localPort, server.ID())
	return ep, nil
}

func (m *Manager) acceptLoop(ep *Endpoint) {
	defer ep.wg.Done()
	for {
		conn, err := ep.listener.Accept()
		if err != nil {
			select {
			case <-ep.stopCh:
				return // штатная остановка
			default:
				m.emit(ep.ID, "ошибка Accept: %v", err)
				return
			}
		}
		go m.handleConn(ep, conn)
	}
}

func (m *Manager) handleConn(ep *Endpoint, clientConn net.Conn) {
	defer clientConn.Close()

	req, err := socks5.Accept(clientConn)
	if err != nil {
		return // клиент прислал не SOCKS5 или оборвал соединение — не логируем как ошибку сервера
	}
	if debugflag.Enabled() {
		m.emit(ep.ID, "[debug] принято соединение от %s, цель %s:%d", clientConn.RemoteAddr(), req.TargetHost, req.TargetPort)
	}

	server := ep.CurrentServer()
	remoteConn, err := ssclient.Dial(server, req.RawAddr, m.dialTimeout)
	if err != nil {
		_ = req.Deny() // честно сообщаем клиенту об отказе, а не молчим после ложного "успеха"
		m.emit(ep.ID, "не удалось подключиться к %s (target %s:%d): %v",
			server.ID(), req.TargetHost, req.TargetPort, err)
		return
	}
	defer remoteConn.Close()

	if err := req.Grant(); err != nil {
		return // клиент уже отвалился, пока мы соединялись с апстримом
	}
	if debugflag.Enabled() {
		m.emit(ep.ID, "[debug] туннель к %s:%d установлен, начинаю релей", req.TargetHost, req.TargetPort)
	}

	relay(req.Conn, remoteConn)

	if debugflag.Enabled() {
		m.emit(ep.ID, "[debug] соединение к %s:%d закрыто", req.TargetHost, req.TargetPort)
	}
}

// relay гоняет байты в обе стороны, пока одна из сторон не закроется.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// Stop останавливает конкретный endpoint по исходному ID сервера,
// с которым он был создан через Start.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	ep, ok := m.endpoints[id]
	if ok {
		delete(m.endpoints, id)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("endpoint %s не найден", id)
	}
	close(ep.stopCh)
	ep.listener.Close()
	ep.wg.Wait()
	m.emit(id, "остановлен")
	return nil
}

// StopAll останавливает все endpoint'ы.
func (m *Manager) StopAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.endpoints))
	for id := range m.endpoints {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.Stop(id)
	}
}

// Endpoints возвращает снимок текущих endpoint'ов.
func (m *Manager) Endpoints() []*Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Endpoint, 0, len(m.endpoints))
	for _, ep := range m.endpoints {
		out = append(out, ep)
	}
	return out
}

// RunHealthLoop запускает фоновый периодический health-чек всех
// активных endpoint'ов. При failThreshold подряд неудачных проверках
// endpoint пытается точечно (без полного ре-скана) найти замену в
// резервном пуле — сервер, ещё не занятый другим endpoint'ом — и
// проверяет именно его, прежде чем подменить. Останавливается, когда
// закрывается stop.
func (m *Manager) RunHealthLoop(interval time.Duration, checkTimeout time.Duration, failThreshold int, stop <-chan struct{}) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if failThreshold <= 0 {
		failThreshold = 2
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			for _, ep := range m.Endpoints() {
				m.healthCheckOne(ep, checkTimeout, failThreshold)
			}
		}
	}
}

func (m *Manager) healthCheckOne(ep *Endpoint, checkTimeout time.Duration, failThreshold int) {
	server := ep.CurrentServer()
	res := checker.CheckOne(server, checkTimeout)
	if res.Alive {
		if !ep.Alive() {
			m.emit(ep.ID, "сервер %s снова жив", server.ID())
		}
		ep.mu.Lock()
		ep.alive = true
		ep.consecutiveFails = 0
		ep.mu.Unlock()
		return
	}

	ep.mu.Lock()
	ep.consecutiveFails++
	fails := ep.consecutiveFails
	ep.mu.Unlock()

	m.emit(ep.ID, "проверка не прошла (%d/%d): %v", fails, failThreshold, res.Err)
	if fails < failThreshold {
		return
	}

	ep.setAlive(false)
	m.emit(ep.ID, "сервер %s считается мёртвым, ищу замену в резерве...", server.ID())

	replacement, ok := m.pickReplacement(server.ID())
	if !ok {
		m.emit(ep.ID, "замена не найдена (резервный пул пуст или все уже заняты)")
		return
	}

	checkRes := checker.CheckOne(replacement, checkTimeout)
	if !checkRes.Alive {
		m.emit(ep.ID, "кандидат на замену %s тоже недоступен", replacement.ID())
		return
	}

	ep.swapServer(replacement)
	m.emit(ep.ID, "переключён на %s (задержка %v)", replacement.ID(), checkRes.Latency.Round(time.Millisecond))
}

// pickReplacement ищет в резервном пуле сервер, ещё не используемый
// ни одним активным endpoint'ом.
func (m *Manager) pickReplacement(excludeID string) (ssuri.Server, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	inUse := make(map[string]bool, len(m.endpoints))
	for _, ep := range m.endpoints {
		inUse[ep.CurrentServer().ID()] = true
	}

	for _, cand := range m.pool {
		if cand.ID() == excludeID {
			continue
		}
		if inUse[cand.ID()] {
			continue
		}
		return cand, true
	}
	return ssuri.Server{}, false
}
