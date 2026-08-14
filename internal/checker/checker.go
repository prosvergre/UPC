// Package checker проверяет доступность Shadowsocks-серверов в
// несколько потоков (worker pool на горутинах).
//
// Есть два уровня проверки:
//   - CheckAll — быстрая TCP-проверка (порт открыт и что-то слушает).
//     Отсеивает явно мёртвые хосты, но НЕ гарантирует, что там реально
//     Shadowsocks с рабочими method/password — публичные списки часто
//     содержат порты, которые технически отвечают, но с устаревшими
//     или неверными данными.
//   - DeepVerifyAll — настоящая проверка: реальное SS-подключение и
//     HTTP-запрос через туннель наружу. Медленнее, но только она даёт
//     гарантию, что прокси реально работает (это то, что проверяет
//     Proxifier и любой другой строгий клиент).
package checker

import (
	"net"
	"sync"
	"time"

	"proxycheck/internal/ssclient"
	"proxycheck/internal/ssuri"
)

// Result — результат проверки одного сервера.
type Result struct {
	Server  ssuri.Server
	Alive   bool
	Latency time.Duration
	Err     error
}

// Options — параметры проверки.
type Options struct {
	Concurrency int           // сколько серверов проверяем одновременно
	Timeout     time.Duration // таймаут на одну попытку соединения
}

// DefaultOptions — разумные значения по умолчанию.
func DefaultOptions() Options {
	return Options{
		Concurrency: 50,
		Timeout:     5 * time.Second,
	}
}

// ProgressFunc вызывается после каждой завершённой проверки —
// удобно для прогресс-бара в CLI/GUI. done — сколько уже проверено,
// total — сколько всего.
type ProgressFunc func(done, total int, r Result)

// CheckAll проверяет список серверов в пуле из opts.Concurrency горутин
// и возвращает срез результатов В ТОМ ЖЕ ПОРЯДКЕ, что и вход.
func CheckAll(servers []ssuri.Server, opts Options, onProgress ProgressFunc) []Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}

	results := make([]Result, len(servers))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	total := len(servers)

	worker := func() {
		defer wg.Done()
		for i := range jobs {
			r := checkOne(servers[i], opts.Timeout)
			results[i] = r
			if onProgress != nil {
				mu.Lock()
				done++
				onProgress(done, total, r)
				mu.Unlock()
			}
		}
	}

	workerCount := opts.Concurrency
	if workerCount > len(servers) && len(servers) > 0 {
		workerCount = len(servers)
	}
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go worker()
	}
	for i := range servers {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// CheckOne проверяет один сервер (публичная обёртка — используется
// как для полного скана, так и для точечного ре-чека одного сервера
// из relay.Manager).
func CheckOne(s ssuri.Server, timeout time.Duration) Result {
	return checkOne(s, timeout)
}

// DeepVerifyAll делает настоящую проверку каждого сервера: реальное
// Shadowsocks-подключение и HTTP-запрос через туннель наружу (см.
// ssclient.VerifyHandshake). Обычно применяется к уже прошедшим
// быструю TCP-проверку серверам (CheckAll) — так остаётся заметно
// меньше кандидатов, и более тяжёлая проверка не превращается в
// узкое место. Возвращает результаты в том же порядке, что и вход.
func DeepVerifyAll(servers []ssuri.Server, opts Options, onProgress ProgressFunc) []Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}

	results := make([]Result, len(servers))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	total := len(servers)

	worker := func() {
		defer wg.Done()
		for i := range jobs {
			s := servers[i]
			latency, err := ssclient.VerifyHandshake(s, opts.Timeout)
			r := Result{Server: s, Latency: latency, Err: err, Alive: err == nil}
			results[i] = r
			if onProgress != nil {
				mu.Lock()
				done++
				onProgress(done, total, r)
				mu.Unlock()
			}
		}
	}

	workerCount := opts.Concurrency
	if workerCount > len(servers) && len(servers) > 0 {
		workerCount = len(servers)
	}
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go worker()
	}
	for i := range servers {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

func checkOne(s ssuri.Server, timeout time.Duration) Result {
	addr := net.JoinHostPort(s.Host, itoa(s.Port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	latency := time.Since(start)
	if err != nil {
		return Result{Server: s, Alive: false, Latency: latency, Err: err}
	}
	_ = conn.Close()
	return Result{Server: s, Alive: true, Latency: latency}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
