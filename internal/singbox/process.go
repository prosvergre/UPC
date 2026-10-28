package singbox

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// Process — один запущенный процесс sing-box со сторожем: при неожиданном
// падении перезапускается с тем же конфигом (но не чаще, чем раз в backoff).
type Process struct {
	Binary  string
	WorkDir string
	Logf    func(format string, args ...interface{})

	mu       sync.Mutex
	cmd      *exec.Cmd
	cfgPath  string
	stopped  bool
	restarts int
	done     chan struct{}
}

// Start записывает конфиг и запускает процесс. Возвращает ошибку, если
// конфиг не прошёл проверку (sing-box check) или процесс сразу завершился.
func (p *Process) Start(cfg []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil {
		return fmt.Errorf("sing-box уже запущен")
	}
	if p.Logf == nil {
		p.Logf = func(string, ...interface{}) {}
	}
	if err := os.MkdirAll(p.WorkDir, 0o755); err != nil {
		return err
	}
	p.cfgPath = filepath.Join(p.WorkDir, "config.json")
	if err := os.WriteFile(p.cfgPath, cfg, 0o600); err != nil {
		return err
	}
	if out, err := exec.Command(p.Binary, "check", "-c", p.cfgPath).CombinedOutput(); err != nil {
		return fmt.Errorf("конфиг не прошёл проверку: %v: %s", err, out)
	}
	p.stopped = false
	p.done = make(chan struct{})
	if err := p.spawn(); err != nil {
		return err
	}
	go p.watch()
	return nil
}

func (p *Process) spawn() error {
	cmd := exec.Command(p.Binary, "run", "-c", p.cfgPath, "-D", p.WorkDir)
	hideWindow(cmd)
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск sing-box: %w", err)
	}
	p.cmd = cmd
	pump := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			p.Logf("[sing-box] %s", sc.Text())
		}
	}
	go pump(stderr)
	go pump(stdout)
	return nil
}

func (p *Process) watch() {
	backoff := time.Second
	for {
		p.mu.Lock()
		cmd := p.cmd
		p.mu.Unlock()
		if cmd == nil {
			return
		}
		started := time.Now()
		err := cmd.Wait()
		p.mu.Lock()
		if p.stopped {
			p.mu.Unlock()
			close(p.done)
			return
		}
		p.Logf("sing-box завершился неожиданно (%v), перезапуск через %v", err, backoff)
		p.mu.Unlock()
		time.Sleep(backoff)
		if time.Since(started) > time.Minute {
			backoff = time.Second
		} else if backoff < 30*time.Second {
			backoff *= 2
		}
		p.mu.Lock()
		if p.stopped {
			p.mu.Unlock()
			close(p.done)
			return
		}
		p.restarts++
		if err := p.spawn(); err != nil {
			p.Logf("перезапуск не удался: %v", err)
		}
		p.mu.Unlock()
	}
}

// Restarts — сколько раз сторож перезапускал процесс.
func (p *Process) Restarts() int { p.mu.Lock(); defer p.mu.Unlock(); return p.restarts }

// Running сообщает, запущен ли процесс.
func (p *Process) Running() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.cmd != nil && !p.stopped }

// Stop останавливает процесс и сторож.
func (p *Process) Stop() {
	p.mu.Lock()
	if p.cmd == nil || p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	cmd := p.cmd
	done := p.done
	p.mu.Unlock()
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	p.mu.Lock()
	p.cmd = nil
	p.mu.Unlock()
}

// WaitReady ждёт, пока Clash API начнёт отвечать.
func WaitReady(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return fmt.Errorf("sing-box не поднял API на %s за %v", addr, timeout)
}
