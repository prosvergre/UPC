package gui

import (
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

// logBuffer — потокобезопасный накопитель строк лога для вкладки "Логи".
type logBuffer struct {
	mu     sync.Mutex
	lines  []string
	widget *widget.Entry
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.lines = append(b.lines, strings.TrimRight(string(p), "\n"))
	if len(b.lines) > 2000 {
		b.lines = b.lines[len(b.lines)-2000:]
	}
	text := strings.Join(b.lines, "\n")
	b.mu.Unlock()

	if b.widget != nil {
		fyne.Do(func() {
			b.widget.SetText(text)
			b.widget.CursorRow = len(b.lines)
		})
	}
	return len(p), nil
}

// trayFailureDetector — io.Writer, который ничего никуда не пишет
// сам по себе, а просто следит за проходящими через log строками:
// если видит "systray error", запоминает это через атомарный флаг.
// Официального способа узнать "получилось ли у трея" в Fyne нет —
// библиотека systray просто логирует ошибку при сбое инициализации,
// поэтому мы её перехватываем как единственный доступный сигнал.
type trayFailureDetector struct {
	failed atomic.Bool
}

func (d *trayFailureDetector) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "systray error") {
		d.failed.Store(true)
	}
	return len(p), nil
}

func (d *trayFailureDetector) Failed() bool { return d.failed.Load() }

// stderrWrite пишет напрямую в os.Stderr — вынесено в отдельную
// маленькую функцию, чтобы logWriterStderr (в gui.go) не тянул os
// прямо в основной файл и было явно видно назначение при чтении кода.
func stderrWrite(p []byte) (int, error) {
	return os.Stderr.Write(p)
}

// safeMultiWriter — как io.MultiWriter, но НЕ прерывается, если один
// из writer'ов вернул ошибку. Это важно: в GUI-сборке под Windows
// (субсистема windowsgui, без консоли) запись в os.Stderr может
// вернуть ошибку из-за отсутствия консоли — стандартный io.MultiWriter
// в этом случае молча прекращает запись во ВСЕ последующие writer'ы,
// включая наш виджет логов. Из-за этого вкладка "Логи" была пустой
// даже при реальных ошибках соединения.
type safeMultiWriter struct {
	writers []io.Writer
}

func (m safeMultiWriter) Write(p []byte) (int, error) {
	for _, w := range m.writers {
		_, _ = w.Write(p) // ошибку одного writer'а игнорируем, остальные всё равно должны получить лог
	}
	return len(p), nil
}
