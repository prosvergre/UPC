package ssclient

import (
	"fmt"
	"net"
	"time"

	"proxycheck/internal/ssuri"
)

// Dial устанавливает TCP-соединение с Shadowsocks-сервером, оборачивает
// его AEAD-шифрованием и отправляет адрес назначения (targetAddr —
// уже закодирован в формате SOCKS5/Shadowsocks: ATYP+ADDR+PORT,
// см. пакет internal/socks5). Возвращает net.Conn, готовый для
// обычного io.Copy в обе стороны — расшифровка/шифровка прозрачны.
func Dial(server ssuri.Server, targetAddr []byte, timeout time.Duration) (net.Conn, error) {
	if !Supported(server.Method) {
		return nil, fmt.Errorf("метод %q не поддерживается (поддерживаются: %v)", server.Method, SupportedMethods())
	}
	addr := net.JoinHostPort(server.Host, portStr(server.Port))
	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("соединение с %s: %w", addr, err)
	}
	conn := NewConn(raw, server.Method, server.Password)

	if timeout > 0 {
		_ = raw.SetWriteDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write(targetAddr); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("отправка адреса назначения: %w", err)
	}
	if timeout > 0 {
		_ = raw.SetWriteDeadline(time.Time{})
	}
	return conn, nil
}

func portStr(p int) string {
	return fmt.Sprintf("%d", p)
}
