package ssclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"proxycheck/internal/ssuri"
)

// HTTPGetThroughTunnel устанавливает TLS-туннель через Shadowsocks-
// сервер (та же инфраструктура, что и VerifyHandshake/DetectExitIP) и
// делает HTTPS GET-запрос, возвращая СЫРОЕ тело ответа как есть — без
// предположений о формате (годится и для текста, и для бинарных
// протоколов вроде DNS-over-HTTPS wire-format).
func HTTPGetThroughTunnel(server ssuri.Server, host string, port int, path string, headers map[string]string, timeout time.Duration) ([]byte, error) {
	cfg := &tls.Config{ServerName: host}
	return httpGetThroughTunnelWithConfig(server, host, port, path, headers, cfg, timeout)
}

// HTTPGetThroughTunnelWithTLSConfig — версия с настраиваемым
// *tls.Config, экспортирована специально для юнит-тестов ДРУГИХ
// пакетов (например internal/localdns), которым нужно подставить
// InsecureSkipVerify для локального тестового TLS-сервера с
// самоподписанным сертификатом. В боевом коде используйте
// HTTPGetThroughTunnel — он всегда проверяет сертификат по-настоящему.
func HTTPGetThroughTunnelWithTLSConfig(server ssuri.Server, host string, port int, path string, headers map[string]string, tlsCfg *tls.Config, timeout time.Duration) ([]byte, error) {
	return httpGetThroughTunnelWithConfig(server, host, port, path, headers, tlsCfg, timeout)
}

func httpGetThroughTunnelWithConfig(server ssuri.Server, host string, port int, path string, headers map[string]string, tlsCfg *tls.Config, timeout time.Duration) ([]byte, error) {
	targetAddr := encodeDomainTarget(host, port)
	rawConn, err := Dial(server, targetAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("подключение к серверу: %w", err)
	}
	defer rawConn.Close()

	if err := rawConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS-хендшейк не удался: %w", err)
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", path, host)
	for k, v := range headers {
		req += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	req += "\r\n"

	if _, err := io.WriteString(tlsConn, req); err != nil {
		return nil, fmt.Errorf("отправка запроса: %w", err)
	}

	statusLine, body, err := readHTTPResponse(tlsConn, 64*1024)
	if err != nil {
		return nil, err
	}
	if !isHTTPOK(statusLine) {
		return nil, fmt.Errorf("неожиданный ответ сервера: %s", statusLine)
	}
	return body, nil
}

func isHTTPOK(statusLine string) bool {
	// statusLine выглядит как "HTTP/1.1 200 OK" — считаем успехом любой 2xx
	return len(statusLine) >= 12 && statusLine[9] == '2'
}
