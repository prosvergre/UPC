package ssclient

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"proxycheck/internal/ssuri"
)

// readHTTPResponse читает HTTP-ответ построчно и корректно учитывает
// заголовок Content-Length — читает РОВНО столько байт тела, сколько
// заявлено, вместо того чтобы ждать закрытия соединения (EOF).
//
// Это важно: некоторые сервисы (в том числе за CDN вроде Cloudflare)
// не закрывают TLS-соединение мгновенно после отправки тела даже при
// заголовке "Connection: close" от клиента — может быть небольшая
// задержка перед фактическим FIN. Чтение до EOF в таком случае
// блокируется до таймаута, хотя все нужные данные уже пришли. Именно
// это оказалось причиной, почему VerifyHandshake (которому достаточно
// первых байт ответа) работал стабильно, а DetectExitIP (который ждал
// EOF) — нет.
func readHTTPResponse(r io.Reader, maxBody int) (statusLine string, body []byte, err error) {
	reader := bufio.NewReader(r)

	statusLine, err = reader.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("чтение статус-строки: %w", err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")

	contentLength := -1
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return statusLine, nil, fmt.Errorf("чтение заголовков: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // конец заголовков
		}
		if idx := strings.IndexByte(line, ':'); idx != -1 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			if key == "content-length" {
				if n, e := strconv.Atoi(strings.TrimSpace(line[idx+1:])); e == nil {
					contentLength = n
				}
			}
		}
	}

	if contentLength >= 0 {
		if contentLength > maxBody {
			contentLength = maxBody
		}
		body = make([]byte, contentLength)
		if _, err := io.ReadFull(reader, body); err != nil {
			return statusLine, nil, fmt.Errorf("чтение тела (Content-Length=%d): %w", contentLength, err)
		}
		return statusLine, body, nil
	}

	// заголовка Content-Length нет — читаем до EOF или лимита как раньше
	// (лучшее, что можно сделать без chunked-парсера)
	body, err = io.ReadAll(io.LimitReader(reader, int64(maxBody)))
	if err != nil && len(body) == 0 {
		return statusLine, nil, fmt.Errorf("чтение тела: %w", err)
	}
	return statusLine, body, nil
}

// verifyTargetHost/Port — фиксированная цель для глубокой проверки:
// www.gstatic.com/generate_204 по HTTPS (порт 443) — тот же самый
// эндпоинт и та же схема, которую используют Android и ChromeOS для
// проверки интернет-соединения. Порт 443 — сознательный выбор: почти
// весь реальный интернет-трафик (браузеры, Proxifier-тесты, приложения)
// идёт по HTTPS/TLS, а не по голому HTTP. Проверка только через порт
// 80 (как было раньше) оказалась слишком мягкой: некоторые публичные
// сервера пропускают простой HTTP, но режут или не тянут настоящий
// TLS-трафик — из-за этого чекер отмечал их живыми, а Proxifier и
// реальные приложения по HTTPS корректно видели их мёртвыми.
const (
	verifyTargetHost = "www.gstatic.com"
	verifyTargetPort = 443
)

// VerifyHandshake устанавливает реальное соединение через Shadowsocks-
// сервер, проводит настоящий TLS-хендшейк (с полной проверкой
// сертификата — как настоящий браузер) и отправляет минимальный
// HTTPS-запрос на известный лёгкий эндпоинт, проверяя, что получен
// ответ. В отличие от простого TCP-коннекта (порт открыт) или
// проверки только на голом HTTP (порт 80), это подтверждает, что
// сервер реально Shadowsocks, метод/пароль верны, и — что важнее
// всего — что через него проходит настоящий HTTPS-трафик, как в
// подавляющем большинстве реального использования.
func VerifyHandshake(server ssuri.Server, timeout time.Duration) (time.Duration, error) {
	cfg := &tls.Config{ServerName: verifyTargetHost}
	return verifyHandshakeWithConfig(server, verifyTargetHost, verifyTargetPort, cfg, timeout)
}

// verifyHandshakeWithConfig — параметризованная реализация: принимает
// готовый *tls.Config, чтобы юнит-тесты могли подставить локальный
// фейковый TLS-сервер с InsecureSkipVerify вместо реального
// www.gstatic.com, к которому нет доступа из тестовой среды. Боевой
// путь (VerifyHandshake) всегда использует полную проверку сертификата.
func verifyHandshakeWithConfig(server ssuri.Server, targetHost string, targetPort int, tlsCfg *tls.Config, timeout time.Duration) (time.Duration, error) {
	start := time.Now()

	targetAddr := encodeDomainTarget(targetHost, targetPort)
	rawConn, err := Dial(server, targetAddr, timeout)
	if err != nil {
		return 0, fmt.Errorf("подключение к серверу: %w", err)
	}
	defer rawConn.Close()

	if err := rawConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return 0, fmt.Errorf("TLS-хендшейк через туннель не удался (сервер не проксирует HTTPS-трафик): %w", err)
	}

	req := fmt.Sprintf("GET /generate_204 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return 0, fmt.Errorf("отправка запроса через туннель: %w", err)
	}

	buf := make([]byte, 64)
	n, err := tlsConn.Read(buf)
	if err != nil && n == 0 {
		return 0, fmt.Errorf("нет ответа через туннель после TLS-хендшейка: %w", err)
	}
	if n == 0 {
		return 0, fmt.Errorf("пустой ответ через туннель")
	}

	return time.Since(start), nil
}

// encodeDomainTarget кодирует домен+порт в формат ATYP+ADDR+PORT,
// который ожидает Dial (тот же формат, что отдаёт наш SOCKS5-сервер
// для доменных адресов).
func encodeDomainTarget(host string, port int) []byte {
	out := make([]byte, 0, 1+1+len(host)+2)
	out = append(out, 0x03, byte(len(host)))
	out = append(out, []byte(host)...)
	out = append(out, byte(port>>8), byte(port))
	return out
}

// exitIPHost — сервис, возвращающий IP-адрес входящего запроса в виде
// простого текста (без JSON и прочего) — специально для таких задач,
// широко используется именно в этом качестве.
const exitIPHost = "api.ipify.org"

// DetectExitIP определяет, каким IP-адресом сервер "выходит" в
// интернет — устанавливает TLS-туннель (та же инфраструктура, что и
// VerifyHandshake) и делает лёгкий запрос к сервису, возвращающему
// просто IP как текст. Не влияет на решение "жив/мёртв" — вызывать
// только для уже подтверждённых VerifyHandshake серверов; ошибка здесь
// не должна считаться поводом считать сервер нерабочим (это просто
// дополнительная информация, а не критерий живости).
func DetectExitIP(server ssuri.Server, timeout time.Duration) (string, error) {
	cfg := &tls.Config{ServerName: exitIPHost}
	return detectExitIPWithConfig(server, exitIPHost, 443, cfg, timeout)
}

func detectExitIPWithConfig(server ssuri.Server, targetHost string, targetPort int, tlsCfg *tls.Config, timeout time.Duration) (string, error) {
	targetAddr := encodeDomainTarget(targetHost, targetPort)
	rawConn, err := Dial(server, targetAddr, timeout)
	if err != nil {
		return "", fmt.Errorf("подключение к серверу: %w", err)
	}
	defer rawConn.Close()

	if err := rawConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return "", fmt.Errorf("TLS-хендшейк не удался: %w", err)
	}

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return "", fmt.Errorf("отправка запроса: %w", err)
	}

	_, body, err := readHTTPResponse(tlsConn, 4096)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("сервис вернул не похожее на IP значение: %q", ip)
	}
	return ip, nil
}
