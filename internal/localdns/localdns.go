// Package localdns поднимает локальный DNS-резолвер (UDP:53),
// который резолвит запросы через уже настроенный Shadowsocks-туннель
// с помощью DNS-over-HTTPS (DoH) — так DNS-запросы тоже идут через
// прокси, а не напрямую с компьютера пользователя.
//
// Реализация нарочно простая и надёжная: мы НЕ парсим и не собираем
// DNS-сообщения сами (это отдельный протокол со своими тонкостями).
// Вместо этого используем "wire-format" DoH API (RFC 8484): исходный
// UDP-пакет DNS-запроса, как есть, кодируется в base64url и
// пробрасывается GET-запросом на DoH-сервер; тело ответа — уже
// полностью готовый DNS-ответ в том же wire-формате, который можно
// отправить клиенту как есть. Это даёт поддержку ЛЮБых типов записей
// (A, AAAA, MX, TXT и т.д.), а не только вручную реализованных.
package localdns

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"proxycheck/internal/debugflag"
	"proxycheck/internal/node"
)

// dohHost/Port — DNS-over-HTTPS сервер (Cloudflare). Поддерживает
// wire-format DoH (RFC 8484) через простой GET с параметром ?dns=.
const (
	dohHost = "cloudflare-dns.com"
	dohPort = 443
)

// Resolver — запущенный локальный DNS-резолвер.
type Resolver struct {
	conn    *net.UDPConn
	server  node.Node
	socks   string // адрес локального SOCKS5 (линии), через которую идёт DoH
	client  *http.Client
	timeout time.Duration
	stop    chan struct{}
}

// Start поднимает UDP-listener на localAddr (обычно "127.0.0.1:53") и
// начинает резолвить входящие запросы через server. Если порт уже
// занят другой программой (или недостаточно прав на bind) — возвращает
// ошибку, НЕ падая и не паникуя: вызывающий код должен залогировать и
// продолжить работу без локального DNS, а не прерывать программу.
func Start(localAddr string, socksAddr string, server node.Node, timeout time.Duration) (*Resolver, error) {
	addr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("разбор адреса %s: %w", localAddr, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("не удалось занять %s (порт занят другой программой?): %w", localAddr, err)
	}

	proxy, _ := url.Parse("socks5://" + socksAddr)
	r := &Resolver{conn: conn, server: server, socks: socksAddr, timeout: timeout, stop: make(chan struct{}),
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}}
	go r.loop()
	log.Printf("[dns] локальный резолвер запущен на %s, резолвит через %s", localAddr, server.Label())
	return r, nil
}

// Stop останавливает резолвер и освобождает порт.
func (r *Resolver) Stop() {
	close(r.stop)
	r.conn.Close()
}

// Server возвращает сервер, через который сейчас идёт резолвинг.
func (r *Resolver) Server() node.Node { return r.server }

func (r *Resolver) loop() {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.stop:
				return
			default:
				continue
			}
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go r.handle(query, clientAddr)
	}
}

func (r *Resolver) handle(query []byte, clientAddr *net.UDPAddr) {
	if debugflag.Enabled() {
		log.Printf("[dns][debug] запрос от %s, %d байт", clientAddr, len(query))
	}
	resp, err := r.resolveViaDoH(query)
	if err != nil {
		// стандартное поведение DNS при ошибке — просто не отвечать
		// (клиент сам обработает таймаут/повтор), но логируем для
		// диагностики
		log.Printf("[dns] ошибка резолва: %v", err)
		return
	}
	if _, err := r.conn.WriteToUDP(resp, clientAddr); err != nil {
		log.Printf("[dns] не удалось отправить ответ клиенту %s: %v", clientAddr, err)
	} else if debugflag.Enabled() {
		log.Printf("[dns][debug] ответ отправлен %s, %d байт", clientAddr, len(resp))
	}
}

// resolveViaDoH пробрасывает сырой DNS-запрос через DoH (RFC 8484, wire-format)
// поверх локальной линии (SOCKS5 sing-box).
func (r *Resolver) resolveViaDoH(rawQuery []byte) ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(rawQuery)
	u := fmt.Sprintf("https://%s:%d/dns-query?dns=%s", dohHost, dohPort, encoded)
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("DoH: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}
