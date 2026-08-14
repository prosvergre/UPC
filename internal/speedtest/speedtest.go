// Package speedtest измеряет скорость скачивания через уже поднятый
// локальный SOCKS5-вход (relay.Endpoint) — качает файл известного
// размера по HTTP(S) через прокси и считает Кбит/с.
package speedtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

// DefaultTestURL — файл фиксированного размера для замера скорости.
// Cloudflare отдаёт такие файлы стабильно и без авторизации. Размер
// уменьшен с 10 до 5 МБ: на медленных или намеренно дросселируемых
// (анти-абузных) прокси-серверах 10 МБ иногда не успевали скачаться
// в разумный таймаут, из-за чего честно рабочий прокси показывал "—"
// вместо реальной (пусть и низкой) скорости.
const DefaultTestURL = "https://speed.cloudflare.com/__down?bytes=5000000" // 5 МБ

// Result — результат замера.
type Result struct {
	Bytes    int64
	Duration time.Duration
	Mbps     float64 // мегабит/с (скачивание)
}

// DefaultUploadURL — приёмник для замера скорости отдачи (upload).
// Тот же сервис Cloudflare speedtest, что и для скачивания — просто
// принимает POST-тело и не проверяет содержимое.
const DefaultUploadURL = "https://speed.cloudflare.com/__up"

// DefaultUploadBytes — сколько байт отправляем для замера upload.
// Раньше было 2 МБ (заметно меньше, чем 5 МБ на download) — при
// типичной для публичных прокси задержке в 300-500ms такой маленький
// объём во многом уходит на разгон TCP (slow start) и не успевает
// показать реальную устоявшуюся скорость, из-за чего числа выглядели
// подозрительно заниженными. Уравнял с объёмом download, чтобы оба
// замера были сопоставимы по методике.
const DefaultUploadBytes = 5 * 1024 * 1024

// Upload измеряет скорость отдачи (upload) через SOCKS5-прокси на
// localAddr — отправляет nBytes случайных данных на uploadURL POST-ом
// и считает скорость по времени до завершения запроса.
func Upload(localSocksAddr, uploadURL string, nBytes int, timeout time.Duration) (Result, error) {
	if uploadURL == "" {
		uploadURL = DefaultUploadURL
	}
	if nBytes <= 0 {
		nBytes = DefaultUploadBytes
	}
	dialer, err := proxy.SOCKS5("tcp", localSocksAddr, nil, proxy.Direct)
	if err != nil {
		return Result{}, fmt.Errorf("создание SOCKS5-dialer: %w", err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	payload := make([]byte, nBytes)
	if _, err := rand.Read(payload); err != nil {
		return Result{}, fmt.Errorf("генерация тестовых данных: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	req.ContentLength = int64(nBytes)
	req.Header.Set("Content-Type", "application/octet-stream")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("запрос через прокси: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // дочитываем тело ответа, чтобы соединение корректно переиспользовалось/закрылось
	elapsed := time.Since(start)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("неожиданный статус ответа: %d", resp.StatusCode)
	}

	mbps := 0.0
	if elapsed > 0 {
		mbps = (float64(nBytes) * 8 / 1_000_000) / elapsed.Seconds()
	}

	return Result{Bytes: int64(nBytes), Duration: elapsed, Mbps: mbps}, nil
}

// "127.0.0.1:1080") и измеряет скорость. maxBytes ограничивает объём
// скачивания (0 = докачать файл целиком, если сервер отдаёт
// Content-Length меньше — качаем сколько есть).
func Download(localSocksAddr, testURL string, timeout time.Duration) (Result, error) {
	if testURL == "" {
		testURL = DefaultTestURL
	}
	dialer, err := proxy.SOCKS5("tcp", localSocksAddr, nil, proxy.Direct)
	if err != nil {
		return Result{}, fmt.Errorf("создание SOCKS5-dialer: %w", err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	req, err := http.NewRequest(http.MethodGet, testURL, nil)
	if err != nil {
		return Result{}, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("запрос через прокси: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return Result{}, fmt.Errorf("неожиданный статус ответа: %d", resp.StatusCode)
	}

	n, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)
	if err != nil && n == 0 {
		return Result{}, fmt.Errorf("чтение тела ответа: %w", err)
	}

	mbps := 0.0
	if elapsed > 0 {
		mbps = (float64(n) * 8 / 1_000_000) / elapsed.Seconds()
	}

	return Result{Bytes: n, Duration: elapsed, Mbps: mbps}, nil
}
