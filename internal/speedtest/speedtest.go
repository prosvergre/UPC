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

// DefaultUploadBytes — верхний предел суммарного объёма для замера upload.
const DefaultUploadBytes = 8 * 1024 * 1024

// Upload измеряет скорость отдачи (upload) через SOCKS5-прокси на localAddr.
//
// Один большой POST на медленном прокси упирался в таймаут и давал просто
// «ошибку» без результата. Поэтому данные отправляются последовательными
// кусками растущего размера (128 КБ … 4 МБ) по одному keep-alive соединению,
// пока не выйдет время (timeout) или не кончится лимит nBytes. Результат —
// скорость самого быстрого куска (когда соединение «разогналось»), так что
// медленный сервер тоже получает измеренное, пусть и небольшое, число.
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
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	deadline := time.Now().Add(timeout)
	var best Result
	var sent int
	var lastErr error
	for _, n := range []int{128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20, 4 << 20} {
		if sent+n > nBytes && sent > 0 {
			break
		}
		remaining := time.Until(deadline)
		if remaining < 700*time.Millisecond && best.Bytes > 0 {
			break
		}
		if remaining <= 0 {
			lastErr = fmt.Errorf("время вышло")
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		res, err := uploadChunk(ctx, client, uploadURL, n)
		cancel()
		if err != nil {
			lastErr = err
			break
		}
		sent += n
		if res.Mbps > best.Mbps {
			best = res
		}
		if res.Duration > 3*time.Second { // уже устоявшаяся скорость, дальше только дольше
			break
		}
	}
	if best.Bytes == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("нет результата")
		}
		return Result{}, fmt.Errorf("upload: %v", lastErr)
	}
	return best, nil
}

func uploadChunk(ctx context.Context, client *http.Client, url string, n int) (Result, error) {
	payload := make([]byte, n)
	if _, err := rand.Read(payload); err != nil {
		return Result{}, fmt.Errorf("генерация данных: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return Result{}, err
	}
	req.ContentLength = int64(n)
	req.Header.Set("Content-Type", "application/octet-stream")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("запрос через прокси: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	elapsed := time.Since(start)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("неожиданный статус ответа: %d", resp.StatusCode)
	}
	mbps := 0.0
	if elapsed > 0 {
		mbps = (float64(n) * 8 / 1_000_000) / elapsed.Seconds()
	}
	return Result{Bytes: int64(n), Duration: elapsed, Mbps: mbps}, nil
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
