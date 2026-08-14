// Package sources содержит список GitHub-репозиториев с публичными
// списками Shadowsocks-серверов и функции для их загрузки.
//
// ВАЖНО: структура файлов в этих репозиториях иногда меняется (авторы
// переименовывают ветки/файлы). Если какой-то источник перестал
// отдавать данные — обновите URL здесь или добавьте свой через --source.
package sources

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// Source описывает один источник подписки.
type Source struct {
	Name string // короткое имя для логов
	URL  string // прямая (raw) ссылка на файл
}

// Default — список проверенных долгоживущих (2+ года) репозиториев.
var Default = []Source{
	{Name: "Pawdroid/Free-servers", URL: "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"},
	{Name: "freefq/free", URL: "https://raw.githubusercontent.com/freefq/free/master/v2"},
	{Name: "mahdibland/V2RayAggregator", URL: "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"},
	{Name: "ermaozi/get_subscribe", URL: "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"},
	{Name: "zengfr/free-vpn-subscribe", URL: "https://raw.githubusercontent.com/zengfr/free-vpn-subscribe/main/vpn_sub_raw_shadowsocks.txt"},
	{Name: "peasoft/NoMoreWalls", URL: "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt"},
}

// Fetch скачивает содержимое одного источника с таймаутом.
func Fetch(client *http.Client, src Source, timeout time.Duration) (string, error) {
	req, err := http.NewRequest(http.MethodGet, src.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxycheck/1.0 (+https://github.com/)")

	ctxClient := client
	if ctxClient == nil {
		ctxClient = &http.Client{Timeout: timeout}
	}
	resp, err := ctxClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: %w", src.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", src.Name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // максимум 32 МБ
	if err != nil {
		return "", fmt.Errorf("%s: чтение тела ответа: %w", src.Name, err)
	}
	return string(body), nil
}

// FetchResult — результат загрузки одного источника (для параллельной загрузки).
type FetchResult struct {
	Source Source
	Body   string
	Err    error
}

// FetchAll параллельно загружает все источники.
func FetchAll(list []Source, timeout time.Duration) []FetchResult {
	client := &http.Client{Timeout: timeout}
	results := make([]FetchResult, len(list))
	done := make(chan int, len(list))

	for i, src := range list {
		go func(i int, src Source) {
			body, err := Fetch(client, src, timeout)
			results[i] = FetchResult{Source: src, Body: body, Err: err}
			done <- i
		}(i, src)
	}
	for range list {
		<-done
	}
	return results
}
