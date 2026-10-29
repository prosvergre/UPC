package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RemoteDate узнаёт, когда файл по ссылке обновлялся на удалённой стороне, без
// скачивания тела. Для raw-ссылок GitHub берётся дата последнего коммита,
// трогавшего файл (у raw нет Last-Modified); для остальных — заголовок
// Last-Modified. Если дату узнать нельзя, возвращается ошибка.
func RemoteDate(ctx context.Context, rawURL string) (time.Time, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return time.Time{}, "", fmt.Errorf("некорректная ссылка")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if owner, repo, ref, path, ok := githubParts(u); ok {
		if t, err := githubCommitDate(ctx, client, owner, repo, ref, path); err == nil {
			return t, "github-commit", nil
		}
	}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, _ := http.NewRequestWithContext(ctx, method, rawURL, nil)
		req.Header.Set("User-Agent", "proxycheck")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if lm := resp.Header.Get("Last-Modified"); lm != "" {
			if t, err := http.ParseTime(lm); err == nil {
				return t, "last-modified", nil
			}
		}
	}
	return time.Time{}, "", fmt.Errorf("сервер не сообщает дату обновления")
}

// githubParts разбирает raw.githubusercontent.com/o/r/ref/path и github.com/o/r/(raw|blob)/ref/path.
func githubParts(u *url.URL) (owner, repo, ref, path string, ok bool) {
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	switch u.Host {
	case "raw.githubusercontent.com":
		if len(parts) >= 4 {
			return parts[0], parts[1], parts[2], strings.Join(parts[3:], "/"), true
		}
	case "github.com":
		if len(parts) >= 5 && (parts[2] == "raw" || parts[2] == "blob") {
			return parts[0], parts[1], parts[3], strings.Join(parts[4:], "/"), true
		}
	}
	return
}

func githubCommitDate(ctx context.Context, c *http.Client, owner, repo, ref, path string) (time.Time, error) {
	api := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?path=%s&sha=%s&per_page=1",
		url.PathEscape(owner), url.PathEscape(repo), url.QueryEscape(path), url.QueryEscape(ref))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "proxycheck")
	resp, err := c.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return time.Time{}, fmt.Errorf("github api: HTTP %d", resp.StatusCode)
	}
	var commits []struct {
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil || len(commits) == 0 {
		return time.Time{}, fmt.Errorf("github api: нет коммитов")
	}
	return commits[0].Commit.Committer.Date, nil
}
