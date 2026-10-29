package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestGithubParts(t *testing.T) {
	u, _ := url.Parse("https://raw.githubusercontent.com/o/r/main/dir/file.txt")
	o, r, ref, p, ok := githubParts(u)
	if !ok || o != "o" || r != "r" || ref != "main" || p != "dir/file.txt" {
		t.Fatal(o, r, ref, p, ok)
	}
	u, _ = url.Parse("https://github.com/o/r/blob/dev/a/b.txt")
	if _, _, ref, p, ok := githubParts(u); !ok || ref != "dev" || p != "a/b.txt" {
		t.Fatal(ref, p, ok)
	}
	u, _ = url.Parse("https://example.com/x")
	if _, _, _, _, ok := githubParts(u); ok {
		t.Fatal("не github")
	}
}

func TestRemoteDateLastModified(t *testing.T) {
	want := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", want.Format(http.TimeFormat))
	}))
	defer ts.Close()
	got, src, err := RemoteDate(context.Background(), ts.URL+"/sub")
	if err != nil || !got.Equal(want) || src != "last-modified" {
		t.Fatal(got, src, err)
	}
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts2.Close()
	if _, _, err := RemoteDate(context.Background(), ts2.URL); err == nil {
		t.Fatal("без заголовка должна быть ошибка")
	}
	if _, _, err := RemoteDate(context.Background(), "ftp://x"); err == nil {
		t.Fatal("только http(s)")
	}
}
