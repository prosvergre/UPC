package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"proxycheck/internal/app"
	"proxycheck/internal/settings"
	"proxycheck/internal/web"
)

// isWebMode сообщает, что запрошен веб-режим (или пароль веб-интерфейса).
func isWebMode(args []string) bool {
	for _, a := range args {
		switch strings.TrimLeft(a, "-") {
		case "web", "set-web-password":
			return true
		}
	}
	return false
}

// runWeb запускает веб-интерфейс: ядро приложения + HTTP-сервер.
func runWeb(args []string) int {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	fs.Bool("web", true, "запустить веб-интерфейс")
	addr := fs.String("web-addr", "", "адрес веб-интерфейса (по умолчанию из настроек или 127.0.0.1:8080)")
	cert := fs.String("web-cert", "", "файл сертификата TLS (включает HTTPS)")
	key := fs.String("web-key", "", "файл ключа TLS")
	setPw := fs.Bool("set-web-password", false, "задать пароль веб-интерфейса (читается из stdin) и выйти")
	noOpen := fs.Bool("no-browser", false, "не открывать браузер автоматически")
	fs.Parse(args)

	a := app.New(settings.DefaultPath())

	if *setPw {
		fmt.Fprint(os.Stderr, "Новый пароль веб-интерфейса: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		pw := strings.TrimRight(line, "\r\n")
		if len(pw) < 8 {
			fmt.Fprintln(os.Stderr, "пароль должен быть не короче 8 символов")
			return 1
		}
		h, err := web.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		a.UpdateSettings(func(s *settings.Settings) { s.WebPasswordHash = h })
		fmt.Println("Пароль сохранён.")
		return 0
	}

	listen := *addr
	if listen == "" {
		listen = a.Settings().WebListen
	}
	if listen == "" {
		listen = "127.0.0.1:8080"
	}
	srv := web.New(a)
	if err := srv.Check(listen); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	scheme := "http"
	if *cert != "" && *key != "" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, listen)
	fmt.Println("Веб-интерфейс:", url)

	stopSched := make(chan struct{})
	go a.Run(stopSched)
	defer close(stopSched)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe(listen, *cert, *key) }()
	if !*noOpen && web.IsLoopback(listen) {
		openBrowser(url)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		fmt.Fprintln(os.Stderr, "ошибка сервера:", err)
		a.Shutdown()
		return 1
	case <-sig:
		fmt.Println("\nОстанавливаюсь...")
		a.Shutdown()
		return 0
	}
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}
