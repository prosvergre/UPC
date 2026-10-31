//go:build windows

package main

import (
	"proxycheck/internal/app"
	"proxycheck/internal/settings"
	"proxycheck/internal/winui"
)

const guiAvailable = true

// runGUI открывает нативное окно Windows поверх ядра приложения.
func runGUI(opts RunOptions) {
	a := app.New(settings.DefaultPath())
	stop := make(chan struct{})
	go a.Run(stop)
	winui.Run(a, winui.Options{StartMinimized: opts.StartMinimized})
	close(stop)
}
