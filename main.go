// Command proxycheck — чекер и клиент публичных Shadowsocks-прокси.
//
// Без аргументов запускает графический интерфейс (GUI) — если сборка
// его поддерживает (см. gui_enabled.go / gui_disabled.go и тег nogui).
// С любыми аргументами работает как консольная утилита — см. -h.
package main

import (
	"fmt"
	"os"

	"proxycheck/internal/cli"
	"proxycheck/internal/debugflag"
)

// RunOptions — параметры автозапуска GUI, независимые от пакета
// internal/gui, чтобы main.go собирался и в nogui-сборках, не таща
// cgo-зависимости.
type RunOptions struct {
	AutoStart      bool
	StartMinimized bool
}

func main() {
	args := stripDebugFlag(os.Args[1:])

	if isWebMode(args) {
		os.Exit(runWeb(args))
	}

	if len(args) == 0 {
		if !guiAvailable {
			// сборка без окна (Linux/Raspberry): по умолчанию — веб-интерфейс
			os.Exit(runWeb(nil))
		}
		runGUI(RunOptions{})
		return
	}

	opts, rest, isGUI := parseGUIArgs(args)
	if isGUI {
		if !guiAvailable {
			fmt.Println("Эта сборка без GUI (тег nogui).")
			os.Exit(1)
		}
		runGUI(opts)
		return
	}

	os.Exit(cli.Run(rest))
}

// stripDebugFlag ищет -debug/--debug среди аргументов, включает
// debugflag.Enabled() и убирает флаг из списка — дальше он и GUI-, и
// CLI-парсерам аргументов не нужен (это не их забота), а флаг
// действует глобально сразу после этой функции.
func stripDebugFlag(args []string) []string {
	var rest []string
	for _, a := range args {
		if a == "-debug" || a == "--debug" {
			debugflag.Set(true)
			continue
		}
		rest = append(rest, a)
	}
	return rest
}

func parseGUIArgs(args []string) (RunOptions, []string, bool) {
	opts := RunOptions{}
	guiFlagsOnly := true
	var rest []string
	for _, a := range args {
		switch a {
		case "-gui-autostart", "--gui-autostart":
			opts.AutoStart = true
		case "-gui-tray", "--gui-tray":
			opts.StartMinimized = true
			opts.AutoStart = true
		default:
			guiFlagsOnly = false
			rest = append(rest, a)
		}
	}
	return opts, rest, guiFlagsOnly
}
