//go:build windows

package main

import (
	"os"
	"syscall"
)

// Сборка с -H=windowsgui не имеет консоли: при запуске с аргументами
// (CLI, -web, справка) подключаемся к консоли родительского процесса,
// чтобы вывод был виден в cmd/PowerShell.
func init() {
	if len(os.Args) < 2 {
		return
	}
	k := syscall.NewLazyDLL("kernel32.dll")
	attach := k.NewProc("AttachConsole")
	const attachParent = ^uintptr(0) // ATTACH_PARENT_PROCESS = -1
	if r, _, _ := attach.Call(attachParent); r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
}
