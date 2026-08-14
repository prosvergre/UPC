//go:build nogui

// Сборка с тегом nogui: используется для платформ/окружений без cgo и
// X11/OpenGL (например, ARM64-CLI без десктопного окружения).
package main

const guiAvailable = false

func runGUI(_ RunOptions) {
	// не должно вызываться — main.go проверяет guiAvailable раньше
}
