//go:build !windows

package main

// Вне Windows нативного окна нет: по умолчанию запускается веб-интерфейс.
const guiAvailable = false

func runGUI(_ RunOptions) {}
