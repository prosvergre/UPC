//go:build !nogui

package main

import "proxycheck/internal/gui"

const guiAvailable = true

func runGUI(opts RunOptions) {
	gui.Run(gui.RunOptions{
		AutoStart:      opts.AutoStart,
		StartMinimized: opts.StartMinimized,
	})
}
