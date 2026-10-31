//go:build windows

package winui

import "proxycheck/internal/app"

func appAuto(min int, onStart bool) app.AutoSettings {
	return app.AutoSettings{ScanMin: min, ScanOnStart: onStart}
}
