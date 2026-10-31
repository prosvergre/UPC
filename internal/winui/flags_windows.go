//go:build windows

package winui

import (
	"bytes"
	"embed"
	"image/png"
	"strings"
	"sync"

	"github.com/tailscale/walk"
)

//go:embed flags/*.png
var flagFS embed.FS

type flagKey struct {
	code string
	dpi  int
}

var (
	flagMu    sync.Mutex
	flagCache = map[flagKey]*walk.Bitmap{}
)

// flagBitmap возвращает растр флага для DPI (nil, если флага нет).
func flagBitmap(code string, dpi int) *walk.Bitmap {
	code = strings.ToLower(code)
	k := flagKey{code, dpi}
	flagMu.Lock()
	defer flagMu.Unlock()
	if b, ok := flagCache[k]; ok {
		return b
	}
	var bmp *walk.Bitmap
	if data, err := flagFS.ReadFile("flags/" + code + ".png"); err == nil {
		if img, err := png.Decode(bytes.NewReader(data)); err == nil {
			bmp, _ = walk.NewBitmapFromImageForDPI(img, dpi)
		}
	}
	flagCache[k] = bmp
	return bmp
}
