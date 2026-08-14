// Package debugflag хранит один глобальный флаг подробного логирования
// (--debug), который могут читать любые другие пакеты (relay, localdns
// и т.д.) без риска циклических импортов — main.go/cli.go/gui.go
// устанавливают его один раз при старте по флагу командной строки.
package debugflag

import "sync/atomic"

var enabled atomic.Bool

// Set включает/выключает подробное логирование глобально.
func Set(v bool) { enabled.Store(v) }

// Enabled сообщает, включён ли --debug.
func Enabled() bool { return enabled.Load() }
