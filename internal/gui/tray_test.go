package gui

import "testing"

func TestTrayFailureDetector(t *testing.T) {
	d := &trayFailureDetector{}
	if d.Failed() {
		t.Fatal("изначально трей не должен считаться неудавшимся")
	}

	d.Write([]byte("08:16:07 правило файрвола для портов 1080-1179 готово\n"))
	if d.Failed() {
		t.Fatal("обычное лог-сообщение не должно триггерить детектор")
	}

	d.Write([]byte("08:16:07 systray error: failed to connect to DBus: exec: \"dbus-launch\" executable file not found in $PATH\n"))
	if !d.Failed() {
		t.Fatal("сообщение с 'systray error' должно триггерить детектор")
	}

	// однажды сработавший детектор не должен сбрасываться последующими
	// обычными сообщениями
	d.Write([]byte("08:16:08 [relay:1.2.3.4:443] запущен на 0.0.0.0:1080\n"))
	if !d.Failed() {
		t.Fatal("детектор не должен сбрасываться после срабатывания")
	}
}
