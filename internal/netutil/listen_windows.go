//go:build windows

// Package netutil содержит платформо-зависимые обёртки над net.Listen.
//
// На Windows, в отличие от Linux, ПО УМОЛЧАНИЮ разрешено двум разным
// процессам слушать один и тот же порт в комбинации 0.0.0.0 + 127.0.0.1
// (или даже 0.0.0.0 + 0.0.0.0 в некоторых случаях) — это исторически
// сложившееся поведение сокетов Winsock, известное как "port hijacking".
// Именно это вызвало баг: старый (зомби) процесс проекта, оставшийся в
// фоне из-за неудачной инициализации трея, продолжал слушать 127.0.0.1
// на тех же портах, а новый процесс спокойно "занимал" 0.0.0.0 на тех
// же портах без единой ошибки — и какой из двух процессов реально
// получал соединение, было непредсказуемо.
//
// SO_EXCLUSIVEADDRUSE — официальная рекомендация Microsoft для защиты
// от этого: заставляет Windows вести себя как Linux и по-настоящему
// возвращать ошибку "порт занят", если порт уже используется другим
// сокетом — именно это нужно нашей логике авто-подбора порта, чтобы
// корректно обнаруживать конфликты.
package netutil

import (
	"context"
	"net"
	"syscall"
)

// SO_EXCLUSIVEADDRUSE в заголовках Windows определён как ~SO_REUSEADDR,
// то есть 0xFFFFFFFB — значение задокументировано в Microsoft Docs
// (winsock2.h) и стабильно между версиями Windows.
const soExclusiveAddrUse = 0xfffffffb

// ListenExclusiveTCP слушает TCP-адрес с установленным
// SO_EXCLUSIVEADDRUSE — гарантирует, что попытка забиндиться на уже
// занятый (другим процессом) порт вернёт настоящую ошибку, а не тихо
// пройдёт мимо, как бывает в Windows по умолчанию.
func ListenExclusiveTCP(address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soExclusiveAddrUse, 1)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp", address)
}
