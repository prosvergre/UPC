//go:build !windows

// Package netutil содержит платформо-зависимые обёртки над net.Listen.
// На не-Windows платформах это просто обычный net.Listen — ОС и так
// по умолчанию не позволяет двум процессам слушать один порт.
package netutil

import "net"

// ListenExclusiveTCP слушает TCP-адрес. На не-Windows — обычное
// поведение net.Listen (там по умолчанию порт уже эксклюзивен).
func ListenExclusiveTCP(address string) (net.Listener, error) {
	return net.Listen("tcp", address)
}
