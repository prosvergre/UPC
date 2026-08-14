// Package config пишет список рабочих серверов в формате конфига
// shadowsocks-rust (sslocal), который поддерживает массив "servers" —
// клиент сам выбирает рабочий/самый быстрый сервер.
//
// Формат описан в документации shadowsocks-rust (SIP008-подобный,
// но конкретно поле "servers" в конфиге sslocal):
// https://github.com/shadowsocks/shadowsocks-rust
package config

import (
	"encoding/json"
	"os"

	"proxycheck/internal/ssuri"
)

// ServerEntry — одна запись сервера в конфиге shadowsocks-rust.
type ServerEntry struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Method   string `json:"method"`
	Remarks  string `json:"remarks,omitempty"`
	Plugin   string `json:"plugin,omitempty"`
	// Timeout в секундах на сервер — необязательно, но полезно.
	Timeout int `json:"timeout,omitempty"`
}

// File — корневая структура конфига shadowsocks-rust (sslocal, режим
// балансировки между несколькими серверами).
type File struct {
	Servers      []ServerEntry `json:"servers"`
	LocalAddress string        `json:"local_address"`
	LocalPort    int           `json:"local_port"`
	Mode         string        `json:"mode"`
}

// FromServers конвертирует список ssuri.Server в конфиг shadowsocks-rust.
// localPort — порт локального SOCKS5/HTTP входа (по умолчанию 1080).
func FromServers(servers []ssuri.Server, localPort int) File {
	if localPort == 0 {
		localPort = 1080
	}
	entries := make([]ServerEntry, 0, len(servers))
	for _, s := range servers {
		entries = append(entries, ServerEntry{
			Address:  s.Host,
			Port:     s.Port,
			Password: s.Password,
			Method:   s.Method,
			Remarks:  s.Remarks,
			Plugin:   s.Plugin,
			Timeout:  5,
		})
	}
	return File{
		Servers:      entries,
		LocalAddress: "127.0.0.1",
		LocalPort:    localPort,
		Mode:         "tcp_and_udp",
	}
}

// WriteJSON пишет конфиг в файл в человекочитаемом (с отступами) виде.
func WriteJSON(path string, f File) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
