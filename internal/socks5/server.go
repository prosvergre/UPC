// Package socks5 реализует минимальный SOCKS5-сервер (RFC 1928),
// поддерживающий только команду CONNECT без аутентификации — этого
// достаточно, чтобы браузер/torrent-клиент/любое SOCKS5-совместимое
// приложение могло подключиться к нашему локальному порту.
//
// Важно: Accept НЕ отправляет клиенту финальный ответ "успех/отказ" —
// это осознанно вынесено в отдельные методы Request.Grant()/Request.Deny(),
// чтобы вызывающий код (relay.Manager) мог сначала реально подключиться
// к Shadowsocks-серверу и только потом сообщить клиенту правду. Если
// отвечать "успех" сразу (как было раньше), а апстрим окажется мёртв —
// клиент (например, Proxifier) получает ложное "OK", а затем тишину,
// и это выглядит как нестабильный/битый прокси, а не как честный отказ.
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Request — принятое CONNECT-подключение вместе с сырым адресом
// назначения. Финальный ответ клиенту ещё не отправлен — вызывающий
// код обязан вызвать Grant() или Deny() ровно один раз.
type Request struct {
	Conn       net.Conn
	RawAddr    []byte // ATYP+ADDR+PORT, как есть — то, что нужно отправить на SS-сервер
	TargetHost string // для логов/отладки
	TargetPort int
}

// Accept выполняет SOCKS5-приветствие и разбирает CONNECT-запрос на
// уже принятом TCP-соединении. НЕ отправляет финальный ответ клиенту —
// см. Request.Grant()/Deny(). При ошибке разбора соединение уже закрыто.
func Accept(conn net.Conn) (*Request, error) {
	if err := handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}
	raw, host, port, err := readRequest(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Request{Conn: conn, RawAddr: raw, TargetHost: host, TargetPort: port}, nil
}

// Grant сообщает клиенту, что соединение установлено успешно.
// Вызывать ТОЛЬКО после того, как реальное соединение до апстрима
// (Shadowsocks-сервера) уже установлено.
func (r *Request) Grant() error {
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := r.Conn.Write(reply)
	return err
}

// Deny сообщает клиенту об отказе (0x01 = general SOCKS server
// failure — не различаем точную причину, этого достаточно, чтобы
// клиент корректно пометил прокси как нерабочий, а не завис в ожидании).
func (r *Request) Deny() error {
	reply := []byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := r.Conn.Write(reply)
	return err
}

// handshake: читает список методов аутентификации клиента, отвечает
// "без аутентификации" (0x00).
func handshake(conn net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("чтение приветствия SOCKS5: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("неподдерживаемая версия SOCKS: %d", head[0])
	}
	nMethods := int(head[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("чтение методов аутентификации: %w", err)
	}
	// отвечаем: версия 5, метод 0x00 (без аутентификации)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	return nil
}

// readRequest читает CONNECT-запрос и возвращает сырые байты адреса
// (для пересылки на SS-сервер) плюс разобранные host/port для логов.
// Финальный ответ клиенту здесь НЕ отправляется.
func readRequest(conn net.Conn) (raw []byte, host string, port int, err error) {
	head := make([]byte, 4)
	if _, err = io.ReadFull(conn, head); err != nil {
		return nil, "", 0, fmt.Errorf("чтение заголовка запроса: %w", err)
	}
	if head[0] != 0x05 {
		return nil, "", 0, fmt.Errorf("неподдерживаемая версия SOCKS: %d", head[0])
	}
	if head[1] != 0x01 { // 0x01 = CONNECT
		return nil, "", 0, fmt.Errorf("поддерживается только команда CONNECT (получено 0x%02x)", head[1])
	}
	atyp := head[3]

	var addrBytes []byte
	switch atyp {
	case atypIPv4:
		addrBytes = make([]byte, 4)
		if _, err = io.ReadFull(conn, addrBytes); err != nil {
			return nil, "", 0, err
		}
		host = net.IP(addrBytes).String()
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenByte); err != nil {
			return nil, "", 0, err
		}
		domain := make([]byte, lenByte[0])
		if _, err = io.ReadFull(conn, domain); err != nil {
			return nil, "", 0, err
		}
		addrBytes = append(lenByte, domain...)
		host = string(domain)
	case atypIPv6:
		addrBytes = make([]byte, 16)
		if _, err = io.ReadFull(conn, addrBytes); err != nil {
			return nil, "", 0, err
		}
		host = net.IP(addrBytes).String()
	default:
		return nil, "", 0, fmt.Errorf("неизвестный ATYP: 0x%02x", atyp)
	}

	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBytes); err != nil {
		return nil, "", 0, err
	}
	port = int(binary.BigEndian.Uint16(portBytes))

	raw = make([]byte, 0, 1+len(addrBytes)+2)
	raw = append(raw, atyp)
	raw = append(raw, addrBytes...)
	raw = append(raw, portBytes...)

	return raw, host, port, nil
}
