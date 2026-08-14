package ssclient

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const maxChunkSize = 0x3FFF // 16383 байт — максимальный размер полезной нагрузки в чанке

// aeadConn оборачивает net.Conn, прозрачно шифруя всё, что пишем,
// и расшифровывая всё, что читаем, по формату Shadowsocks TCP AEAD:
//
//	[salt] [len_chunk][payload_chunk] [len_chunk][payload_chunk] ...
//
// где len_chunk = AEAD(2 байта длины) и payload_chunk = AEAD(payload),
// каждый со своим независимо инкрементируемым nonce.
type aeadConn struct {
	net.Conn
	method   string
	password string

	writeAEAD  cipher.AEAD
	writeNonce []byte
	wroteSalt  bool

	readAEAD  cipher.AEAD
	readNonce []byte
	readSalt  bool

	readBuf bytes.Buffer // остаток расшифрованных, но ещё не отданных вызывающему данных
}

// NewConn оборачивает уже установленное TCP-соединение до Shadowsocks-
// сервера в шифрующий/дешифрующий слой. Автоматически выбирает AEAD
// или legacy stream-режим по методу.
func NewConn(raw net.Conn, method, password string) net.Conn {
	if isStream(method) {
		return &streamConn{Conn: raw, method: method, password: password}
	}
	return &aeadConn{Conn: raw, method: method, password: password}
}

func (c *aeadConn) ensureWriteCipher() error {
	if c.writeAEAD != nil {
		return nil
	}
	saltLen := SaltLen(c.method)
	salt, err := randomSalt(saltLen)
	if err != nil {
		return err
	}
	aead, err := aeadForSession(c.method, c.password, salt)
	if err != nil {
		return err
	}
	if _, err := c.Conn.Write(salt); err != nil {
		return err
	}
	c.writeAEAD = aead
	c.writeNonce = make([]byte, aead.NonceSize())
	c.wroteSalt = true
	return nil
}

func (c *aeadConn) ensureReadCipher() error {
	if c.readAEAD != nil {
		return nil
	}
	saltLen := SaltLen(c.method)
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return fmt.Errorf("чтение соли от сервера: %w", err)
	}
	aead, err := aeadForSession(c.method, c.password, salt)
	if err != nil {
		return err
	}
	c.readAEAD = aead
	c.readNonce = make([]byte, aead.NonceSize())
	c.readSalt = true
	return nil
}

func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// Write шифрует и отправляет payload одним или несколькими чанками
// (если payload больше maxChunkSize).
func (c *aeadConn) Write(b []byte) (int, error) {
	if err := c.ensureWriteCipher(); err != nil {
		return 0, err
	}
	total := 0
	for len(b) > 0 {
		n := len(b)
		if n > maxChunkSize {
			n = maxChunkSize
		}
		chunk := b[:n]
		b = b[n:]

		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		encLen := c.writeAEAD.Seal(nil, c.writeNonce, lenBuf[:], nil)
		incNonce(c.writeNonce)
		if _, err := c.Conn.Write(encLen); err != nil {
			return total, err
		}

		encPayload := c.writeAEAD.Seal(nil, c.writeNonce, chunk, nil)
		incNonce(c.writeNonce)
		if _, err := c.Conn.Write(encPayload); err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Read отдаёт расшифрованные данные вызывающему, читая и расшифровывая
// новые чанки по мере необходимости.
func (c *aeadConn) Read(b []byte) (int, error) {
	if err := c.ensureReadCipher(); err != nil {
		return 0, err
	}
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	tagLen := c.readAEAD.Overhead()

	// длина чанка
	encLen := make([]byte, 2+tagLen)
	if _, err := io.ReadFull(c.Conn, encLen); err != nil {
		return 0, err
	}
	lenBuf, err := c.readAEAD.Open(nil, c.readNonce, encLen, nil)
	if err != nil {
		return 0, fmt.Errorf("расшифровка длины чанка: %w", err)
	}
	incNonce(c.readNonce)
	chunkLen := binary.BigEndian.Uint16(lenBuf)

	encPayload := make([]byte, int(chunkLen)+tagLen)
	if _, err := io.ReadFull(c.Conn, encPayload); err != nil {
		return 0, err
	}
	payload, err := c.readAEAD.Open(nil, c.readNonce, encPayload, nil)
	if err != nil {
		return 0, fmt.Errorf("расшифровка payload чанка: %w", err)
	}
	incNonce(c.readNonce)

	c.readBuf.Write(payload)
	return c.readBuf.Read(b)
}
