package ssclient

import (
	"crypto/cipher"
	"fmt"
	"io"
	"net"
)

// streamConn оборачивает net.Conn для legacy (не-AEAD) Shadowsocks:
// сначала передаётся случайный IV в открытом виде, затем весь поток
// в обе стороны непрерывно XOR'ится через cipher.Stream (без чанков,
// без тегов аутентификации — так работал оригинальный протокол).
type streamConn struct {
	net.Conn
	method   string
	password string

	writeStream cipher.Stream
	wroteIV     bool

	readStream cipher.Stream
	readIV     bool
}

func (c *streamConn) ensureWriteStream() error {
	if c.writeStream != nil {
		return nil
	}
	ivLen := IVLen(c.method)
	iv, err := randomSalt(ivLen)
	if err != nil {
		return err
	}
	st, err := streamCipherForSession(c.method, c.password, iv, true)
	if err != nil {
		return err
	}
	if _, err := c.Conn.Write(iv); err != nil {
		return err
	}
	c.writeStream = st
	c.wroteIV = true
	return nil
}

func (c *streamConn) ensureReadStream() error {
	if c.readStream != nil {
		return nil
	}
	ivLen := IVLen(c.method)
	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return fmt.Errorf("чтение IV от сервера: %w", err)
	}
	st, err := streamCipherForSession(c.method, c.password, iv, false)
	if err != nil {
		return err
	}
	c.readStream = st
	c.readIV = true
	return nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	if err := c.ensureWriteStream(); err != nil {
		return 0, err
	}
	enc := make([]byte, len(b))
	c.writeStream.XORKeyStream(enc, b)
	return c.Conn.Write(enc)
}

func (c *streamConn) Read(b []byte) (int, error) {
	if err := c.ensureReadStream(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.readStream.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}
