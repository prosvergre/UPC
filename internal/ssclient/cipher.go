// Package ssclient реализует клиентскую часть протокола Shadowsocks —
// как современный режим AEAD (SIP004), так и старый (legacy) stream-
// режим (CFB/CTR), который до сих пор используют многие публичные
// сервера. Это не полная переустановка shadowsocks-libev/rust, а
// компактная реализация под наши нужды: один TCP-поток на соединение.
//
// AEAD: aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-ietf-poly1305.
// Stream (legacy): aes-128-cfb, aes-192-cfb, aes-256-cfb,
// aes-128-ctr, aes-192-ctr, aes-256-ctr.
//
// Спецификации: https://shadowsocks.org/guide/aead.html
// https://shadowsocks.org/doc/stream.html
package ssclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type cipherKind int

const (
	kindAEAD cipherKind = iota
	kindStream
)

// methodSpec описывает параметры метода шифрования.
type methodSpec struct {
	kind   cipherKind
	keyLen int
	ivLen  int // используется только для stream-режима (для AEAD длина соли = keyLen)

	newAEAD func(key []byte) (cipher.AEAD, error) // только для kindAEAD

	// newStream создаёт cipher.Stream для одного направления (encrypt или
	// decrypt — для CFB это разные функции, для CTR одна и та же).
	newStreamEncrypter func(block cipher.Block, iv []byte) cipher.Stream
	newStreamDecrypter func(block cipher.Block, iv []byte) cipher.Stream
}

var methods = map[string]methodSpec{
	// --- AEAD (современные, приоритетные) ---
	"aes-128-gcm":            {kind: kindAEAD, keyLen: 16, newAEAD: newGCM},
	"aes-192-gcm":            {kind: kindAEAD, keyLen: 24, newAEAD: newGCM},
	"aes-256-gcm":            {kind: kindAEAD, keyLen: 32, newAEAD: newGCM},
	"chacha20-ietf-poly1305": {kind: kindAEAD, keyLen: 32, newAEAD: chacha20poly1305.New},
	"chacha20-poly1305":      {kind: kindAEAD, keyLen: 32, newAEAD: chacha20poly1305.New},

	// --- Stream (legacy, но всё ещё широко встречается на публичных серверах) ---
	"aes-128-cfb": {kind: kindStream, keyLen: 16, ivLen: 16,
		newStreamEncrypter: cipher.NewCFBEncrypter, newStreamDecrypter: cipher.NewCFBDecrypter},
	"aes-192-cfb": {kind: kindStream, keyLen: 24, ivLen: 16,
		newStreamEncrypter: cipher.NewCFBEncrypter, newStreamDecrypter: cipher.NewCFBDecrypter},
	"aes-256-cfb": {kind: kindStream, keyLen: 32, ivLen: 16,
		newStreamEncrypter: cipher.NewCFBEncrypter, newStreamDecrypter: cipher.NewCFBDecrypter},
	"aes-128-ctr": {kind: kindStream, keyLen: 16, ivLen: 16,
		newStreamEncrypter: newCTR, newStreamDecrypter: newCTR},
	"aes-192-ctr": {kind: kindStream, keyLen: 24, ivLen: 16,
		newStreamEncrypter: newCTR, newStreamDecrypter: newCTR},
	"aes-256-ctr": {kind: kindStream, keyLen: 32, ivLen: 16,
		newStreamEncrypter: newCTR, newStreamDecrypter: newCTR},
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newCTR(block cipher.Block, iv []byte) cipher.Stream {
	return cipher.NewCTR(block, iv)
}

// Supported сообщает, поддерживаем ли мы метод шифрования.
func Supported(method string) bool {
	_, ok := methods[method]
	return ok
}

// SupportedMethods возвращает список поддерживаемых методов (для UI/сообщений).
func SupportedMethods() []string {
	out := make([]string, 0, len(methods))
	for m := range methods {
		if m == "chacha20-poly1305" {
			continue // алиас chacha20-ietf-poly1305, не дублируем в списке
		}
		out = append(out, m)
	}
	return out
}

// isStream сообщает, является ли метод legacy stream-шифром (а не AEAD).
func isStream(method string) bool {
	spec, ok := methods[method]
	return ok && spec.kind == kindStream
}

// masterKey выводит мастер-ключ из пароля по алгоритму EVP_BytesToKey
// (MD5-based), как в оригинальном Shadowsocks.
func masterKey(password string, keyLen int) []byte {
	var out []byte
	var prev []byte
	for len(out) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

// subkey выводит сессионный ключ через HKDF-SHA1(masterKey, salt, "ss-subkey") — только для AEAD.
func subkey(master, salt []byte, keyLen int) ([]byte, error) {
	r := hkdf.New(sha1.New, master, salt, []byte("ss-subkey"))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// aeadForSession создаёt AEAD-шифр для конкретной сессии (после того как
// известна соль — своя для каждого направления соединения).
func aeadForSession(method, password string, salt []byte) (cipher.AEAD, error) {
	spec, ok := methods[method]
	if !ok || spec.kind != kindAEAD {
		return nil, fmt.Errorf("метод %q не является AEAD-шифром", method)
	}
	mk := masterKey(password, spec.keyLen)
	sk, err := subkey(mk, salt, spec.keyLen)
	if err != nil {
		return nil, err
	}
	return spec.newAEAD(sk)
}

// streamCipherForSession создаёт cipher.Stream для legacy-режима.
// В отличие от AEAD, здесь используется мастер-ключ напрямую (без HKDF
// subkey) и IV вместо соли — это исторический формат оригинального
// Shadowsocks (shadowsocks-libev "stream" ciphers).
func streamCipherForSession(method, password string, iv []byte, encrypt bool) (cipher.Stream, error) {
	spec, ok := methods[method]
	if !ok || spec.kind != kindStream {
		return nil, fmt.Errorf("метод %q не является stream-шифром", method)
	}
	mk := masterKey(password, spec.keyLen)
	block, err := aes.NewCipher(mk)
	if err != nil {
		return nil, err
	}
	if encrypt {
		return spec.newStreamEncrypter(block, iv), nil
	}
	return spec.newStreamDecrypter(block, iv), nil
}

// SaltLen возвращает длину соли (AEAD) для метода.
func SaltLen(method string) int {
	if spec, ok := methods[method]; ok && spec.kind == kindAEAD {
		return spec.keyLen
	}
	return 0
}

// IVLen возвращает длину IV (stream-режим) для метода.
func IVLen(method string) int {
	if spec, ok := methods[method]; ok && spec.kind == kindStream {
		return spec.ivLen
	}
	return 0
}

// randomSalt генерирует случайные байты нужной длины (используется и для
// AEAD-соли, и для stream-IV — в обоих случаях это просто случайный вектор).
func randomSalt(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
