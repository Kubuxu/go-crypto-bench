package main

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func BenchmarkChacha20Poly1305(b *testing.B) {
	key1 := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key1)

	aead, err := chacha20poly1305.New(key1)
	if err != nil {
		b.Fatal(err)
	}

	nonce1 := make([]byte, aead.NonceSize())
	rand.Read(nonce1)

	data := make([]byte, 1<<19)
	rand.Read(data)

	b.SetBytes(1 << 19)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(data[:0], nonce1, data, []byte{})
	}

}

func BenchmarkAES128GCM(b *testing.B) {
	benchmarkAESX(b, 128/8)
}

func BenchmarkAES256GCM(b *testing.B) {
	benchmarkAESX(b, 256/8)
}

func benchmarkAESX(b *testing.B, keysize int) {
	key1 := make([]byte, keysize)
	rand.Read(key1)

	aes, err := aes.NewCipher(key1)
	if err != nil {
		b.Fatal(err)
	}

	aead, err := cipher.NewGCM(aes)
	if err != nil {
		b.Fatal(err)
	}

	nonce1 := make([]byte, aead.NonceSize())
	rand.Read(nonce1)

	data := make([]byte, 1<<19)
	rand.Read(data)

	b.SetBytes(1 << 19)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(data[:0], nonce1, data, []byte{})
	}

}
