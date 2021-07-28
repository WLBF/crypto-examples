package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {

	msg := "winner takes it all!"

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	cha, _ := New(key)
	chiperText, _ := cha.Encrypt(msg)
	fmt.Println(chiperText)
	plainText, _ := cha.Decrypt(chiperText)
	fmt.Println(plainText)
}

type ChaCha20Poly1305 struct {
	aead cipher.AEAD
}

func New(key []byte) (*ChaCha20Poly1305, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &ChaCha20Poly1305{aead: aead}, nil
}

func (c *ChaCha20Poly1305) Encrypt(text string) (string, error) {
	plain := []byte(text)

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, c.aead.NonceSize(), c.aead.NonceSize()+len(plain)+c.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Encrypt the message and append the ciphertext to the nonce.
	encrypted := c.aead.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (c *ChaCha20Poly1305) Decrypt(encrypted string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	if len(cipherText) < c.aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := cipherText[:c.aead.NonceSize()], cipherText[c.aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
