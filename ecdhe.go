package main

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/curve25519"
)

func main() {
	ephemeralA := make([]byte, curve25519.ScalarSize)
	rand.Read(ephemeralA)
	publicKeyA, _ := curve25519.X25519(ephemeralA, curve25519.Basepoint)

	ephemeralB := make([]byte, curve25519.ScalarSize)
	rand.Read(ephemeralB)
	publicKeyB, _ := curve25519.X25519(ephemeralB, curve25519.Basepoint)

	sharedSecret1, _ := curve25519.X25519(ephemeralA, publicKeyB)
	sharedSecret2, _ := curve25519.X25519(ephemeralB, publicKeyA)

	fmt.Printf("shared secret: %x\n", sharedSecret1)
	fmt.Printf("shared secret: %x\n", sharedSecret2)
}
