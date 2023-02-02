package main

import (
	"github.com/decred/dcrd/crypto/blake256"
	"golang.org/x/crypto/ed25519"
)

func verify(pk ed25519.PublicKey, data []byte, sig [64]byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	h := blake256.New()
	h.Write(data)
	return ed25519.Verify(pk, h.Sum(nil), sig[:])
}

func VerifySignature(sig [64]byte, pub [32]byte, data []byte) bool {
	return verify(ed25519.PublicKey(pub[:]), data, sig)
}
