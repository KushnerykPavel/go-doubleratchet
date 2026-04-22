// Package kdf provides key derivation functions for the Double Ratchet.
package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const (
	// HeaderKeySize is the header key output size (32 bytes).
	HeaderKeySize = 32
)

var (
	// rootHeConstant is the HKDF info constant for KDF_RK_HE (distinct from base KDF_RK).
	rootHeConstant = []byte("DoubleRatchetRootKeyHE")
	// chainHeConstant is the HKDF info constant for chain key in KDF_RK_HE.
	chainHeConstant = []byte("DoubleRatchetChainKeyHE")
	// headerKeyConstant is the HKDF info constant for next header key in KDF_RK_HE.
	headerKeyConstant = []byte("DoubleRatchetHeaderKeyHE")
)

// KDF_RK_HE implements HKDF-SHA256 for root key derivation with header keys.
// Extends KDF_RK to also derive next header key.
// rk is the current root key (salt).
// dhOutput is the Diffie-Hellman output (IKM).
// Returns (newRK, newCK, newNHK).
func KDF_RK_HE(rk, dhOutput []byte) ([]byte, []byte, [32]byte, error) {
	if len(rk) < RootKeySize {
		return nil, nil, [32]byte{}, errors.New("root key too short")
	}

	// HKDF-Extract: prk = HMAC-SHA256(rk, dhOutput)
	h := hmac.New(sha256.New, rk)
	h.Write(dhOutput)
	prk := h.Sum(nil)

	// Derive root key: T(1) = HMAC(prk, info || 0x01)
	h = hmac.New(sha256.New, prk)
	h.Write(rootHeConstant)
	h.Write([]byte{0x01})
	newRK := h.Sum(nil)

	// Derive chain key: T(2) = HMAC(prk, T(1) || info || 0x02)
	h = hmac.New(sha256.New, prk)
	h.Write(newRK)
	h.Write(chainHeConstant)
	h.Write([]byte{0x02})
	newCK := h.Sum(nil)

	// Derive header key: T(3) = HMAC(prk, T(2) || info || 0x03)
	h = hmac.New(sha256.New, prk)
	h.Write(newCK)
	h.Write(headerKeyConstant)
	h.Write([]byte{0x03})
	var newNHK [32]byte
	copy(newNHK[:], h.Sum(nil))

	return newRK, newCK, newNHK, nil
}