// Package kdf provides key derivation functions for the Double Ratchet.
package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const (
	// RootKeySize is the root key output size (32 bytes for SHA-256).
	RootKeySize = 32
)

// ErrNotDerived is returned if Expand is called before Derive.
var ErrNotDerived = errors.New("root KDF not derived")

// RootKDF implements HKDF-SHA256 for root key derivation.
type RootKDF struct {
	salt []byte
	info []byte
	prk  []byte
}

// NewRootKDF creates a new RootKDF with optional salt and info.
// If salt is nil, HKDF uses zeros. info can be nil.
func NewRootKDF(salt, info []byte) *RootKDF {
	if salt == nil {
		salt = make([]byte, sha256.New().Size())
	}
	return &RootKDF{
		salt: salt,
		info: info,
	}
}

// Derive derives a root key from input key material using HKDF-Extract.
// Returns a RootKDF ready for Expand calls.
func (r *RootKDF) Derive(ikm []byte) error {
	// HKDF-Extract: HMAC-SHA256(salt, ikm)
	h := hmac.New(sha256.New, r.salt)
	h.Write(ikm)
	r.prk = h.Sum(nil)
	return nil
}

// Expand expands the PRK to produce output key material.
// info is additional context (appended to r.info).
// Each call produces 32 bytes. Returns the derived key bytes.
func (r *RootKDF) Expand(info []byte, length int) ([]byte, error) {
	if r.prk == nil {
		return nil, ErrNotDerived
	}
	combinedInfo := append(r.info, info...)

	// HKDF-Expand: derive key material from PRK using HMAC-SHA256
	// T(1) = HMAC(prk, info || 0x01)
	// T(2) = HMAC(prk, T(1) || info || 0x02)
	// etc.
	h := hmac.New(sha256.New, r.prk)
	h.Write(combinedInfo)
	h.Write([]byte{0x01})
	out := h.Sum(nil)

	if length > len(out) {
		return nil, errors.New("requested length exceeds single block size")
	}
	return out[:length], nil
}

// RootKDFDerive is a convenience function that derives a root key in one call.
func RootKDFDerive(ikm, salt, info []byte) ([]byte, error) {
	r := NewRootKDF(salt, info)
	if err := r.Derive(ikm); err != nil {
		return nil, err
	}
	return r.Expand(info, RootKeySize)
}