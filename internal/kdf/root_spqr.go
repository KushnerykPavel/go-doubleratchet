// Package kdf provides SPQR-specific key derivation functions.
package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

var (
	// sckaInitConstant is used in KDF_SCKA_INIT.
	sckaInitConstant = []byte("SCKAInit")
	// sckaRKConstant is used in KDF_SCKA_RK.
	sckaRKConstant = []byte("SCKARatchet")
	// sckaCKConstant is used in KDF_SCKA_CK for chain key derivation.
	sckaCKConstant = []byte{0x01}
	// sckaMKConstant is used in KDF_SCKA_CK for message key derivation.
	sckaMKConstant = []byte{0x02}
)

// ErrInvalidInput is returned for invalid inputs.
var ErrInvalidInput = errors.New("invalid input")

// KDF_SCKA_INIT derives initial RK, CKs, CKr from SK.
// Returns (rk, cks, ckr) each 32 bytes.
func KDF_SCKA_INIT(sk []byte) (rk, cks, ckr []byte, err error) {
	if len(sk) < 32 {
		return nil, nil, nil, ErrInvalidInput
	}

	// Use HKDF-SHA256 to derive 96 bytes (32*3) of key material.
	// salt = sk[:32], IKM = sk, info = "SCKAInit".
	h := hmac.New(sha256.New, sk[:32])
	h.Write(sckaInitConstant)
	rk = h.Sum(nil)[:32]

	h = hmac.New(sha256.New, rk)
	h.Write(sckaCKConstant)
	cks = h.Sum(nil)[:32]

	h = hmac.New(sha256.New, rk)
	h.Write(sckaMKConstant)
	ckr = h.Sum(nil)[:32]

	return rk, cks, ckr, nil
}

// KDF_SCKA_RK derives new RK, CKs, CKr from current RK and SCKA output.
func KDF_SCKA_RK(rk, sckaOutput []byte) (newRK, cks, ckr []byte, err error) {
	if len(rk) < 32 || len(sckaOutput) < 32 {
		return nil, nil, nil, ErrInvalidInput
	}

	// Combine RK and SCKA output for derivation.
	h := hmac.New(sha256.New, rk)
	h.Write(sckaOutput)
	h.Write(sckaRKConstant)
	newRK = h.Sum(nil)[:32]

	h = hmac.New(sha256.New, newRK)
	h.Write(sckaCKConstant)
	cks = h.Sum(nil)[:32]

	h = hmac.New(sha256.New, newRK)
	h.Write(sckaMKConstant)
	ckr = h.Sum(nil)[:32]

	return newRK, cks, ckr, nil
}

// KDF_SCKA_CK derives next chain key and message key from current chain key.
func KDF_SCKA_CK(ck []byte, ctr uint32) (nextCK, mk []byte, err error) {
	if len(ck) < 32 {
		return nil, nil, ErrInvalidInput
	}

	// Derive next chain key: HMAC-SHA256(ck, 0x01 || ctr)
	ckInput := make([]byte, len(sckaCKConstant)+4)
	copy(ckInput, sckaCKConstant)
	ckInput[1] = byte(ctr >> 24)
	ckInput[2] = byte(ctr >> 16)
	ckInput[3] = byte(ctr >> 8)
	ckInput[4] = byte(ctr)

	h := hmac.New(sha256.New, ck)
	h.Write(ckInput)
	nextCK = h.Sum(nil)[:32]

	// Derive message key: HMAC-SHA256(nextCK, 0x02 || ctr)
	mkInput := make([]byte, len(sckaMKConstant)+4)
	copy(mkInput, sckaMKConstant)
	mkInput[1] = byte(ctr >> 24)
	mkInput[2] = byte(ctr >> 16)
	mkInput[3] = byte(ctr >> 8)
	mkInput[4] = byte(ctr)

	h = hmac.New(sha256.New, nextCK)
	h.Write(mkInput)
	mk = h.Sum(nil)[:32]

	return nextCK, mk, nil
}
