package kdf

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// HeaderKeySize is the header key output size (32 bytes).
	HeaderKeySize = 32
)

// ErrRootKeyTooShort is returned when the root key is shorter than required.
var ErrRootKeyTooShort = errors.New("root key too short")

// DeriveRootKeyHE implements standard HKDF-SHA256 for the header-encryption variant
// of the root KDF. Produces 96 bytes split into (newRK, newCK, newNHK).
//
// Per spec §4: same structure as KDF_RK but extended to also output a next
// header key. Uses HKDF with rk as salt, dh_out as IKM, and info as label.
//
// The info parameter should be an application-specific byte sequence distinct from the base
// DR KDF_RK info (e.g. "DoubleRatchetHE").
func DeriveRootKeyHE(rk, dhOutput, info []byte) (newRK, newCK []byte, newNHK [32]byte, err error) {
	if len(rk) < RootKeySize {
		return nil, nil, [32]byte{}, ErrRootKeyTooShort
	}

	okm := make([]byte, 96)
	reader := hkdf.New(sha256.New, dhOutput, rk, info)
	if _, err := io.ReadFull(reader, okm); err != nil {
		return nil, nil, [32]byte{}, err
	}

	newRK = append([]byte(nil), okm[:32]...)
	newCK = append([]byte(nil), okm[32:64]...)
	copy(newNHK[:], okm[64:96])
	return newRK, newCK, newNHK, nil
}
