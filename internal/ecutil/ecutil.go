// Package ecutil provides shared X25519 primitives used by the x3dh and pqxdh packages.
package ecutil

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// ErrZeroSharedSecret is returned when an X25519 DH computation produces all-zero
// output, indicating the peer provided a low-order point.
var ErrZeroSharedSecret = errors.New("ecutil: X25519 produced all-zero shared secret (low-order point)")

// ErrInvalidPublicKey is returned when a received public key fails
// canonical or torsion-free validation.
var ErrInvalidPublicKey = errors.New("ecutil: invalid public key")

// GenerateX25519KeyPair generates a clamped X25519 key pair.
func GenerateX25519KeyPair() (priv, pub [32]byte, err error) {
	privBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privBytes); err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	// Clamp per RFC 7748.
	privBytes[0] &= 248
	privBytes[31] &= 127
	privBytes[31] |= 64

	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	copy(priv[:], privBytes)
	copy(pub[:], pubBytes)
	return priv, pub, nil
}

// DHX25519 computes DH(priv, pub) and rejects low-order points.
// The all-zero check is constant-time to avoid leaking partial secret information.
func DHX25519(priv, pub [32]byte) ([]byte, error) {
	ss, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return nil, err
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(ss, zero[:]) == 1 {
		return nil, ErrZeroSharedSecret
	}
	return ss, nil
}

// eightInvModL is 8⁻¹ mod l (precomputed). Used for cofactor-clearing
// torsion check: P is in the prime-order subgroup iff 8⁻¹·(8·P) == P.
var eightInvModL = [32]byte{
	0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
	0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
}

// curve25519P is 2^255 - 19 in little-endian.
var curve25519P = [32]byte{
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

// ValidatePublicKey checks that a Montgomery u-coordinate is canonical (u < p)
// and torsion-free, matching libsignal's is_canonical() check.
func ValidatePublicKey(pub [32]byte) error {
	if !scalarIsInRange(pub) {
		return ErrInvalidPublicKey
	}

	yBytes := MontgomeryUToEdwardsYBytes(pub)
	if yBytes == nil {
		return ErrInvalidPublicKey
	}
	yBytes[31] &= 0x7F
	edPoint, err := new(edwards25519.Point).SetBytes(yBytes)
	if err != nil {
		return ErrInvalidPublicKey
	}

	eightBytes := [32]byte{8}
	eightScalar, err := edwards25519.NewScalar().SetCanonicalBytes(eightBytes[:])
	if err != nil {
		return ErrInvalidPublicKey
	}
	eightInvScalar, err := edwards25519.NewScalar().SetCanonicalBytes(eightInvModL[:])
	if err != nil {
		return ErrInvalidPublicKey
	}

	cofactorP := new(edwards25519.Point).ScalarMult(eightScalar, edPoint)
	cleared := new(edwards25519.Point).ScalarMult(eightInvScalar, cofactorP)

	if cleared.Equal(edPoint) != 1 {
		return ErrInvalidPublicKey
	}
	return nil
}

// scalarIsInRange checks u < p (2^255 - 19).
// Compares all 32 bytes from the most-significant byte down to correctly
// reject all 19 non-canonical values in [p, 2^255).
func scalarIsInRange(k [32]byte) bool {
	// High bit must be clear (bit 255 = 0).
	if k[31]&0x80 != 0 {
		return false
	}
	// Reject if k >= p: compare little-endian from high byte down.
	for i := 31; i >= 0; i-- {
		if k[i] < curve25519P[i] {
			return true
		}
		if k[i] > curve25519P[i] {
			return false
		}
	}
	// k == p exactly — not canonical.
	return false
}
