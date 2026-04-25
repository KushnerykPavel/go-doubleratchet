// Package x3dh implements the X3DH (Extended Triple Diffie-Hellman) key agreement
// protocol per the Signal specification at https://signal.org/docs/specifications/x3dh/.
//
// X3DH establishes a shared secret between two parties (Alice and Bob) without
// requiring Bob to be online. The output feeds directly into the Double Ratchet
// via doubleratchet.InitAlice / doubleratchet.InitBob.
package x3dh

import (
	"crypto/rand"
	"errors"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// ErrZeroSharedSecret is returned when an X25519 DH computation produces all-zero
// output, indicating the peer provided a low-order point.
var ErrZeroSharedSecret = errors.New("x3dh: X25519 produced all-zero shared secret (low-order point)")

// ErrInvalidSPKSignature is returned when the signed prekey signature in a
// PrekeyBundle fails XEdDSA verification.
var ErrInvalidSPKSignature = errors.New("x3dh: invalid signed prekey signature")

// IdentityKey is a long-term X25519 key pair used for authentication.
// Generate with GenerateIdentityKey.
type IdentityKey struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// SignedPreKey is a semi-static X25519 key pair. The Signature is an XEdDSA
// signature over PublicKey made with the owner's IdentityKey, allowing recipients
// to verify authenticity without an online exchange.
// Generate with GenerateSPK.
type SignedPreKey struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
	KeyID      uint32
	Signature  [64]byte // XEdDSA(IdentityKey.PrivateKey, PublicKey[:])
}

// OneTimePreKey is a single-use X25519 key pair that provides an additional
// DH contribution (DH4) for enhanced forward secrecy. Once used, both parties
// must discard it.
// Generate with GenerateOPK.
type OneTimePreKey struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
	KeyID      uint32
}

// GenerateIdentityKey generates a new long-term X25519 identity key pair.
func GenerateIdentityKey() (IdentityKey, error) {
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		return IdentityKey{}, err
	}
	return IdentityKey{PrivateKey: priv, PublicKey: pub}, nil
}

// GenerateSPK generates a new signed prekey and signs it with ik using XEdDSA.
func GenerateSPK(ik IdentityKey, keyID uint32) (SignedPreKey, error) {
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		return SignedPreKey{}, err
	}
	sig, err := xeddsaSign(ik.PrivateKey, pub[:])
	if err != nil {
		return SignedPreKey{}, err
	}
	return SignedPreKey{PrivateKey: priv, PublicKey: pub, KeyID: keyID, Signature: sig}, nil
}

// GenerateOPK generates a new one-time prekey with the given ID.
func GenerateOPK(keyID uint32) (OneTimePreKey, error) {
	priv, pub, err := generateX25519KeyPair()
	if err != nil {
		return OneTimePreKey{}, err
	}
	return OneTimePreKey{PrivateKey: priv, PublicKey: pub, KeyID: keyID}, nil
}

// ErrInvalidPublicKey is returned when a received public key fails
// canonical or torsion-free validation.
var ErrInvalidPublicKey = errors.New("x3dh: invalid public key")

// eightInvModL is 8⁻¹ mod l (precomputed). Used for cofactor-clearing
// torsion check: P is in the prime-order subgroup iff 8⁻¹·(8·P) == P.
var eightInvModL = [32]byte{
	0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
	0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
}

// validatePublicKey checks that a Montgomery u-coordinate is canonical (u < p)
// and torsion-free, matching libsignal's is_canonical() check.
func validatePublicKey(pub [32]byte) error {
	// 1. Canonical check: u < p  (p = 2^255 - 19).
	if !scalarIsInRange(pub) {
		return ErrInvalidPublicKey
	}

	// 2. Torsion-free check via cofactor clearing.
	// Convert Montgomery → Edwards, then check that 8⁻¹·(8·P) == P.
	// If P has a torsion component T (order dividing 8), then 8·P kills T,
	// and 8⁻¹·(8·P) recovers only the prime-order component, which differs from P.
	yBytes := montgomeryUToEdwardsYBytes(pub)
	if yBytes == nil {
		return ErrInvalidPublicKey
	}
	yBytes[31] &= 0x7F // sign=0 for torsion check (doesn't affect subgroup membership)
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

	// cleared = 8⁻¹ · (8 · P)  — strips any torsion component.
	cofactorP := new(edwards25519.Point).ScalarMult(eightScalar, edPoint)
	cleared := new(edwards25519.Point).ScalarMult(eightInvScalar, cofactorP)

	if cleared.Equal(edPoint) != 1 {
		return ErrInvalidPublicKey
	}
	return nil
}

// scalarIsInRange checks u < p (2^255 - 19) after clearing the high bit.
// Mirrors libsignal's scalar_is_in_range in curve.rs.
func scalarIsInRange(k [32]byte) bool {
	// High bit must be clear.
	if k[31]&0x80 != 0 {
		return false
	}
	// Reject if k[0] >= 237 (0xED = 256-19) AND k[1..30] all 0xFF AND k[31] == 0x7F.
	if k[0] >= 0xED {
		allFF := true
		for i := 1; i < 31; i++ {
			if k[i] != 0xFF {
				allFF = false
				break
			}
		}
		if allFF && k[31] == 0x7F {
			return false
		}
	}
	return true
}

// generateX25519KeyPair generates a clamped X25519 key pair.
func generateX25519KeyPair() (priv, pub [32]byte, err error) {
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
