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
