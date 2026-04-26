// Package crypto provides X25519 Diffie-Hellman operations for the Double Ratchet.
package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	// KeySize is the X25519 public key (32 bytes) and private key (32 bytes) size.
	KeySize = 32
	// SharedSecretSize is the X25519 shared secret size (32 bytes).
	SharedSecretSize = 32
)

// ErrLowOrderPoint is returned when the X25519 shared secret is all zeros,
// indicating the peer sent a low-order point.
var ErrLowOrderPoint = errors.New("x25519: shared secret is all zeros; peer sent a low-order point")

// KeyPair represents an X25519 key pair.
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// GenerateKeyPair generates a new X25519 key pair.
// Returns private key (32 bytes) and public key (32 bytes).
func GenerateKeyPair() (privateKey, publicKey [KeySize]byte, err error) {
	privBytes := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, privBytes); err != nil {
		return [KeySize]byte{}, [KeySize]byte{}, err
	}

	// Clamp private key per X25519 spec.
	privBytes[0] &= 248
	privBytes[31] &= 127
	privBytes[31] |= 64

	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return [KeySize]byte{}, [KeySize]byte{}, err
	}

	copy(privateKey[:], privBytes)
	copy(publicKey[:], pubBytes)
	return privateKey, publicKey, nil
}

// NewKeyPair generates a new X25519 KeyPair.
func NewKeyPair() (KeyPair, error) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PrivateKey: priv, PublicKey: pub}, nil
}

// SharedSecret computes the X25519 shared secret given a private key and a public key.
// Returns a 32-byte shared secret. Returns an error if the peer's public key is a
// low-order point (all-zeros output indicates a small-subgroup attack per RFC 7748 §6).
func SharedSecret(privateKey, publicKey [KeySize]byte) ([]byte, error) {
	ss, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, err
	}
	// Reject low-order points: clamped scalars are multiples of 8, and
	// 8*(any 8-torsion point) = identity whose x-coordinate is 0.
	allZero := true
	for _, b := range ss {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, ErrLowOrderPoint
	}
	return ss, nil
}

// PublicKeyFromPrivate extracts the public key from a private key.
// For X25519, the public key is derived from the private key.
func PublicKeyFromPrivate(privateKey [KeySize]byte) ([KeySize]byte, error) {
	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return [KeySize]byte{}, err
	}
	var pk [KeySize]byte
	copy(pk[:], publicKey)
	return pk, nil
}

// VerifyPublicKey checks that a public key is valid for X25519.
func VerifyPublicKey(pk [KeySize]byte) bool {
	// Check for the identity element (low-order point).
	// X25519 public keys must not be the all-zero value.
	for _, b := range pk {
		if b != 0 {
			return true
		}
	}
	return false
}

// VerifyPrivateKey checks that a private key is valid for X25519.
// Valid private keys are 32 bytes (clamping is applied during use).
func VerifyPrivateKey(sk [KeySize]byte) bool {
	// Private key must not be all zeros.
	for _, b := range sk {
		if b != 0 {
			return true
		}
	}
	return false
}
