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

// KeyPair represents an X25519 key pair.
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

var errInvalidKey = errors.New("invalid key")

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
	return
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
// Returns a 32-byte shared secret.
func SharedSecret(privateKey, publicKey [KeySize]byte) ([]byte, error) {
	ss, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return nil, err
	}
	return ss, nil
}

// DHRatchet performs a DH ratchet step using the local private key and remote public key.
// Returns the new shared secret.
func DHRatchet(localPrivate, remotePublic [KeySize]byte) ([]byte, error) {
	return SharedSecret(localPrivate, remotePublic)
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
