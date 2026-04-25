// Package pqxdh implements the PQXDH (Post-Quantum Extended Diffie-Hellman)
// key agreement protocol per the Signal specification at
// https://signal.org/docs/specifications/pqxdh/.
//
// PQXDH extends X3DH by adding a post-quantum KEM (ML-KEM) to the handshake,
// providing resistance against "harvest now, decrypt later" quantum attacks.
// The output feeds directly into the Double Ratchet and SPQR ratchets.
package pqxdh

import (
	"errors"

	"github.com/KushnerykPavel/go-doubleratchet/internal/ecutil"
)

// ErrZeroSharedSecret is returned when an X25519 DH computation produces all-zero
// output, indicating the peer provided a low-order point.
var ErrZeroSharedSecret = ecutil.ErrZeroSharedSecret

// ErrInvalidPublicKey is returned when a received public key fails
// canonical or torsion-free validation.
var ErrInvalidPublicKey = ecutil.ErrInvalidPublicKey

// ErrInvalidSPKSignature is returned when the signed prekey signature in a
// PrekeyBundle fails XEdDSA verification.
var ErrInvalidSPKSignature = errors.New("pqxdh: invalid signed prekey signature")

// ErrInvalidPQPreKeySignature is returned when the PQ prekey signature in a
// PrekeyBundle fails XEdDSA verification.
var ErrInvalidPQPreKeySignature = errors.New("pqxdh: invalid PQ prekey signature")

// IdentityKey is a long-term X25519 key pair used for authentication.
type IdentityKey struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// SignedPreKey is a semi-static X25519 key pair. The Signature is an XEdDSA
// signature over PublicKey made with the owner's IdentityKey.
type SignedPreKey struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
	KeyID      uint32
	Signature  [64]byte
}

// OneTimePreKey is a single-use X25519 key pair that provides an additional
// DH contribution (DH4) for enhanced forward secrecy.
type OneTimePreKey struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
	KeyID      uint32
}

// GenerateIdentityKey generates a new long-term X25519 identity key pair.
func GenerateIdentityKey() (IdentityKey, error) {
	priv, pub, err := ecutil.GenerateX25519KeyPair()
	if err != nil {
		return IdentityKey{}, err
	}
	return IdentityKey{PrivateKey: priv, PublicKey: pub}, nil
}

// GenerateSPK generates a new signed prekey and signs it with ik using XEdDSA.
func GenerateSPK(ik IdentityKey, keyID uint32) (SignedPreKey, error) {
	priv, pub, err := ecutil.GenerateX25519KeyPair()
	if err != nil {
		return SignedPreKey{}, err
	}
	sig, err := ecutil.XEdDSASign(ik.PrivateKey, pub[:])
	if err != nil {
		return SignedPreKey{}, err
	}
	return SignedPreKey{PrivateKey: priv, PublicKey: pub, KeyID: keyID, Signature: sig}, nil
}

// GenerateOPK generates a new one-time prekey with the given ID.
func GenerateOPK(keyID uint32) (OneTimePreKey, error) {
	priv, pub, err := ecutil.GenerateX25519KeyPair()
	if err != nil {
		return OneTimePreKey{}, err
	}
	return OneTimePreKey{PrivateKey: priv, PublicKey: pub, KeyID: keyID}, nil
}
