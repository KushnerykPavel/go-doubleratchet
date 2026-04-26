package pqxdh

import (
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"io"

	"github.com/KushnerykPavel/go-doubleratchet/internal/ecutil"
)

// ErrUnsupportedKEMParams is returned for unknown KEMParams values.
var ErrUnsupportedKEMParams = errors.New("pqxdh: unsupported KEM parameter set")

// KEMParams specifies the ML-KEM parameter set.
type KEMParams int

const (
	// MLKEM768 selects ML-KEM-768 (NIST security level 3).
	MLKEM768 KEMParams = iota
	// MLKEM1024 selects ML-KEM-1024 (NIST security level 5).
	// This is the default, matching libsignal's Kyber-1024.
	MLKEM1024
)

// String returns the human-readable name of the KEM parameter set.
func (p KEMParams) String() string {
	switch p {
	case MLKEM768:
		return "ML-KEM-768"
	case MLKEM1024:
		return "ML-KEM-1024"
	default:
		return "unknown"
	}
}

// kemSeedSize is the seed size for ML-KEM key generation (64 bytes: d‖z per FIPS 203).
const kemSeedSize = 64

// kemOps bundles the three ML-KEM operations for a single parameter set.
// Adding a new parameter set requires only a new entry in kemRegistry.
type kemOps struct {
	generateEncapKey func(seed []byte) (encapKey []byte, err error)
	encapsulate      func(encapKey []byte) (ct, ss []byte, err error)
	decapsulate      func(seed, ct []byte) (ss []byte, err error)
}

// kemRegistry maps KEMParams to its ML-KEM operations. Adding a new
// parameter set requires a single entry here; no existing code changes.
var kemRegistry = map[KEMParams]kemOps{
	MLKEM768: {
		generateEncapKey: func(seed []byte) ([]byte, error) {
			dk, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, err
			}
			return dk.EncapsulationKey().Bytes(), nil
		},
		encapsulate: func(encapKey []byte) ([]byte, []byte, error) {
			ek, err := mlkem.NewEncapsulationKey768(encapKey)
			if err != nil {
				return nil, nil, err
			}
			ss, ct := ek.Encapsulate()
			return ct, ss, nil
		},
		decapsulate: func(seed, ct []byte) ([]byte, error) {
			dk, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, err
			}
			return dk.Decapsulate(ct)
		},
	},
	MLKEM1024: {
		generateEncapKey: func(seed []byte) ([]byte, error) {
			dk, err := mlkem.NewDecapsulationKey1024(seed)
			if err != nil {
				return nil, err
			}
			return dk.EncapsulationKey().Bytes(), nil
		},
		encapsulate: func(encapKey []byte) ([]byte, []byte, error) {
			ek, err := mlkem.NewEncapsulationKey1024(encapKey)
			if err != nil {
				return nil, nil, err
			}
			ss, ct := ek.Encapsulate()
			return ct, ss, nil
		},
		decapsulate: func(seed, ct []byte) ([]byte, error) {
			dk, err := mlkem.NewDecapsulationKey1024(seed)
			if err != nil {
				return nil, err
			}
			return dk.Decapsulate(ct)
		},
	},
}

// KEMSignedPreKey is a signed last-resort KEM prekey (PQSPK).
// The Signature is XEdDSA(IdentityKey, EncapsulationKey).
// Seed is sensitive private key material — zero it when done.
type KEMSignedPreKey struct {
	EncapsulationKey []byte
	Params           KEMParams
	KeyID            uint32
	Seed             [kemSeedSize]byte
	Signature        [64]byte
}

// KEMOneTimePreKey is a single-use signed KEM prekey (PQOPK).
// Seed is sensitive private key material — zero it after decapsulation.
type KEMOneTimePreKey struct {
	EncapsulationKey []byte
	Params           KEMParams
	KeyID            uint32
	Seed             [kemSeedSize]byte
	Signature        [64]byte
}

// KEMPreKey bundles the seed and parameter set needed for decapsulation.
// Obtain it from KEMSignedPreKey.DecapsKey() or KEMOneTimePreKey.DecapsKey().
type KEMPreKey struct {
	EncapsulationKey []byte
	Seed             [kemSeedSize]byte
	Params           KEMParams
}

// DecapsKey returns the decapsulation key material for use in ReceiveHandshake.
func (k *KEMSignedPreKey) DecapsKey() *KEMPreKey {
	return &KEMPreKey{EncapsulationKey: k.EncapsulationKey, Seed: k.Seed, Params: k.Params}
}

// DecapsKey returns the decapsulation key material for use in ReceiveHandshake.
func (k *KEMOneTimePreKey) DecapsKey() *KEMPreKey {
	return &KEMPreKey{EncapsulationKey: k.EncapsulationKey, Seed: k.Seed, Params: k.Params}
}

// GenerateKEMSPK generates a signed last-resort KEM prekey.
func GenerateKEMSPK(ik IdentityKey, keyID uint32, params KEMParams) (KEMSignedPreKey, error) {
	seed, encapKey, err := kemGenerateKey(params)
	if err != nil {
		return KEMSignedPreKey{}, err
	}
	sig, err := ecutil.XEdDSASign(ik.PrivateKey, encapKey)
	if err != nil {
		return KEMSignedPreKey{}, err
	}
	return KEMSignedPreKey{
		Seed:             seed,
		EncapsulationKey: encapKey,
		KeyID:            keyID,
		Signature:        sig,
		Params:           params,
	}, nil
}

// GenerateKEMOPK generates a signed one-time KEM prekey.
func GenerateKEMOPK(ik IdentityKey, keyID uint32, params KEMParams) (KEMOneTimePreKey, error) {
	seed, encapKey, err := kemGenerateKey(params)
	if err != nil {
		return KEMOneTimePreKey{}, err
	}
	sig, err := ecutil.XEdDSASign(ik.PrivateKey, encapKey)
	if err != nil {
		return KEMOneTimePreKey{}, err
	}
	return KEMOneTimePreKey{
		Seed:             seed,
		EncapsulationKey: encapKey,
		KeyID:            keyID,
		Signature:        sig,
		Params:           params,
	}, nil
}

// kemGenerateKey generates an ML-KEM key pair, returning the seed and encapsulation key bytes.
func kemGenerateKey(params KEMParams) (seed [kemSeedSize]byte, encapKey []byte, err error) {
	ops, ok := kemRegistry[params]
	if !ok {
		return [kemSeedSize]byte{}, nil, ErrUnsupportedKEMParams
	}
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return [kemSeedSize]byte{}, nil, err
	}
	encapKey, err = ops.generateEncapKey(seed[:])
	if err != nil {
		return [kemSeedSize]byte{}, nil, err
	}
	return seed, encapKey, nil
}

// kemEncapsulate encapsulates a shared secret against the given encapsulation key bytes.
// Returns (ciphertext, sharedSecret).
func kemEncapsulate(encapKeyBytes []byte, params KEMParams) (ct, ss []byte, err error) {
	ops, ok := kemRegistry[params]
	if !ok {
		return nil, nil, ErrUnsupportedKEMParams
	}
	return ops.encapsulate(encapKeyBytes)
}

// kemDecapsulate decapsulates a shared secret using the seed to reconstruct the decapsulation key.
func kemDecapsulate(pqpk *KEMPreKey, ciphertext []byte) (ss []byte, err error) {
	ops, ok := kemRegistry[pqpk.Params]
	if !ok {
		return nil, ErrUnsupportedKEMParams
	}
	return ops.decapsulate(pqpk.Seed[:], ciphertext)
}
