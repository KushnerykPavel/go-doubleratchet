package pqxdh

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
	"github.com/KushnerykPavel/go-doubleratchet/internal/ecutil"
)

// PrekeyBundle is Bob's public prekey bundle including PQ keys.
// Alice fetches this to initiate a session without Bob being online.
type PrekeyBundle struct {
	OneTimePreKey     *[32]byte
	OPKID             *uint32
	PQPreKey          []byte
	PQParams          KEMParams
	SPKID             uint32
	PQPreKeyID        uint32
	SPKSignature      [64]byte
	PQPreKeySignature [64]byte
	IdentityKey       [32]byte
	SignedPreKey      [32]byte
}

// InitialMessage is what Alice sends to Bob alongside the first DR-encrypted message.
type InitialMessage struct {
	OPKID         *uint32
	KEMCiphertext []byte
	PQParams      KEMParams
	PQPreKeyID    uint32
	IdentityKey   [32]byte
	EphemeralKey  [32]byte
}

// HandshakeResult holds the outputs of a completed PQXDH handshake.
// The 96-byte output matches libsignal: root key + chain key + PQR key.
type HandshakeResult struct {
	AD       []byte
	RootKey  [32]byte // feeds Double Ratchet root key
	ChainKey [32]byte // feeds Double Ratchet chain key
	PQRKey   [32]byte // feeds SPQR authentication
}

// HKDF info label matching libsignal for cross-validation.
const pqxdhInfo = "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"

// SendHandshake performs the initiator (Alice) side of PQXDH.
//
// It verifies SPK and PQ prekey signatures, generates an ephemeral key pair,
// computes DH1–DH3 (and DH4 if an OPK is present), encapsulates against the
// PQ prekey, and derives the 96-byte shared secret.
//
// The ephemeral private key and all intermediate key material are zeroed before
// this function returns.
func SendHandshake(senderIK IdentityKey, bundle *PrekeyBundle) (HandshakeResult, InitialMessage, error) {
	// Validate received EC public keys.
	if err := ecutil.ValidatePublicKey(bundle.IdentityKey); err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: bundle identity key: %w", err)
	}
	if err := ecutil.ValidatePublicKey(bundle.SignedPreKey); err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: bundle signed prekey: %w", err)
	}
	if bundle.OneTimePreKey != nil {
		if err := ecutil.ValidatePublicKey(*bundle.OneTimePreKey); err != nil {
			return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: bundle one-time prekey: %w", err)
		}
	}

	// Verify EC SPK signature.
	if !ecutil.XEdDSAVerify(bundle.IdentityKey, bundle.SignedPreKey[:], bundle.SPKSignature) {
		return HandshakeResult{}, InitialMessage{}, ErrInvalidSPKSignature
	}

	// Verify PQ prekey signature.
	if !ecutil.XEdDSAVerify(bundle.IdentityKey, bundle.PQPreKey, bundle.PQPreKeySignature) {
		return HandshakeResult{}, InitialMessage{}, ErrInvalidPQPreKeySignature
	}

	// Generate a per-session ephemeral key pair.
	ekPriv, ekPub, err := ecutil.GenerateX25519KeyPair()
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: ephemeral key generation: %w", err)
	}
	defer crypto.ZeroBytes(ekPriv[:])

	// KEM encapsulation against PQ prekey.
	ct, kemSS, err := kemEncapsulate(bundle.PQPreKey, bundle.PQParams)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: KEM encapsulate: %w", err)
	}
	defer crypto.ZeroBytes(kemSS)

	// DH1 = DH(IKA_priv, SPKB_pub)
	dh1, err := ecutil.DHX25519(senderIK.PrivateKey, bundle.SignedPreKey)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: DH1: %w", err)
	}
	defer crypto.ZeroBytes(dh1)

	// DH2 = DH(EKA_priv, IKB_pub)
	dh2, err := ecutil.DHX25519(ekPriv, bundle.IdentityKey)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: DH2: %w", err)
	}
	defer crypto.ZeroBytes(dh2)

	// DH3 = DH(EKA_priv, SPKB_pub)
	dh3, err := ecutil.DHX25519(ekPriv, bundle.SignedPreKey)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: DH3: %w", err)
	}
	defer crypto.ZeroBytes(dh3)

	var dh4 []byte
	var opkID *uint32
	if bundle.OneTimePreKey != nil {
		// DH4 = DH(EKA_priv, OPKB_pub)
		dh4, err = ecutil.DHX25519(ekPriv, *bundle.OneTimePreKey)
		if err != nil {
			return HandshakeResult{}, InitialMessage{}, fmt.Errorf("pqxdh: DH4: %w", err)
		}
		defer crypto.ZeroBytes(dh4)
		opkID = bundle.OPKID
	}

	result, err := derivePQXDHSK(dh1, dh2, dh3, dh4, kemSS)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, err
	}
	result.AD = buildAD(senderIK.PublicKey, bundle.IdentityKey, bundle.PQPreKey)

	return result, InitialMessage{
		IdentityKey:   senderIK.PublicKey,
		EphemeralKey:  ekPub,
		OPKID:         opkID,
		PQPreKeyID:    bundle.PQPreKeyID,
		PQParams:      bundle.PQParams,
		KEMCiphertext: ct,
	}, nil
}

// ReceiveHandshake performs the responder (Bob) side of PQXDH.
//
// Pqpk must be the KEMPreKey for the key identified by msg.PQPreKeyID — obtain
// it via KEMSignedPreKey.DecapsKey() or KEMOneTimePreKey.DecapsKey(). Its
// Params are validated against msg.PQParams to prevent silent key-mismatch.
//
// The opk parameter must be the OneTimePreKey identified by msg.OPKID, or nil.
// After ReceiveHandshake returns, the caller must discard any used one-time keys.
func ReceiveHandshake(
	receiverIK IdentityKey,
	spk *SignedPreKey,
	opk *OneTimePreKey,
	pqpk KEMPreKey,
	msg *InitialMessage,
) (HandshakeResult, error) {
	// Guard: KEMParams in the message must match the key Bob has stored.
	// Mismatch means a misconfigured server or parameter downgrade attempt.
	if pqpk.Params != msg.PQParams {
		return HandshakeResult{}, fmt.Errorf("pqxdh: KEM params mismatch: key has %v, message has %v", pqpk.Params, msg.PQParams)
	}

	// Validate received EC public keys.
	if err := ecutil.ValidatePublicKey(msg.IdentityKey); err != nil {
		return HandshakeResult{}, fmt.Errorf("pqxdh: sender identity key: %w", err)
	}
	if err := ecutil.ValidatePublicKey(msg.EphemeralKey); err != nil {
		return HandshakeResult{}, fmt.Errorf("pqxdh: sender ephemeral key: %w", err)
	}

	// KEM decapsulation.
	kemSS, err := kemDecapsulate(pqpk, msg.KEMCiphertext)
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("pqxdh: KEM decapsulate: %w", err)
	}
	defer crypto.ZeroBytes(kemSS)

	// DH1 = DH(SPKB_priv, IKA_pub)
	dh1, err := ecutil.DHX25519(spk.PrivateKey, msg.IdentityKey)
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("pqxdh: DH1: %w", err)
	}
	defer crypto.ZeroBytes(dh1)

	// DH2 = DH(IKB_priv, EKA_pub)
	dh2, err := ecutil.DHX25519(receiverIK.PrivateKey, msg.EphemeralKey)
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("pqxdh: DH2: %w", err)
	}
	defer crypto.ZeroBytes(dh2)

	// DH3 = DH(SPKB_priv, EKA_pub)
	dh3, err := ecutil.DHX25519(spk.PrivateKey, msg.EphemeralKey)
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("pqxdh: DH3: %w", err)
	}
	defer crypto.ZeroBytes(dh3)

	var dh4 []byte
	if msg.OPKID != nil {
		if opk == nil {
			return HandshakeResult{}, fmt.Errorf("pqxdh: message uses OPK %d but none provided", *msg.OPKID)
		}
		// DH4 = DH(OPKB_priv, EKA_pub)
		dh4, err = ecutil.DHX25519(opk.PrivateKey, msg.EphemeralKey)
		if err != nil {
			return HandshakeResult{}, fmt.Errorf("pqxdh: DH4: %w", err)
		}
		defer crypto.ZeroBytes(dh4)
	}

	result, err := derivePQXDHSK(dh1, dh2, dh3, dh4, kemSS)
	if err != nil {
		return HandshakeResult{}, err
	}
	result.AD = buildAD(msg.IdentityKey, receiverIK.PublicKey, pqpk.EncapsulationKey)

	return result, nil
}

// derivePQXDHSK computes SK = HKDF-SHA256(salt=0, ikm=F‖DH1‖DH2‖DH3[‖DH4]‖SS, info=label, len=96).
// The key material buffer km is zeroed before returning.
func derivePQXDHSK(dh1, dh2, dh3, dh4, kemSS []byte) (HandshakeResult, error) {
	// F = 0xFF × 32 (discontinuity bytes per spec).
	f := [32]byte{}
	for i := range f {
		f[i] = 0xFF
	}

	size := 32 + 32 + 32 + 32 + 32 // F + DH1 + DH2 + DH3 + SS (kemSS is always 32)
	if dh4 != nil {
		size += 32
	}
	km := make([]byte, 0, size)
	km = append(km, f[:]...)
	km = append(km, dh1...)
	km = append(km, dh2...)
	km = append(km, dh3...)
	if dh4 != nil {
		km = append(km, dh4...)
	}
	km = append(km, kemSS...)
	defer crypto.ZeroBytes(km)

	salt := make([]byte, 32) // all zeros per spec
	r := hkdf.New(sha256.New, km, salt, []byte(pqxdhInfo))
	var sk [96]byte
	if _, err := io.ReadFull(r, sk[:]); err != nil {
		return HandshakeResult{}, fmt.Errorf("pqxdh: HKDF: %w", err)
	}
	defer func() { sk = [96]byte{} }()

	var result HandshakeResult
	copy(result.RootKey[:], sk[:32])
	copy(result.ChainKey[:], sk[32:64])
	copy(result.PQRKey[:], sk[64:96])
	return result, nil
}

// buildAD constructs the associated data: IKA_pub ‖ IKB_pub ‖ PQPK.
// Including the PQ prekey in AD provides stronger binding per PQXDH spec §4.
func buildAD(ikaPublic, ikbPublic [32]byte, pqPreKey []byte) []byte {
	ad := make([]byte, 64+len(pqPreKey))
	copy(ad[:32], ikaPublic[:])
	copy(ad[32:64], ikbPublic[:])
	copy(ad[64:], pqPreKey)
	return ad
}

