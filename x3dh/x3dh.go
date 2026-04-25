package x3dh

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// PrekeyBundle is Bob's public prekey bundle, typically published to a server.
// Alice fetches this to initiate a session without Bob being online.
type PrekeyBundle struct {
	OneTimePreKey *[32]byte
	OPKID         *uint32
	SPKID         uint32
	SPKSignature  [64]byte
	IdentityKey   [32]byte
	SignedPreKey  [32]byte
}

// InitialMessage is what Alice sends to Bob alongside the first DR-encrypted message.
// It lets Bob reconstruct the same shared secret without prior contact.
type InitialMessage struct {
	OPKID        *uint32
	IdentityKey  [32]byte
	EphemeralKey [32]byte
}

// HandshakeResult holds the outputs of a completed X3DH handshake.
type HandshakeResult struct {
	AD           []byte
	SharedSecret [32]byte
}

// HKDF "info" parameter for SK derivation per the X3DH specification.
const x3dhInfo = "X3DH"

// SendHandshake performs the initiator (Alice) side of X3DH.
//
// It verifies the SPK signature in bundle, generates an ephemeral key pair,
// computes DH1–DH3 (and DH4 if an OPK is present), and derives SK.
// The returned InitialMessage must be sent to Bob so he can reproduce SK.
//
// The ephemeral private key is zeroed before this function returns.
func SendHandshake(senderIK IdentityKey, bundle *PrekeyBundle) (HandshakeResult, InitialMessage, error) {
	// Validate received public keys before any computation.
	if err := validatePublicKey(bundle.IdentityKey); err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("x3dh: bundle identity key: %w", err)
	}
	if err := validatePublicKey(bundle.SignedPreKey); err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("x3dh: bundle signed prekey: %w", err)
	}
	if bundle.OneTimePreKey != nil {
		if err := validatePublicKey(*bundle.OneTimePreKey); err != nil {
			return HandshakeResult{}, InitialMessage{}, fmt.Errorf("x3dh: bundle one-time prekey: %w", err)
		}
	}

	// Verify SPK signature before any DH computation.
	if !xeddsaVerify(bundle.IdentityKey, bundle.SignedPreKey[:], bundle.SPKSignature) {
		return HandshakeResult{}, InitialMessage{}, ErrInvalidSPKSignature
	}

	// Generate a per-session ephemeral key pair.
	ekPriv, ekPub, err := generateX25519KeyPair()
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("x3dh: ephemeral key generation: %w", err)
	}
	// Best-effort zeroing of the ephemeral private key after use.
	defer func() {
		for i := range ekPriv {
			ekPriv[i] = 0
		}
	}()

	// DH1 = DH(IKA_priv, SPKB_pub)
	dh1, err := dhX25519(senderIK.PrivateKey, bundle.SignedPreKey)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("x3dh: DH1: %w", err)
	}
	// DH2 = DH(EKA_priv, IKB_pub)
	dh2, err := dhX25519(ekPriv, bundle.IdentityKey)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("x3dh: DH2: %w", err)
	}
	// DH3 = DH(EKA_priv, SPKB_pub)
	dh3, err := dhX25519(ekPriv, bundle.SignedPreKey)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, fmt.Errorf("x3dh: DH3: %w", err)
	}

	var dh4 []byte
	var opkID *uint32
	if bundle.OneTimePreKey != nil {
		// DH4 = DH(EKA_priv, OPKB_pub)
		dh4, err = dhX25519(ekPriv, *bundle.OneTimePreKey)
		if err != nil {
			return HandshakeResult{}, InitialMessage{}, fmt.Errorf("x3dh: DH4: %w", err)
		}
		opkID = bundle.OPKID
	}

	sk, err := deriveX3DHSK(dh1, dh2, dh3, dh4)
	if err != nil {
		return HandshakeResult{}, InitialMessage{}, err
	}

	return HandshakeResult{
			SharedSecret: sk,
			AD:           buildAD(senderIK.PublicKey, bundle.IdentityKey),
		}, InitialMessage{
			IdentityKey:  senderIK.PublicKey,
			EphemeralKey: ekPub,
			OPKID:        opkID,
		}, nil
}

// ReceiveHandshake performs the responder (Bob) side of X3DH.
//
// The opk parameter must be the OneTimePreKey identified by msg.OPKID, or nil if msg.OPKID is nil.
// After ReceiveHandshake returns successfully, the caller must discard the used OPK.
func ReceiveHandshake(receiverIK IdentityKey, spk *SignedPreKey, opk *OneTimePreKey, msg InitialMessage) (HandshakeResult, error) {
	// Validate received public keys before any computation.
	if err := validatePublicKey(msg.IdentityKey); err != nil {
		return HandshakeResult{}, fmt.Errorf("x3dh: sender identity key: %w", err)
	}
	if err := validatePublicKey(msg.EphemeralKey); err != nil {
		return HandshakeResult{}, fmt.Errorf("x3dh: sender ephemeral key: %w", err)
	}

	// DH1 = DH(SPKB_priv, IKA_pub)
	dh1, err := dhX25519(spk.PrivateKey, msg.IdentityKey)
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("x3dh: DH1: %w", err)
	}
	// DH2 = DH(IKB_priv, EKA_pub)
	dh2, err := dhX25519(receiverIK.PrivateKey, msg.EphemeralKey)
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("x3dh: DH2: %w", err)
	}
	// DH3 = DH(SPKB_priv, EKA_pub)
	dh3, err := dhX25519(spk.PrivateKey, msg.EphemeralKey)
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("x3dh: DH3: %w", err)
	}

	var dh4 []byte
	if msg.OPKID != nil {
		if opk == nil {
			return HandshakeResult{}, fmt.Errorf("x3dh: message uses OPK %d but none provided", *msg.OPKID)
		}
		// DH4 = DH(OPKB_priv, EKA_pub)
		dh4, err = dhX25519(opk.PrivateKey, msg.EphemeralKey)
		if err != nil {
			return HandshakeResult{}, fmt.Errorf("x3dh: DH4: %w", err)
		}
	}

	sk, err := deriveX3DHSK(dh1, dh2, dh3, dh4)
	if err != nil {
		return HandshakeResult{}, err
	}

	return HandshakeResult{
		SharedSecret: sk,
		AD:           buildAD(msg.IdentityKey, receiverIK.PublicKey),
	}, nil
}

// dhX25519 computes DH(priv, pub) and rejects low-order points.
func dhX25519(priv, pub [32]byte) ([]byte, error) {
	ss, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return nil, err
	}
	var allZero = true
	for _, b := range ss {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, ErrZeroSharedSecret
	}
	return ss, nil
}

// deriveX3DHSK computes SK = HKDF-SHA256(salt=0x00×32, ikm=F‖DH1‖DH2‖DH3[‖DH4], info="X3DH", len=32).
// Dh4 may be nil when no OPK was used.
func deriveX3DHSK(dh1, dh2, dh3, dh4 []byte) ([32]byte, error) {
	// F = 0xFF × 32 (discontinuity bytes per X3DH spec).
	f := make([]byte, 32)
	for i := range f {
		f[i] = 0xFF
	}

	size := 32 + 32 + 32 + 32
	if dh4 != nil {
		size += 32
	}
	km := make([]byte, 0, size)
	km = append(km, f...)
	km = append(km, dh1...)
	km = append(km, dh2...)
	km = append(km, dh3...)
	if dh4 != nil {
		km = append(km, dh4...)
	}

	salt := make([]byte, 32) // all zeros per X3DH spec
	r := hkdf.New(sha256.New, km, salt, []byte(x3dhInfo))
	var sk [32]byte
	if _, err := io.ReadFull(r, sk[:]); err != nil {
		return [32]byte{}, fmt.Errorf("x3dh: HKDF: %w", err)
	}
	return sk, nil
}

// buildAD constructs the associated data: IKA_pub ‖ IKB_pub.
func buildAD(ikaPublic, ikbPublic [32]byte) []byte {
	ad := make([]byte, 64)
	copy(ad[:32], ikaPublic[:])
	copy(ad[32:], ikbPublic[:])
	return ad
}
