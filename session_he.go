// Package doubleratchet provides header encryption session methods for the Double Ratchet.
package doubleratchet

import (
	"crypto/subtle"

	"doubleratchet/internal/crypto"
	"doubleratchet/internal/kdf"
	"doubleratchet/internal/state"
)

// InitAliceHE initializes a session for Alice with header encryption.
// sharedSecret is the initial shared secret (32+ bytes).
// bobRatchetPK is Bob's initial ratchet public key (32 bytes).
// sharedHKA is Alice's initial header key (32 bytes).
// sharedNHKB is Bob's initial next header key (32 bytes).
// cfg is the session configuration (may be nil for defaults).
func InitAliceHE(sharedSecret []byte, bobRatchetPK [32]byte, sharedHKA [32]byte, sharedNHKB [32]byte, cfg *Config) (*Session, error) {
	if len(sharedSecret) < 32 {
		return nil, ErrInvalidInput
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Generate Alice's ratchet key pair.
	dhsPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Compute DH output: DH(DHs.Private, DHr.Public).
	dhOut, err := crypto.SharedSecret(dhsPriv, bobRatchetPK)
	if err != nil {
		return nil, err
	}

	// Derive RK, CKs, NHKs via KDF_RK_HE per Section 4.4 spec.
	// Use sharedSecret as the keying material for HKDF.
	rk, cks, nhks, err := kdf.KDF_RK_HE(sharedSecret[:32], dhOut)
	if err != nil {
		return nil, err
	}

	// Convert CKs from []byte to bytes type if needed (deriveChainKey returns same type).
	cksBytes := cks

	// Initialize skipped key storage.
	sk, err := state.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, err
	}

	s := &Session{
		RK:                  rk,
		CKs:                 cksBytes,
		CKr:                 nil,
		DHs:                 dhsPriv,
		DHr:                 bobRatchetPK,
		Ns:                  0,
		Nr:                  0,
		PN:                  0,
		MKSKIPPED:           sk,
		Config:              cfg,
		invariants:          state.NewInvariants(),
		dhRatchetPerformed: false,
		// Header encryption keys.
		HKs:  crypto.HeaderKey{Key: sharedHKA, NonceCounter: 0},
		HKr:  crypto.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		NHKs: crypto.HeaderKey{Key: nhks, NonceCounter: 0},
		NHKr: crypto.HeaderKey{Key: sharedNHKB, NonceCounter: 0},
	}

	return s, nil
}

// InitBobHE initializes a session for Bob with header encryption.
// sharedSecret is the initial shared secret (32+ bytes).
// bobKeyPair is Bob's ratchet key pair.
// sharedHKA is Alice's initial header key (32 bytes).
// sharedNHKB is Bob's initial next header key (32 bytes).
// cfg is the session configuration (may be nil for defaults).
func InitBobHE(sharedSecret []byte, bobKeyPair crypto.KeyPair, sharedHKA [32]byte, sharedNHKB [32]byte, cfg *Config) (*Session, error) {
	if len(sharedSecret) < 32 {
		return nil, ErrInvalidInput
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !crypto.VerifyPublicKey(bobKeyPair.PublicKey) {
		return nil, ErrInvalidInput
	}

	// Bob keeps the shared secret as the initial HE root key so the first
	// receive-side derivation matches Alice's initial send-side derivation.
	rk := append([]byte(nil), sharedSecret...)

	// Initialize skipped key storage.
	sk, err := state.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, err
	}

	s := &Session{
		RK:         rk,
		CKs:        nil, // Bob's sending chain is set on first encrypt
		CKr:        nil, // Will be set on first decrypt (DH ratchet)
		DHs:        bobKeyPair.PrivateKey,
		DHr:        [32]byte{}, // DHr is zeroed until first message from Alice arrives
		Ns:         0,
		Nr:         0,
		PN:         0,
		MKSKIPPED:  sk,
		Config:     cfg,
		invariants: state.NewInvariants(),
		// Header encryption keys.
		HKs:  crypto.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		HKr:  crypto.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		NHKs: crypto.HeaderKey{Key: sharedNHKB, NonceCounter: 0},
		NHKr: crypto.HeaderKey{Key: sharedHKA, NonceCounter: 0},
	}

	return s, nil
}

// DHRatchetHE performs a DH ratchet step with header key rotation.
// Called when a new remote ratchet public key is received.
func (s *Session) DHRatchetHE(header Header) error {
	// Save PN = Ns, then reset Ns and Nr.
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0

	// Advance header keys: HKs = NHKs, HKr = NHKr.
	s.HKs = s.NHKs
	s.HKr = s.NHKr

	// Step 1: DH(DHs, DHr) - compute shared secret with current remote key.
	dhOut, err := crypto.SharedSecret(s.DHs, header.RatchetPublicKey)
	if err != nil {
		return err
	}

	// Derive new RK, CKr, NHKr.
	newRK, ckr, nhkr, err := kdf.KDF_RK_HE(s.RK, dhOut)
	if err != nil {
		return err
	}
	s.RK = newRK
	s.CKr = ckr
	s.NHKr.Key = nhkr

	// Generate new DHs key pair.
	newPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Update DHs with new key pair.
	s.DHs = newPriv

	// Step 2: DH(DHs, DHr) with new DHs and current DHr.
	dhOut2, err := crypto.SharedSecret(s.DHs, s.DHr)
	if err != nil {
		return err
	}

	// Derive new RK, CKs, NHKs.
	newRK, cks, nhks, err := kdf.KDF_RK_HE(s.RK, dhOut2)
	if err != nil {
		return err
	}
	s.RK = newRK
	s.CKs = cks
	s.NHKs.Key = nhks

	// Update DHr to the new remote public key from header.
	s.DHr = header.RatchetPublicKey

	return nil
}

// SkipMessageKeysHE stores skipped message keys indexed by HKr.Key.
// Takes header containing PN (previous chain length).
func (s *Session) SkipMessageKeysHE(pn uint32) error {
	if s.CKr == nil {
		return nil
	}

	for s.Nr < pn {
		msgKey, err := kdf.DeriveMessageKey(s.CKr)
		if err != nil {
			return err
		}

		var mk [32]byte
		copy(mk[:], msgKey)
		if err := s.MKSKIPPED.StoreHK(s.HKr.Key, s.Nr, mk); err != nil {
			return err
		}

		s.CKr, _, err = kdf.ChainKDFDerive(s.CKr)
		if err != nil {
			return err
		}
		s.Nr++
	}
	return nil
}

// DecryptHeader decrypts an encrypted header using HKr or NHKr.
// Returns (header, dhRatchetFlag, error).
// dhRatchetFlag is true if decryption succeeded with NHKr.
func (s *Session) DecryptHeader(encHeader EncryptedHeader, ad []byte) (Header, bool, error) {
	if pt, ok := crypto.HDECRYPT(s.HKr.Key, encHeader.Ciphertext, ad); ok {
		header, err := decodeHeader(pt)
		if err != nil {
			return Header{}, false, err
		}
		return header, false, nil
	}

	if pt, ok := crypto.HDECRYPT(s.NHKr.Key, encHeader.Ciphertext, ad); ok {
		header, err := decodeHeader(pt)
		if err != nil {
			return Header{}, false, err
		}
		return header, true, nil
	}

	return Header{}, false, ErrAuthFailure
}

// EncryptHE encrypts a message with encrypted headers.
// Returns (EncryptedHeader, Message).
func (s *Session) EncryptHE(plaintext, ad []byte) (EncryptedHeader, Message, error) {
	// Check if we need to perform a DH ratchet step after receiving.
	// DH ratchet is performed when dhRatchetPerformed flag is set (set by receive side).
	if s.dhRatchetPerformed || s.CKs == nil {
		if err := s.performDHRatchetSendHE(); err != nil {
			return EncryptedHeader{}, Message{}, err
		}
	}

	// Derive message key from CKs.
	if s.CKs == nil {
		return EncryptedHeader{}, Message{}, ErrInvalidTransition
	}

	// Derive message key.
	msgKey, err := deriveMessageKey(s.CKs)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	// Build plaintext header.
	pubKey, err := crypto.PublicKeyFromPrivate(s.DHs)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}
	header := Header{
		RatchetPublicKey: pubKey,
		PN:               s.PN,
		N:                s.Ns,
	}

	// Encode header for encryption.
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	// Encrypt header with HKs.
	// Header encryption AD is just ad (per spec Section 4.2).
	encHeaderBytes, err := crypto.HENCRYPT(&s.HKs, headerBytes, ad)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}
	encHeader := EncryptedHeader{Ciphertext: encHeaderBytes}

	// Bind the payload to the encrypted header rather than the plaintext header.
	ct, err := encryptMessage(msgKey, plaintext, encHeaderBytes, ad)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	// Advance chain key.
	newCKs, err := advanceChainKey(s.CKs)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}
	s.CKs = newCKs

	// Increment message number.
	s.Ns++

	return encHeader, Message{
		Ciphertext: ct,
	}, nil
}

// DecryptHE decrypts a message with encrypted headers.
// Returns plaintext on success, rolls back on auth failure.
func (s *Session) DecryptHE(encHeader EncryptedHeader, msg Message, ad []byte) ([]byte, error) {
	// Record state before any changes for rollback.
	s.invariants.Record(s.Ns, s.Nr, s.PN, s.RK, s.DHs, s.DHr, s.CKs, s.CKr, s.MKSKIPPED)

	// Try skipped keys first by iterating through MKSKIPPED.
	// Per Section 4.6: try HDECRYPT with each stored hk, checking if header.n matches.
	// Header AD is CONCAT(ad, enc_header) per spec.
	if msgKey, found := s.trySkippedMessageKeysHE(encHeader.Ciphertext, ad); found {
		pt, err := decryptMessage(msgKey, msg.Ciphertext, encHeader.Ciphertext, ad)
		if err != nil {
			s.rollback()
			return nil, ErrAuthFailure
		}
		return pt, nil
	}

	// Decrypt header to detect DH ratchet requirement.
	// AD is CONCAT(ad, enc_header) per Section 4.6 spec.
	header, dhRatchet, err := s.DecryptHeader(encHeader, ad)
	if err != nil {
		s.rollback()
		return nil, err
	}

	// Check if this is a new remote ratchet key (DH ratchet).
	newRemotePK := !s.hasRemoteRatchetKey() || !hkBytesEqual(s.DHr[:], header.RatchetPublicKey[:])

	if newRemotePK || dhRatchet {
		// Perform DH ratchet step.
		if err := s.performDHRatchetRecvHE(header, dhRatchet); err != nil {
			s.rollback()
			return nil, err
		}
	}

	// Check MaxSkip before deriving keys.
	if header.N > s.Nr && header.N-s.Nr > s.Config.EffectiveMaxSkip() {
		s.rollback()
		return nil, ErrMaxSkipExceeded
	}

	if err := s.SkipMessageKeysHE(header.N); err != nil {
		s.rollback()
		return nil, err
	}

	// Derive message key from receiving chain key using decrypted header's N.
	msgKey, err := s.deriveRecvMessageKey(header.N)
	if err != nil {
		s.rollback()
		return nil, err
	}

	pt, err := decryptMessage(msgKey, msg.Ciphertext, encHeader.Ciphertext, ad)
	if err != nil {
		s.rollback()
		return nil, ErrAuthFailure
	}

	// Decryption successful - commit state changes.
	s.Nr++

	return pt, nil
}

// performDHRatchetRecvHE performs the receive-side DH ratchet step for header encryption.
func (s *Session) performDHRatchetRecvHE(header Header, promoteNextHeaderKey bool) error {
	// Save current receiving chain key and chain length for skipped message derivation.
	prevCKr := s.CKr
	prevNr := s.Nr
	prevHKr := s.HKr

	if promoteNextHeaderKey {
		s.HKr = s.NHKr
	}

	// Compute DH output: DH(DHs.Private, newRemotePK).
	dhOut, err := crypto.SharedSecret(s.DHs, header.RatchetPublicKey)
	if err != nil {
		return err
	}

	// Derive new root key, receiving chain key, and next header key.
	newRK, ckr, nhkr, err := kdf.KDF_RK_HE(s.RK, dhOut)
	if err != nil {
		return err
	}
	s.RK = newRK
	s.CKr = ckr
	s.NHKr = crypto.HeaderKey{Key: nhkr}

	// Update remote ratchet public key.
	s.DHr = header.RatchetPublicKey

	// Derive skipped message keys for any missed messages from previous chain.
	// The missed messages are from prevNr to (header.PN - 1) if header.PN > prevNr.
	// Must derive from previous CKr (before ratchet), not the new CKr.
	// Skip keys are indexed by HKr.Key (which will become NHKr after rotation).
	if header.PN > prevNr && prevCKr != nil {
		ckr := make([]byte, len(prevCKr))
		copy(ckr, prevCKr)
		for n := prevNr; n < header.PN; n++ {
			msgKey, err := kdf.DeriveMessageKey(ckr)
			if err != nil {
				return err
			}
			var mk [32]byte
			copy(mk[:], msgKey)
			// Previous-chain skipped keys must remain indexed by the header key
			// that actually encrypted that chain's headers.
			if err := s.MKSKIPPED.StoreHK(prevHKr.Key, n, mk); err != nil {
				return err
			}
			ckr, _, err = kdf.ChainKDFDerive(ckr)
			if err != nil {
				return err
			}
		}
	}

	// Reset receiving chain counter.
	s.Nr = 0
	s.CKs = nil

	// The next send ratchet is driven by the missing sending chain state.
	s.dhRatchetPerformed = false

	return nil
}

// decodeHeader decodes bytes into a Header.
func decodeHeader(data []byte) (Header, error) {
	if len(data) < 32+4+4 {
		return Header{}, ErrInvalidInput
	}
	var h Header
	copy(h.RatchetPublicKey[:], data[:32])
	h.PN = hkGetUint32BE(data[32:])
	h.N = hkGetUint32BE(data[36:])
	return h, nil
}

func hkGetUint32BE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func hkBytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// trySkippedMessageKeysHE iterates through MKSKIPPED and tries to decrypt
// the encrypted header with each stored header key. Per Section 4.6 spec.
func (s *Session) trySkippedMessageKeysHE(encHeader []byte, headerAD []byte) ([]byte, bool) {
	return s.MKSKIPPED.TryAllHeaderKeys(encHeader, headerAD, crypto.HDECRYPT)
}

// performDHRatchetSendHE performs the DH ratchet step for the sending side
// after a DH ratchet was performed on the receiving side.
func (s *Session) performDHRatchetSendHE() error {
	// Save PN = Ns, reset Ns.
	s.PN = s.Ns
	s.Ns = 0

	// Promote the pending sending header key before sending the first message of
	// the new local sending chain.
	s.HKs = s.NHKs

	// Generate the new local ratchet key for this sending chain.
	newPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}

	// The receive side already advanced RK/CKr; sending only needs the second
	// DH step using the fresh local ratchet key and the current remote key.
	dhOut, err := crypto.SharedSecret(newPriv, s.DHr)
	if err != nil {
		return err
	}

	newRK, cks, nhks, err := kdf.KDF_RK_HE(s.RK, dhOut)
	if err != nil {
		return err
	}
	s.RK = newRK
	s.CKs = cks
	s.NHKs = crypto.HeaderKey{Key: nhks}
	s.DHs = newPriv

	// Clear DH ratchet performed flag.
	s.dhRatchetPerformed = false

	return nil
}
