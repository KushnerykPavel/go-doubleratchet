// Package doubleratchet implements the base Signal Double Ratchet algorithm.
package doubleratchet

import (
	"crypto/subtle"

	"doubleratchet/internal/crypto"
	"doubleratchet/internal/kdf"
	"doubleratchet/internal/state"
	"doubleratchet/internal/suite"
)

const (
	// RootKeySize is the root key size (32 bytes).
	RootKeySize = 32
	// ChainKeySize is the chain key size (32 bytes).
	ChainKeySize = 32
	// MessageKeySize is the message key size (32 bytes).
	MessageKeySize = 32
)

var (
	rootKeyLabel               = []byte("DoubleRatchetRootKey")
	chainKeyDerivationConstant = []byte{0x01}
	messageKeyLabel            = []byte("DoubleRatchetMessageKey")
)

// Session represents a Double Ratchet session state.
type Session struct {
	// RK is the current root key.
	RK []byte
	// CKs is the current sending chain key.
	CKs []byte
	// CKr is the current receiving chain key (nil if not yet set).
	CKr []byte
	// DHs is the current local ratchet private key.
	DHs [32]byte
	// DHr is the current remote ratchet public key.
	DHr [32]byte
	// Ns is the number of messages sent in the current sending chain.
	Ns uint32
	// Nr is the number of messages received in the current receiving chain.
	Nr uint32
	// PN is the number of messages in the previous sending chain.
	PN uint32
	// MKSKIPPED stores skipped message keys.
	MKSKIPPED *state.Storage
	// Config is the session configuration.
	Config *Config
	// invariants tracks state for rollback verification.
	invariants *state.Invariants
	// dhRatchetPerformed tracks if DH ratchet was performed since last send.
	// Used to detect when sending side should perform DH ratchet step.
	dhRatchetPerformed bool
}

// InitAlice initializes a session for Alice (the sender who knows Bob's initial ratchet public key).
// sharedSecret is the initial shared secret (32+ bytes).
// bobRatchetPK is Bob's initial ratchet public key (32 bytes).
// cfg is the session configuration (may be nil for defaults).
func InitAlice(sharedSecret []byte, bobRatchetPK [32]byte, cfg *Config) (*Session, error) {
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

	// Derive root key via HKDF: RK = HKDF(DH output as salt, shared secret as IKM).
	rk, err := deriveRootKey(dhOut, sharedSecret)
	if err != nil {
		return nil, err
	}

	// Derive sending chain key.
	cks, err := deriveChainKey(rk)
	if err != nil {
		return nil, err
	}

	// Initialize skipped key storage.
	sk, err := state.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, err
	}

	s := &Session{
		RK:                  rk,
		CKs:                 cks,
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
	}

	return s, nil
}

// InitBob initializes a session for Bob (the receiver who has his own ratchet key pair).
// sharedSecret is the initial shared secret (32+ bytes).
// bobKeyPair is Bob's ratchet key pair.
// cfg is the session configuration (may be nil for defaults).
func InitBob(sharedSecret []byte, bobKeyPair crypto.KeyPair, cfg *Config) (*Session, error) {
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

	// Compute DH output: DH(Bob.Private, Alice.PublicKey).
	// Alice's public key is passed implicitly - but wait, Bob doesn't know Alice's public key yet!
	// In the Double Ratchet, Bob's initial state uses the shared secret + his key pair.
	// The DH ratchet happens when messages arrive.

	// For Bob's initialization: derive RK from shared secret.
	// The first DH ratchet will happen when Bob receives Alice's first message.
	rk, err := deriveRootKeyFromSecret(sharedSecret)
	if err != nil {
		return nil, err
	}

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
	}

	return s, nil
}

// Encrypt encrypts a plaintext message.
// ad is additional authenticated data (included in authentication but not encrypted).
func (s *Session) Encrypt(plaintext, ad []byte) (Message, error) {
	// Check if we need to perform a DH ratchet step.
	// DH ratchet is performed when dhRatchetPerformed flag is set (set by receive side).
	if s.dhRatchetPerformed {
		if err := s.performDHRatchetSend(); err != nil {
			return Message{}, err
		}
	}

	// Derive message key from current sending chain key.
	msgKey, err := deriveMessageKey(s.CKs)
	if err != nil {
		return Message{}, err
	}

	// Build header with public key (computed from private).
	pubKey, err := crypto.PublicKeyFromPrivate(s.DHs)
	if err != nil {
		return Message{}, err
	}
	header := Header{
		RatchetPublicKey: pubKey,
		PN:               s.PN,
		N:                s.Ns,
	}

	// Encrypt using internal suite.
	// The AD includes the header bytes for authentication.
	headerBytes, err := encodeHeader(header)
	if err != nil {
		return Message{}, err
	}

	ct, err := encryptMessage(msgKey, plaintext, headerBytes, ad)
	if err != nil {
		return Message{}, err
	}

	// Advance sending chain key.
	newCKs, err := advanceChainKey(s.CKs)
	if err != nil {
		return Message{}, err
	}
	s.CKs = newCKs

	// Increment message number.
	s.Ns++

	return Message{
		Header:    header,
		Ciphertext: ct,
	}, nil
}

// Decrypt decrypts a message.
// ad is the additional authenticated data (must match what was used during encryption).
func (s *Session) Decrypt(msg Message, ad []byte) ([]byte, error) {
	// Record state before any changes for rollback.
	s.invariants.Record(s.Ns, s.Nr, s.PN, s.RK, s.DHs, s.DHr, s.CKs, s.CKr, s.MKSKIPPED)

	// Try skipped keys first.
	if msgKey, found := s.MKSKIPPED.Get(msg.Header.RatchetPublicKey, msg.Header.N); found {
		// Found a skipped key for this exact (pk, n) pair.
		headerBytes, err := encodeHeader(msg.Header)
		if err != nil {
			return nil, err
		}
		pt, err := decryptMessage(msgKey, msg.Ciphertext, headerBytes, ad)
		if err != nil {
			// Even if decryption fails, rollback.
			s.rollback()
			return nil, ErrAuthFailure
		}
		// Successfully decrypted a skipped message.
		s.Nr++
		return pt, nil
	}

	// Check if this is a new remote ratchet key (DH ratchet).
	newRemotePK := !s.hasRemoteRatchetKey() || !bytesEqual(s.DHr[:], msg.Header.RatchetPublicKey[:])

	if newRemotePK {
		// Perform DH ratchet step.
		if err := s.performDHRatchetRecv(msg.Header); err != nil {
			s.rollback()
			return nil, err
		}
	}

	// Check MaxSkip before deriving keys.
	if msg.Header.N > s.Nr && msg.Header.N-s.Nr > s.Config.EffectiveMaxSkip() {
		s.rollback()
		return nil, ErrMaxSkipExceeded
	}

	// Derive message key from receiving chain key.
	msgKey, err := s.deriveRecvMessageKey(msg.Header.N)
	if err != nil {
		s.rollback()
		return nil, err
	}

	// Decrypt.
	headerBytes, err := encodeHeader(msg.Header)
	if err != nil {
		s.rollback()
		return nil, err
	}

	pt, err := decryptMessage(msgKey, msg.Ciphertext, headerBytes, ad)
	if err != nil {
		s.rollback()
		return nil, ErrAuthFailure
	}

	// Decryption successful - commit state changes.
	s.Nr++

	return pt, nil
}

// performDHRatchetSend performs the DH ratchet step for the sending side.
func (s *Session) performDHRatchetSend() error {
	// Save current sending chain length as PN.
	s.PN = s.Ns

	// Generate new DH key pair.
	newPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}

	// Compute new shared secret with new DHs.Private and current DHr.Public.
	dhOut, err := crypto.SharedSecret(newPriv, s.DHr)
	if err != nil {
		return err
	}

	// Derive new root key and sending chain key.
	rk, cks, err := deriveRootAndChain(dhOut, s.RK)
	if err != nil {
		return err
	}
	s.RK = rk
	s.CKs = cks

	// Update DHs with new key pair (store private key).
	s.DHs = newPriv

	// Reset sending chain counter.
	s.Ns = 0

	// Clear DH ratchet flag - we just performed it.
	s.dhRatchetPerformed = false

	return nil
}

// performDHRatchetRecv performs the DH ratchet step for the receiving side.
func (s *Session) performDHRatchetRecv(header Header) error {
	// Save current receiving chain key and chain length for skipped message derivation.
	prevCKr := s.CKr
	prevNr := s.Nr
	prevDHr := s.DHr // Capture before updating DHr.

	// Compute DH output: DH(DHr.Private, newRemotePK).
	dhOut, err := crypto.SharedSecret(s.DHs, header.RatchetPublicKey)
	if err != nil {
		return err
	}

	// Derive new root key and receiving chain key.
	newRK, ckr, err := deriveRootAndChain(dhOut, s.RK)
	if err != nil {
		return err
	}
	s.RK = newRK
	s.CKr = ckr

	// Update remote ratchet public key.
	s.DHr = header.RatchetPublicKey

	// Derive skipped message keys for any missed messages from previous chain.
	// The missed messages are from prevNr to (header.PN - 1) if header.PN > prevNr.
	// Must derive from previous CKr (before ratchet), not the new CKr.
	if header.PN > prevNr && prevCKr != nil {
		for n := prevNr; n < header.PN; n++ {
			// Derive message key for skipped message n.
			// Advance from prevCKr n times to get the key for message n.
			tmpCKr := make([]byte, len(prevCKr))
			copy(tmpCKr, prevCKr)
			for i := uint32(0); i < n; i++ {
				tmpCKr, _, err = kdf.ChainKDFDerive(tmpCKr)
				if err != nil {
					return err
				}
			}
			msgKey, err := kdf.DeriveMessageKey(tmpCKr)
			if err != nil {
				return err
			}
			var mk [32]byte
			copy(mk[:], msgKey)
			// Store indexed by prevDHr (the remote PK before the ratchet).
			if err := s.MKSKIPPED.Store(prevDHr, n, mk); err != nil {
				return err
			}
		}
	}

	// Reset receiving chain counter.
	s.Nr = 0

	// Signal to sending side that DH ratchet should be performed.
	s.dhRatchetPerformed = true

	return nil
}

// deriveRecvMessageKey derives the message key for receive message number n.
// The receiving chain key CKr must already be set.
func (s *Session) deriveRecvMessageKey(n uint32) ([]byte, error) {
	if s.CKr == nil {
		return nil, ErrInvalidTransition
	}

	// Derive chain keys for each message in the receiving chain up to n.
	// The message key for message n is the n-th message key derived from CKr.
	ckr := make([]byte, len(s.CKr))
	copy(ckr, s.CKr)

	var msgKey []byte
	var err error

	for i := uint32(0); i <= n; i++ {
		if i == n {
			msgKey, err = kdf.DeriveMessageKey(ckr)
			if err != nil {
				return nil, err
			}
		} else {
			// Advance chain key but don't use the message key.
			ckr, _, err = kdf.ChainKDFDerive(ckr)
			if err != nil {
				return nil, err
			}
		}
	}

	if msgKey == nil {
		return nil, ErrInvalidTransition
	}

	// Advance the receiving chain key past message n.
	s.CKr, _, err = kdf.ChainKDFDerive(ckr)
	if err != nil {
		return nil, err
	}

	return msgKey, nil
}

// rollback reverts session state to the recorded previous values.
func (s *Session) rollback() {
	prev := s.invariants.GetPrevState()
	s.Ns = prev.Ns
	s.Nr = prev.Nr
	s.PN = prev.PN
	s.RK = prev.RK
	s.DHs = prev.DHs
	s.DHr = prev.DHr
	s.CKs = prev.CKs
	s.CKr = prev.CKr
	s.MKSKIPPED = prev.MKSKIPPED
}

// hasRemoteRatchetKey returns true if the remote ratchet key is set.
func (s *Session) hasRemoteRatchetKey() bool {
	for _, b := range s.DHr {
		if b != 0 {
			return true
		}
	}
	return false
}

// remoteKeyChanged returns true if the header's ratchet public key differs from stored DHr.
func (s *Session) remoteKeyChanged(headerPubKey [32]byte) bool {
	return !bytesEqual(s.DHr[:], headerPubKey[:])
}

// shouldPerformDHRatchet returns true if the sending side should perform a DH ratchet step.
func (s *Session) shouldPerformDHRatchet(headerPubKey [32]byte) bool {
	// Perform DH ratchet when remote key changes (new ratchet public key in header).
	return s.hasRemoteRatchetKey() && !bytesEqual(s.DHr[:], headerPubKey[:])
}

// --- Key Derivation Helpers ---

// deriveRootKey derives the root key from DH output (salt) and shared secret (IKM).
// Per Signal spec: RK = HKDF(DH(A0,B0), shared_secret) where DH output is salt.
// No info parameter is used.
func deriveRootKey(dhOutput, sharedSecret []byte) ([]byte, error) {
	r := kdf.NewRootKDF(dhOutput, nil)
	if err := r.Derive(sharedSecret); err != nil {
		return nil, err
	}
	return r.Expand(nil, RootKeySize)
}

// deriveRootKeyFromSecret derives root key directly from shared secret (for Bob's init).
// Per Signal spec: no info parameter.
func deriveRootKeyFromSecret(sharedSecret []byte) ([]byte, error) {
	r := kdf.NewRootKDF(nil, nil)
	if err := r.Derive(sharedSecret); err != nil {
		return nil, err
	}
	return r.Expand(nil, RootKeySize)
}

// deriveChainKey derives a chain key from the root key using HKDF.
// Per Signal spec: CK = HKDF(RK, 0x01).
func deriveChainKey(rk []byte) ([]byte, error) {
	r := kdf.NewRootKDF(nil, chainKeyDerivationConstant)
	if err := r.Derive(rk); err != nil {
		return nil, err
	}
	return r.Expand(chainKeyDerivationConstant, ChainKeySize)
}

// deriveRootAndChain derives new root key and chain key from DH output.
// Returns new root key, new chain key.
// Per Signal spec: RK_{i+1} = HKDF(DH(DHr_i, DHs_{i+1}), RK_i) where DH output is salt, RK_i is IKM.
func deriveRootAndChain(dhOutput, currentRK []byte) ([]byte, []byte, error) {
	// DH output is salt, current RK is IKM.
	r := kdf.NewRootKDF(dhOutput, nil)
	if err := r.Derive(currentRK); err != nil {
		return nil, nil, err
	}
	newRK, err := r.Expand(nil, RootKeySize)
	if err != nil {
		return nil, nil, err
	}

	// Derive new chain key from new root key.
	newCK, err := deriveChainKey(newRK)
	if err != nil {
		return nil, nil, err
	}

	return newRK, newCK, nil
}

// deriveMessageKey derives a message key from a chain key.
func deriveMessageKey(chainKey []byte) ([]byte, error) {
	return kdf.DeriveMessageKey(chainKey)
}

// advanceChainKey advances a chain key to the next value.
func advanceChainKey(chainKey []byte) ([]byte, error) {
	newCK, _, err := kdf.ChainKDFDerive(chainKey)
	return newCK, err
}

// encryptMessage encrypts a message using the internal suite.
func encryptMessage(key, plaintext, header, ad []byte) ([]byte, error) {
	// Derive AES and HMAC keys from the message key.
	aesKey, macKey := suite.DeriveKeys(key, "DoubleratchetMessage")
	combinedKey := append(aesKey, macKey...)

	// Build AD from header.
	combinedAD := append(header, ad...)

	return suite.Encrypt(combinedKey, plaintext, combinedAD)
}

// decryptMessage decrypts a message using the internal suite.
func decryptMessage(key, ciphertext, header, ad []byte) ([]byte, error) {
	aesKey, macKey := suite.DeriveKeys(key, "DoubleratchetMessage")
	combinedKey := append(aesKey, macKey...)

	combinedAD := append(header, ad...)

	return suite.Decrypt(combinedKey, ciphertext, combinedAD)
}

// encodeHeader encodes the header to bytes for AD computation.
func encodeHeader(h Header) ([]byte, error) {
	// Encode: 32-byte public key + 4-byte PN + 4-byte N.
	buf := make([]byte, 32+4+4)
	copy(buf[:32], h.RatchetPublicKey[:])
	putUint32BE(buf[32:], h.PN)
	putUint32BE(buf[32+4:], h.N)
	return buf, nil
}

func putUint32BE(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
