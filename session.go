// Package doubleratchet implements the base Signal Double Ratchet algorithm.
package doubleratchet

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
	"github.com/KushnerykPavel/go-doubleratchet/internal/kdf"
	state2 "github.com/KushnerykPavel/go-doubleratchet/internal/state"
	"github.com/KushnerykPavel/go-doubleratchet/internal/suite"
)

const (
	// RootKeySize is the root key size (32 bytes).
	RootKeySize = 32
	// ChainKeySize is the chain key size (32 bytes).
	ChainKeySize = 32
	// MessageKeySize is the message key size (32 bytes).
	MessageKeySize = 32
)

// Session represents a Double Ratchet session state.
type Session struct {
	invariants         *state2.Invariants
	config             *Config
	mkSkipped          *state2.Storage
	recvChains         *state2.ReceiverChains
	rk                 []byte
	cks                []byte
	ns                 uint32
	pn                 uint32
	dhr                [32]byte
	dhs                [32]byte
	dhRatchetPerformed bool
	dhRSet             bool
}

// InitInitiator initializes a session for the Initiator (the sender who knows the Responder's initial ratchet public key).
// SharedSecret is the initial shared secret (32+ bytes); only the first 32 bytes are used.
//
// Security note: The ad parameter passed to Encrypt/Decrypt is included verbatim in the
// HMAC. To bind messages to specific sender/receiver identities and prevent cross-session
// replay, callers SHOULD include both parties' stable identity public keys in ad.
// See BindIdentities for a helper. This matches Signal spec §3.3.
func InitInitiator(sharedSecret []byte, bobRatchetPK [32]byte, cfg *Config) (*Session, error) {
	if len(sharedSecret) < 32 {
		return nil, ErrInvalidInput
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	dhsPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	dhOut, err := crypto.SharedSecret(dhsPriv, bobRatchetPK)
	if err != nil {
		return nil, err
	}

	rk, cks, err := deriveRootAndChain(dhOut, sharedSecret[:32], cfg.effectiveKDFInfo())
	if err != nil {
		return nil, err
	}

	sk, err := state2.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, err
	}

	return &Session{
		rk:                 rk,
		cks:                cks,
		recvChains:         state2.NewReceiverChains(),
		dhs:                dhsPriv,
		dhr:                bobRatchetPK,
		ns:                 0,
		pn:                 0,
		mkSkipped:          sk,
		config:             cfg,
		invariants:         state2.NewInvariants(),
		dhRatchetPerformed: false,
		dhRSet:             true, // Initiator knows Responder's key from initialization
	}, nil
}

// InitResponder initializes a session for the Responder (the receiver who has their own ratchet key pair).
// SharedSecret is the initial shared secret (32+ bytes); only the first 32 bytes are used.
//
// Security note: The ad parameter passed to Encrypt/Decrypt is included verbatim in the
// HMAC. To bind messages to specific sender/receiver identities and prevent cross-session
// replay, callers SHOULD include both parties' stable identity public keys in ad.
// See BindIdentities for a helper. This matches Signal spec §3.3.
func InitResponder(sharedSecret []byte, bobKeyPair crypto.KeyPair, cfg *Config) (*Session, error) {
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

	rk := append([]byte(nil), sharedSecret[:32]...)

	sk, err := state2.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, err
	}

	return &Session{
		rk:         rk,
		cks:        nil,
		recvChains: state2.NewReceiverChains(),
		dhs:        bobKeyPair.PrivateKey,
		dhr:        [32]byte{},
		ns:         0,
		pn:         0,
		mkSkipped:  sk,
		config:     cfg,
		invariants: state2.NewInvariants(),
		dhRSet:     false, // Responder has not yet received Initiator's first message
	}, nil
}

// Encrypt encrypts a plaintext message.
// Ad is additional authenticated data. When Config.LocalIdentityKey and
// Config.RemoteIdentityKey are set, they are automatically prepended to
// the MAC input, binding each message to the session's identity pair.
func (s *Session) Encrypt(plaintext, ad []byte) (Message, error) {
	if s.dhRatchetPerformed {
		if err := s.performDHRatchetSend(); err != nil {
			return Message{}, err
		}
	}

	// After potential ratchet, cks must be set.
	// Responder cannot encrypt before receiving Initiator's first message.
	if s.cks == nil {
		return Message{}, ErrSessionNotInitialized
	}

	msgKey, err := deriveMessageKey(s.cks)
	if err != nil {
		return Message{}, err
	}

	newCKs, err := advanceChainKey(s.cks)
	if err != nil {
		return Message{}, err
	}

	// Advance chain state before encryption (spec §3: cks, mk = KDF_CK(cks) then ns++).
	// If a subsequent step fails, state is advanced without producing a message;
	// callers must treat Encrypt errors as fatal and not retry with different plaintext.
	zeroBytes(s.cks)
	s.cks = newCKs
	n := s.ns
	s.ns++

	pubKey, err := crypto.PublicKeyFromPrivate(s.dhs)
	if err != nil {
		return Message{}, err
	}
	header := Header{
		RatchetPublicKey: pubKey,
		PN:               s.pn,
		N:                n,
	}

	headerBytes := encodeHeader(header)

	combinedAD := s.buildAD(headerBytes, ad, true)
	ct, err := suite.Encrypt(msgKey, plaintext, combinedAD, s.config.effectiveEncryptInfo())
	if err != nil {
		return Message{}, err
	}

	return Message{
		Header:     header,
		Ciphertext: ct,
	}, nil
}

// Decrypt decrypts a message.
// Ad must match what was used during encryption. When Config.LocalIdentityKey and
// Config.RemoteIdentityKey are set, they are automatically prepended to
// the MAC input, binding each message to the session's identity pair.
func (s *Session) Decrypt(msg Message, ad []byte) ([]byte, error) {
	s.invariants.Record(s.ns, s.pn, s.rk, s.dhs, s.dhr, s.cks, s.recvChains, s.mkSkipped, s.dhRSet)

	if msgKey, found := s.mkSkipped.Get(msg.Header.RatchetPublicKey, msg.Header.N); found {
		headerBytes := encodeHeader(msg.Header)
		combinedAD := s.buildAD(headerBytes, ad, false)
		pt, err := suite.Decrypt(msgKey, msg.Ciphertext, combinedAD, s.config.effectiveEncryptInfo())
		if err != nil {
			s.rollback()
			return nil, ErrAuthFailure
		}
		return pt, nil
	}

	// Determine whether this is a known chain or a new DH epoch.
	isCurrentChain := s.dhRSet && bytesEqual(s.dhr[:], msg.Header.RatchetPublicKey[:])
	isOldChain := !isCurrentChain && s.recvChains.Has(msg.Header.RatchetPublicKey)
	newEpoch := !isCurrentChain && !isOldChain

	if newEpoch {
		if err := s.performDHRatchetRecv(msg.Header); err != nil {
			s.rollback()
			return nil, err
		}
	}

	// Look up the chain for this message's ratchet key.
	// After performDHRatchetRecv, s.dhr == msg.Header.RatchetPublicKey.
	recvPK := msg.Header.RatchetPublicKey
	chain := s.recvChains.Get(recvPK)
	if chain == nil && !isOldChain {
		// Should only happen if recvChains was empty and no DH ratchet was needed,
		// which means the responder hasn't received the first initiator message yet.
		s.rollback()
		return nil, ErrInvalidTransition
	}
	// For the active chain after newEpoch, recvChains.Get(recvPK) is always non-nil.
	// For isCurrentChain, same — chain is in the buffer.
	// For isOldChain, chain is in the buffer.
	if chain == nil {
		s.rollback()
		return nil, ErrInvalidTransition
	}

	if msg.Header.N > chain.Nr && msg.Header.N-chain.Nr > s.config.EffectiveMaxSkip() {
		s.rollback()
		return nil, ErrMaxSkipExceeded
	}

	if err := s.skipMessageKeys(recvPK, chain, msg.Header.N); err != nil {
		s.rollback()
		return nil, err
	}

	msgKey, err := s.deriveRecvMessageKey(recvPK, chain, msg.Header.N)
	if err != nil {
		s.rollback()
		return nil, err
	}

	headerBytes := encodeHeader(msg.Header)
	combinedAD := s.buildAD(headerBytes, ad, false)

	pt, err := suite.Decrypt(msgKey, msg.Ciphertext, combinedAD, s.config.effectiveEncryptInfo())
	if err != nil {
		s.rollback()
		return nil, ErrAuthFailure
	}

	chain.Nr++
	return pt, nil
}

// RatchetSendKey derives the next EC message key without encrypting.
// Used by TripleRatchetSession to obtain the EC component key before combining
// with the PQ key via KDF_HYBRID.
func (s *Session) RatchetSendKey() (Header, []byte, error) {
	if s.dhRatchetPerformed {
		if err := s.performDHRatchetSend(); err != nil {
			return Header{}, nil, err
		}
	}
	if s.cks == nil {
		return Header{}, nil, ErrSessionNotInitialized
	}

	msgKey, err := deriveMessageKey(s.cks)
	if err != nil {
		return Header{}, nil, err
	}

	newCKs, err := advanceChainKey(s.cks)
	if err != nil {
		return Header{}, nil, err
	}

	zeroBytes(s.cks)
	s.cks = newCKs
	n := s.ns
	s.ns++

	pubKey, err := crypto.PublicKeyFromPrivate(s.dhs)
	if err != nil {
		return Header{}, nil, err
	}
	header := Header{
		RatchetPublicKey: pubKey,
		PN:               s.pn,
		N:                n,
	}

	return header, msgKey, nil
}

// RatchetReceiveKey processes an incoming EC header and returns the 32-byte message key.
// Used by TripleRatchetSession to obtain the EC component key.
func (s *Session) RatchetReceiveKey(header Header) ([]byte, error) {
	// Try skipped keys first.
	if msgKey, found := s.mkSkipped.Get(header.RatchetPublicKey, header.N); found {
		return msgKey, nil
	}

	isCurrentChain := s.dhRSet && bytesEqual(s.dhr[:], header.RatchetPublicKey[:])
	isOldChain := !isCurrentChain && s.recvChains.Has(header.RatchetPublicKey)
	newEpoch := !isCurrentChain && !isOldChain

	if newEpoch {
		if err := s.performDHRatchetRecv(header); err != nil {
			return nil, err
		}
	}

	recvPK := header.RatchetPublicKey
	chain := s.recvChains.Get(recvPK)
	if chain == nil {
		return nil, ErrInvalidTransition
	}

	if header.N > chain.Nr && header.N-chain.Nr > s.config.EffectiveMaxSkip() {
		return nil, ErrMaxSkipExceeded
	}

	if err := s.skipMessageKeys(recvPK, chain, header.N); err != nil {
		return nil, err
	}

	msgKey, err := s.deriveRecvMessageKey(recvPK, chain, header.N)
	if err != nil {
		return nil, err
	}

	chain.Nr++
	return msgKey, nil
}

// Close zeros all key material in the session, rendering it unusable.
// Callers must not use the session after Close returns.
func (s *Session) Close() error {
	zeroBytes(s.rk)
	zeroBytes(s.cks)
	for i := range s.dhs {
		s.dhs[i] = 0
	}
	for i := range s.dhr {
		s.dhr[i] = 0
	}
	s.dhRSet = false
	if s.recvChains != nil {
		s.recvChains.Clear()
	}
	if s.mkSkipped != nil {
		s.mkSkipped.Clear()
	}
	if s.invariants != nil {
		s.invariants.Clear()
	}
	return nil
}

// GetConfig returns the session configuration.
func (s *Session) GetConfig() *Config {
	return s.config
}

// performDHRatchetSend performs the sending-side DH ratchet step.
func (s *Session) performDHRatchetSend() error {
	s.pn = s.ns

	newPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}

	dhOut, err := crypto.SharedSecret(newPriv, s.dhr)
	if err != nil {
		return err
	}

	rk, cks, err := deriveRootAndChain(dhOut, s.rk, s.config.effectiveKDFInfo())
	if err != nil {
		return err
	}

	// Zero superseded key material before replacing (§8.1 secure deletion).
	zeroBytes(s.rk)
	s.rk = rk
	zeroBytes(s.cks)
	s.cks = cks
	for i := range s.dhs {
		s.dhs[i] = 0
	}
	s.dhs = newPriv
	s.ns = 0
	s.dhRatchetPerformed = false

	return nil
}

// performDHRatchetRecv performs the receiving-side DH ratchet step.
func (s *Session) performDHRatchetRecv(header Header) error {
	// Validate incoming ratchet public key before use.
	if !crypto.VerifyPublicKey(header.RatchetPublicKey) {
		return ErrInvalidInput
	}

	prevNr := uint32(0)
	prevDHr := s.dhr

	// Look up the old chain for PN-skip loop.
	var prevCKr []byte
	if s.dhRSet {
		if oldChain := s.recvChains.Get(s.dhr); oldChain != nil {
			prevCKr = append([]byte(nil), oldChain.CK...)
			prevNr = oldChain.Nr
		}
	}

	dhOut, err := crypto.SharedSecret(s.dhs, header.RatchetPublicKey)
	if err != nil {
		zeroBytes(prevCKr)
		return err
	}

	newRK, ckr, err := deriveRootAndChain(dhOut, s.rk, s.config.effectiveKDFInfo())
	if err != nil {
		zeroBytes(prevCKr)
		return err
	}

	// Zero superseded root key before replacing (§8.1 secure deletion).
	zeroBytes(s.rk)
	s.rk = newRK

	// Store skipped keys from the previous chain (messages between prevNr and header.PN).
	if header.PN > prevNr && prevCKr != nil {
		if header.PN-prevNr > s.config.EffectiveMaxSkip() {
			zeroBytes(prevCKr)
			return ErrMaxSkipExceeded
		}
		tmpCKr := append([]byte(nil), prevCKr...)
		for n := prevNr; n < header.PN; n++ {
			msgKey, err := kdf.DeriveMessageKey(tmpCKr)
			if err != nil {
				zeroBytes(tmpCKr)
				zeroBytes(prevCKr)
				return err
			}
			var mk [32]byte
			copy(mk[:], msgKey)
			if err := s.mkSkipped.Store(prevDHr, n, mk); err != nil {
				zeroBytes(tmpCKr)
				zeroBytes(prevCKr)
				return err
			}
			newTmpCKr, _, err := kdf.ChainKDFDerive(tmpCKr)
			if err != nil {
				zeroBytes(tmpCKr)
				zeroBytes(prevCKr)
				return err
			}
			zeroBytes(tmpCKr)
			tmpCKr = newTmpCKr
		}
		zeroBytes(tmpCKr)
	}
	zeroBytes(prevCKr)

	// Push the new receive chain (may evict the oldest if at capacity).
	s.recvChains.Push(header.RatchetPublicKey, ckr)
	zeroBytes(ckr)

	s.dhr = header.RatchetPublicKey
	s.dhRSet = true
	s.dhRatchetPerformed = true

	return nil
}

// skipMessageKeys stores skipped message keys up to the target message number.
// Chain must be non-nil and is the chain for recvPK.
func (s *Session) skipMessageKeys(recvPK [32]byte, chain *state2.ReceiverChain, until uint32) error {
	for chain.Nr < until {
		msgKey, err := kdf.DeriveMessageKey(chain.CK)
		if err != nil {
			return err
		}

		var mk [32]byte
		copy(mk[:], msgKey)
		if err := s.mkSkipped.Store(recvPK, chain.Nr, mk); err != nil {
			return err
		}

		newCKr, _, err := kdf.ChainKDFDerive(chain.CK)
		if err != nil {
			return err
		}
		// Zero superseded chain key before replacing (§8.1 secure deletion).
		zeroBytes(chain.CK)
		chain.CK = newCKr
		chain.Nr++
	}

	return nil
}

// deriveRecvMessageKey derives the message key for message number n.
// Chain must be non-nil. Advances chain.CK past message n.
func (s *Session) deriveRecvMessageKey(recvPK [32]byte, chain *state2.ReceiverChain, n uint32) ([]byte, error) {
	_ = recvPK // retained for clarity; callers already validated the chain lookup

	if chain.CK == nil {
		return nil, ErrInvalidTransition
	}

	ckr := append([]byte(nil), chain.CK...)
	var msgKey []byte

	for i := chain.Nr; i <= n; i++ {
		if i == n {
			var err error
			msgKey, err = kdf.DeriveMessageKey(ckr)
			if err != nil {
				zeroBytes(ckr)
				return nil, err
			}
		} else {
			newCkr, _, err := kdf.ChainKDFDerive(ckr)
			if err != nil {
				zeroBytes(ckr)
				return nil, err
			}
			zeroBytes(ckr)
			ckr = newCkr
		}
	}

	if msgKey == nil {
		zeroBytes(ckr)
		return nil, ErrInvalidTransition
	}

	newCKr, _, err := kdf.ChainKDFDerive(ckr)
	if err != nil {
		zeroBytes(ckr)
		return nil, err
	}
	zeroBytes(ckr)
	// Zero superseded chain key before replacing (§8.1 secure deletion).
	zeroBytes(chain.CK)
	chain.CK = newCKr

	return msgKey, nil
}

// rollback reverts session state to the recorded snapshot.
func (s *Session) rollback() {
	prev := s.invariants.GetPrevState()
	// Zero current (partially-mutated) slice allocations before restoring the snapshot.
	zeroBytes(s.rk)
	zeroBytes(s.cks)
	if s.recvChains != nil {
		s.recvChains.Clear()
	}
	s.ns = prev.Ns
	s.pn = prev.PN
	s.rk = prev.RK
	s.dhs = prev.DHs
	s.dhr = prev.DHr
	s.cks = prev.CKs
	s.recvChains = prev.RecvChains
	s.mkSkipped = prev.MKSKIPPED
	s.dhRSet = prev.DhRSet
}

// hasRemoteRatchetKey reports whether dhr has been set to a received ratchet public key.
func (s *Session) hasRemoteRatchetKey() bool {
	return s.dhRSet
}

// --- Key Derivation Helpers ---

// deriveRootAndChain derives new root key and chain key from DH output.
// Per spec §7: HKDF(salt=currentRK, IKM=dhOutput, info=app-specific) → 64 bytes.
func deriveRootAndChain(dhOutput, currentRK, info []byte) (newRK, newCK []byte, err error) {
	okm := make([]byte, RootKeySize+ChainKeySize)
	reader := hkdf.New(sha256.New, dhOutput, currentRK, info)
	if _, err := io.ReadFull(reader, okm); err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), okm[:RootKeySize]...), append([]byte(nil), okm[RootKeySize:]...), nil
}

func deriveMessageKey(chainKey []byte) ([]byte, error) {
	return kdf.DeriveMessageKey(chainKey)
}

func advanceChainKey(chainKey []byte) ([]byte, error) {
	newCK, _, err := kdf.ChainKDFDerive(chainKey)
	return newCK, err
}

// buildAD constructs the combined authenticated data for Encrypt/Decrypt.
// Format: [identityPrefix] || ad || header
// buildAD constructs the combined authenticated data for Encrypt/Decrypt.
// Format: [identityPrefix] || ad || header
// When sending=true (encrypt), prefix = local_identity || remote_identity.
// When sending=false (decrypt), prefix = remote_identity || local_identity.
// This matches libsignal's sender_identity || receiver_identity MAC ordering.
func (s *Session) buildAD(header, ad []byte, sending bool) []byte {
	prefix := s.config.identityADPrefix(sending)
	out := make([]byte, 0, len(prefix)+len(ad)+len(header))
	out = append(out, prefix...)
	out = append(out, ad...)
	out = append(out, header...)
	return out
}

func encodeHeader(h Header) []byte {
	buf := make([]byte, 32+4+4)
	copy(buf[:32], h.RatchetPublicKey[:])
	putUint32BE(buf[32:], h.PN)
	putUint32BE(buf[32+4:], h.N)
	return buf
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

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
