package doubleratchet

import (
	"encoding/binary"
	"fmt"

	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
	"github.com/KushnerykPavel/go-doubleratchet/internal/kdf"
	"github.com/KushnerykPavel/go-doubleratchet/internal/state"
	"github.com/KushnerykPavel/go-doubleratchet/internal/suite"
)

// HESession is a Double Ratchet session with header encryption (spec §4).
// Use InitInitiatorHE/InitResponderHE to create one.
type HESession struct {
	// dr is the base Double Ratchet state (composition, not embedding).
	dr *Session
	// hks is the current sending header key.
	hks HeaderKey
	// hkr is the current receiving header key.
	hkr HeaderKey
	// nhks is the next sending header key.
	nhks HeaderKey
	// nhkr is the next receiving header key.
	nhkr HeaderKey
}

// Config returns the session configuration.
func (s *HESession) Config() *Config {
	return s.dr.config
}

// Close zeros all key material in the session, rendering it unusable.
func (s *HESession) Close() error {
	if err := s.dr.Close(); err != nil {
		return err
	}
	for i := range s.hks.Key {
		s.hks.Key[i] = 0
	}
	for i := range s.hkr.Key {
		s.hkr.Key[i] = 0
	}
	for i := range s.nhks.Key {
		s.nhks.Key[i] = 0
	}
	for i := range s.nhkr.Key {
		s.nhkr.Key[i] = 0
	}
	return nil
}

// InitInitiatorHE initializes an HESession for the Initiator.
// SharedSecret is the initial shared secret (32+ bytes); only the first 32 are used.
func InitInitiatorHE(sharedSecret []byte, bobRatchetPK, sharedHKA, sharedNHKB [32]byte, cfg *Config) (*HESession, error) {
	if len(sharedSecret) < 32 {
		return nil, fmt.Errorf("doubleratchet: init initiator HE: %w", ErrSharedSecretTooShort)
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator HE: %w", err)
	}

	dhsPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator HE: %w", err)
	}

	dhOut, err := crypto.SharedSecret(dhsPriv, bobRatchetPK)
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator HE: %w", err)
	}

	rk, cks, nhks, err := kdf.DeriveRootKeyHE(sharedSecret[:32], dhOut, cfg.effectiveHEKDFInfo())
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator HE: %w", err)
	}

	sk, err := state.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator HE: %w", err)
	}

	return &HESession{
		dr: &Session{
			rk:                 rk,
			cks:                cks,
			recvChains:         state.NewReceiverChains(),
			dhs:                dhsPriv,
			dhr:                bobRatchetPK,
			ns:                 0,
			pn:                 0,
			mkSkipped:          sk,
			config:             cfg,
			invariants:         state.NewInvariants(),
			dhRatchetPerformed: false,
			dhRSet:             true, // Initiator knows Responder's key from initialization
		},
		hks:  crypto.HeaderKey{Key: sharedHKA, NonceCounter: 0},
		hkr:  crypto.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		nhks: crypto.HeaderKey{Key: nhks, NonceCounter: 0},
		nhkr: crypto.HeaderKey{Key: sharedNHKB, NonceCounter: 0},
	}, nil
}

// InitResponderHE initializes an HESession for the Responder.
// SharedSecret is the initial shared secret (32+ bytes); only the first 32 are used.
func InitResponderHE(sharedSecret []byte, bobKeyPair crypto.KeyPair, sharedHKA, sharedNHKB [32]byte, cfg *Config) (*HESession, error) {
	if len(sharedSecret) < 32 {
		return nil, fmt.Errorf("doubleratchet: init responder HE: %w", ErrSharedSecretTooShort)
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("doubleratchet: init responder HE: %w", err)
	}
	if !crypto.VerifyPublicKey(bobKeyPair.PublicKey) {
		return nil, fmt.Errorf("doubleratchet: init responder HE: %w", ErrInvalidInput)
	}

	rk := append([]byte(nil), sharedSecret[:32]...)

	sk, err := state.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init responder HE: %w", err)
	}

	return &HESession{
		dr: &Session{
			rk:         rk,
			cks:        nil,
			recvChains: state.NewReceiverChains(),
			dhs:        bobKeyPair.PrivateKey,
			dhr:        [32]byte{},
			ns:         0,
			pn:         0,
			mkSkipped:  sk,
			config:     cfg,
			invariants: state.NewInvariants(),
			dhRSet:     false, // Responder has not yet received Initiator's first message
		},
		hks:  crypto.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		hkr:  crypto.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		nhks: crypto.HeaderKey{Key: sharedNHKB, NonceCounter: 0},
		nhkr: crypto.HeaderKey{Key: sharedHKA, NonceCounter: 0},
	}, nil
}

// skipMessageKeysHE stores skipped message keys (indexed by hkr.Key) up to pn.
func (s *HESession) skipMessageKeysHE(pn uint32) error {
	chain := s.dr.recvChains.Get(s.dr.dhr)
	if chain == nil {
		return nil
	}
	if pn > chain.Nr && pn-chain.Nr > s.dr.config.EffectiveMaxSkip() {
		return ErrMaxSkipExceeded
	}

	for chain.Nr < pn {
		msgKey, err := kdf.DeriveMessageKey(chain.CK)
		if err != nil {
			return err
		}

		var mk [32]byte
		copy(mk[:], msgKey)
		// HE mode indexes skipped keys by header key, not ratchet PK.
		if err := s.dr.mkSkipped.Store(s.hkr.Key, chain.Nr, mk); err != nil {
			return err
		}

		newCKr, _, err := kdf.DeriveNextChainKey(chain.CK)
		if err != nil {
			return err
		}
		// Zero superseded chain key before replacing (§8.1 secure deletion).
		crypto.ZeroBytes(chain.CK)
		chain.CK = newCKr
		chain.Nr++
	}
	return nil
}

// decryptHeader decrypts an encrypted header using hkr or nhkr.
// Returns (header, dhRatchetFlag, error).
// DhRatchetFlag is true if decryption succeeded with nhkr (triggers DH ratchet).
func (s *HESession) decryptHeader(encHeader EncryptedHeader) (Header, bool, error) {
	if pt, ok := crypto.DecryptHeader(s.hkr.Key, encHeader.Ciphertext); ok {
		header, err := decodeHeader(pt)
		if err != nil {
			return Header{}, false, err
		}
		return header, false, nil
	}

	if pt, ok := crypto.DecryptHeader(s.nhkr.Key, encHeader.Ciphertext); ok {
		header, err := decodeHeader(pt)
		if err != nil {
			return Header{}, false, err
		}
		return header, true, nil
	}

	return Header{}, false, ErrAuthFailure
}

// EncryptHE encrypts a message with an encrypted header.
func (s *HESession) EncryptHE(plaintext, ad []byte) (EncryptedHeader, Message, error) {
	if s.dr.dhRatchetPerformed || s.dr.cks == nil {
		if err := s.performDHRatchetSendHE(); err != nil {
			return EncryptedHeader{}, Message{}, err
		}
	}

	if s.dr.cks == nil {
		return EncryptedHeader{}, Message{}, ErrInvalidTransition
	}

	msgKey, err := deriveMessageKey(s.dr.cks)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	newCKs, err := advanceChainKey(s.dr.cks)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	// Advance chain state before encryption (spec §3 ordering).
	crypto.ZeroBytes(s.dr.cks)
	s.dr.cks = newCKs
	n := s.dr.ns
	s.dr.ns++

	pubKey, err := crypto.PublicKeyFromPrivate(s.dr.dhs)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}
	header := Header{
		RatchetPublicKey: pubKey,
		PN:               s.dr.pn,
		N:                n,
	}

	headerBytes := encodeHeader(header)

	encHeaderBytes, err := crypto.EncryptHeader(&s.hks, headerBytes)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}
	encHeader := EncryptedHeader{Ciphertext: encHeaderBytes}

	combinedAD := s.dr.buildAD(encHeaderBytes, ad, true)
	ct, err := suite.Encrypt(msgKey, plaintext, combinedAD, s.dr.config.effectiveEncryptInfo())
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	return encHeader, Message{Ciphertext: ct}, nil
}

// DecryptHE decrypts a message with an encrypted header.
// Rolls back all state (including header keys) on authentication failure.
func (s *HESession) DecryptHE(encHeader EncryptedHeader, msg Message, ad []byte) ([]byte, error) {
	s.dr.invariants.Record(s.dr.ns, s.dr.pn, s.dr.rk, s.dr.dhs, s.dr.dhr, s.dr.cks, s.dr.recvChains, s.dr.mkSkipped, s.dr.dhRSet, s.dr.dhRatchetPerformed)
	hksSnap := s.hks
	hkrSnap := s.hkr
	nhksSnap := s.nhks
	nhkrSnap := s.nhkr

	rollbackAll := func() {
		s.dr.rollback()
		s.hks = hksSnap
		s.hkr = hkrSnap
		s.nhks = nhksSnap
		s.nhkr = nhkrSnap
	}

	if msgKey, found := s.trySkippedMessageKeysHE(encHeader.Ciphertext); found {
		combinedAD := s.dr.buildAD(encHeader.Ciphertext, ad, false)
		pt, err := suite.Decrypt(msgKey, msg.Ciphertext, combinedAD, s.dr.config.effectiveEncryptInfo())
		if err != nil {
			rollbackAll()
			return nil, ErrAuthFailure
		}
		return pt, nil
	}

	header, dhRatchet, err := s.decryptHeader(encHeader)
	if err != nil {
		rollbackAll()
		return nil, err
	}

	newRemotePK := !s.dr.hasRemoteRatchetKey() || !bytesEqual(s.dr.dhr[:], header.RatchetPublicKey[:])

	if newRemotePK || dhRatchet {
		// Strict rejection: if DHr changed but header decrypted with current hkr
		// (not nhkr), the message is anomalous — spec §4 always couples DH ratchet
		// with header key rotation. Only allow this path before DHr has ever been set
		// (Bob's first received message where hkr is still zeroed and nhkr succeeds).
		if newRemotePK && !dhRatchet && s.dr.hasRemoteRatchetKey() {
			rollbackAll()
			return nil, ErrInvalidTransition
		}

		if err := s.performDHRatchetRecvHE(header, dhRatchet); err != nil {
			rollbackAll()
			return nil, err
		}
	}

	// Look up the active receive chain (s.dr.dhr updated by performDHRatchetRecvHE if called).
	chain := s.dr.recvChains.Get(s.dr.dhr)
	if chain == nil {
		rollbackAll()
		return nil, ErrInvalidTransition
	}

	if header.N > chain.Nr && header.N-chain.Nr > s.dr.config.EffectiveMaxSkip() {
		rollbackAll()
		return nil, ErrMaxSkipExceeded
	}

	if err := s.skipMessageKeysHE(header.N); err != nil {
		rollbackAll()
		return nil, err
	}

	msgKey, err := s.dr.deriveRecvMessageKey(s.dr.dhr, chain, header.N)
	if err != nil {
		rollbackAll()
		return nil, err
	}

	combinedAD2 := s.dr.buildAD(encHeader.Ciphertext, ad, false)
	pt, err := suite.Decrypt(msgKey, msg.Ciphertext, combinedAD2, s.dr.config.effectiveEncryptInfo())
	if err != nil {
		rollbackAll()
		return nil, ErrAuthFailure
	}

	chain.Nr++
	return pt, nil
}

// performDHRatchetRecvHE performs the receive-side DH ratchet step for header encryption.
func (s *HESession) performDHRatchetRecvHE(header Header, promoteNextHeaderKey bool) error {
	// Validate incoming ratchet public key before use.
	if !crypto.VerifyPublicKey(header.RatchetPublicKey) {
		return ErrInvalidInput
	}

	// Look up old chain for PN-skip loop.
	var prevCKr []byte
	prevNr := uint32(0)
	prevHKr := s.hkr
	if s.dr.dhRSet {
		if oldChain := s.dr.recvChains.Get(s.dr.dhr); oldChain != nil {
			prevCKr = append([]byte(nil), oldChain.CK...)
			prevNr = oldChain.Nr
		}
	}

	if promoteNextHeaderKey {
		s.hkr = s.nhkr
	}

	dhOut, err := crypto.SharedSecret(s.dr.dhs, header.RatchetPublicKey)
	if err != nil {
		crypto.ZeroBytes(prevCKr)
		return err
	}

	newRK, ckr, nhkr, err := kdf.DeriveRootKeyHE(s.dr.rk, dhOut, s.dr.config.effectiveHEKDFInfo())
	if err != nil {
		crypto.ZeroBytes(prevCKr)
		return err
	}

	// Zero superseded root key before replacing (§8.1 secure deletion).
	crypto.ZeroBytes(s.dr.rk)
	s.dr.rk = newRK
	s.nhkr = crypto.HeaderKey{Key: nhkr}

	// Store skipped keys from the previous chain.
	if header.PN > prevNr && prevCKr != nil {
		if header.PN-prevNr > s.dr.config.EffectiveMaxSkip() {
			crypto.ZeroBytes(prevCKr)
			crypto.ZeroBytes(ckr)
			return ErrMaxSkipExceeded
		}
		ckrTmp := append([]byte(nil), prevCKr...)
		for n := prevNr; n < header.PN; n++ {
			msgKey, err := kdf.DeriveMessageKey(ckrTmp)
			if err != nil {
				crypto.ZeroBytes(ckrTmp)
				crypto.ZeroBytes(prevCKr)
				crypto.ZeroBytes(ckr)
				return err
			}
			var mk [32]byte
			copy(mk[:], msgKey)
			if err := s.dr.mkSkipped.Store(prevHKr.Key, n, mk); err != nil {
				crypto.ZeroBytes(ckrTmp)
				crypto.ZeroBytes(prevCKr)
				crypto.ZeroBytes(ckr)
				return err
			}
			newCkrTmp, _, err := kdf.DeriveNextChainKey(ckrTmp)
			if err != nil {
				crypto.ZeroBytes(ckrTmp)
				crypto.ZeroBytes(prevCKr)
				crypto.ZeroBytes(ckr)
				return err
			}
			crypto.ZeroBytes(ckrTmp)
			ckrTmp = newCkrTmp
		}
		crypto.ZeroBytes(ckrTmp)
	}
	crypto.ZeroBytes(prevCKr)

	// Push new receive chain (may evict oldest if at capacity).
	s.dr.recvChains.Push(header.RatchetPublicKey, ckr)
	crypto.ZeroBytes(ckr)

	s.dr.dhr = header.RatchetPublicKey
	s.dr.dhRSet = true
	crypto.ZeroBytes(s.dr.cks)
	s.dr.cks = nil
	s.dr.dhRatchetPerformed = true // consistent with base DR flag convention

	return nil
}

// performDHRatchetSendHE performs the sending-side DH ratchet step for header encryption.
func (s *HESession) performDHRatchetSendHE() error {
	if !s.dr.hasRemoteRatchetKey() {
		return ErrSessionNotInitialized
	}

	s.dr.pn = s.dr.ns
	s.dr.ns = 0
	s.hks = s.nhks

	newPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}

	dhOut, err := crypto.SharedSecret(newPriv, s.dr.dhr)
	if err != nil {
		return err
	}

	newRK, cks, nhks, err := kdf.DeriveRootKeyHE(s.dr.rk, dhOut, s.dr.config.effectiveHEKDFInfo())
	if err != nil {
		return err
	}

	// Zero superseded key material before replacing (§8.1 secure deletion).
	crypto.ZeroBytes(s.dr.rk)
	s.dr.rk = newRK
	crypto.ZeroBytes(s.dr.cks)
	s.dr.cks = cks
	s.nhks = crypto.HeaderKey{Key: nhks}
	for i := range s.dr.dhs {
		s.dr.dhs[i] = 0
	}
	s.dr.dhs = newPriv
	s.dr.dhRatchetPerformed = false

	return nil
}

// decodeHeader decodes bytes into a Header.
func decodeHeader(data []byte) (Header, error) {
	if len(data) < 32+4+4 {
		return Header{}, ErrInvalidInput
	}
	var h Header
	copy(h.RatchetPublicKey[:], data[:32])
	h.PN = binary.BigEndian.Uint32(data[32:])
	h.N = binary.BigEndian.Uint32(data[36:])
	return h, nil
}

func (s *HESession) trySkippedMessageKeysHE(encHeader []byte) ([]byte, bool) {
	return s.dr.mkSkipped.TryAllHeaderKeys(encHeader, crypto.DecryptHeader)
}
