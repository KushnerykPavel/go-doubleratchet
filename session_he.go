package doubleratchet

import (
	"crypto/subtle"

	crypto2 "github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
	kdf2 "github.com/KushnerykPavel/go-doubleratchet/internal/kdf"
	state2 "github.com/KushnerykPavel/go-doubleratchet/internal/state"
	"github.com/KushnerykPavel/go-doubleratchet/internal/suite"
)

// HESession is a Double Ratchet session with header encryption (spec §4).
// Use InitInitiatorHE/InitResponderHE to create one.
// Do not call Encrypt/Decrypt on HESession — use EncryptHE/DecryptHE instead.
type HESession struct {
	// Session embeds the base Double Ratchet state.
	// Accessing s.Session directly and calling Session.Encrypt/Decrypt on it
	// is unsupported and produces ciphertext incompatible with any standard receiver.
	Session
	// hks is the current sending header key.
	hks HeaderKey
	// hkr is the current receiving header key.
	hkr HeaderKey
	// nhks is the next sending header key.
	nhks HeaderKey
	// nhkr is the next receiving header key.
	nhkr HeaderKey
}

// Encrypt is not valid on HESession. Use EncryptHE instead.
func (s *HESession) Encrypt(_, _ []byte) (Message, error) {
	return Message{}, ErrInvalidTransition
}

// Decrypt is not valid on HESession. Use DecryptHE instead.
func (s *HESession) Decrypt(_ Message, _ []byte) ([]byte, error) {
	return nil, ErrInvalidTransition
}

// Close zeros all key material in the session, rendering it unusable.
func (s *HESession) Close() error {
	if err := s.Session.Close(); err != nil {
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
		return nil, ErrInvalidInput
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	dhsPriv, _, err := crypto2.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	dhOut, err := crypto2.SharedSecret(dhsPriv, bobRatchetPK)
	if err != nil {
		return nil, err
	}

	rk, cks, nhks, err := kdf2.RRKHE(sharedSecret[:32], dhOut, cfg.effectiveHEKDFInfo())
	if err != nil {
		return nil, err
	}

	sk, err := state2.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, err
	}

	return &HESession{
		Session: Session{
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
		},
		hks:  crypto2.HeaderKey{Key: sharedHKA, NonceCounter: 0},
		hkr:  crypto2.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		nhks: crypto2.HeaderKey{Key: nhks, NonceCounter: 0},
		nhkr: crypto2.HeaderKey{Key: sharedNHKB, NonceCounter: 0},
	}, nil
}

// InitResponderHE initializes an HESession for the Responder.
// SharedSecret is the initial shared secret (32+ bytes); only the first 32 are used.
func InitResponderHE(sharedSecret []byte, bobKeyPair crypto2.KeyPair, sharedHKA, sharedNHKB [32]byte, cfg *Config) (*HESession, error) {
	if len(sharedSecret) < 32 {
		return nil, ErrInvalidInput
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !crypto2.VerifyPublicKey(bobKeyPair.PublicKey) {
		return nil, ErrInvalidInput
	}

	rk := append([]byte(nil), sharedSecret[:32]...)

	sk, err := state2.NewStorage(cfg.EffectiveMaxSkip())
	if err != nil {
		return nil, err
	}

	return &HESession{
		Session: Session{
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
		},
		hks:  crypto2.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		hkr:  crypto2.HeaderKey{Key: [32]byte{}, NonceCounter: 0},
		nhks: crypto2.HeaderKey{Key: sharedNHKB, NonceCounter: 0},
		nhkr: crypto2.HeaderKey{Key: sharedHKA, NonceCounter: 0},
	}, nil
}

// SkipMessageKeysHE stores skipped message keys (indexed by hkr.Key) up to pn.
func (s *HESession) SkipMessageKeysHE(pn uint32) error {
	chain := s.recvChains.Get(s.dhr)
	if chain == nil {
		return nil
	}
	if pn > chain.Nr && pn-chain.Nr > s.config.EffectiveMaxSkip() {
		return ErrMaxSkipExceeded
	}

	for chain.Nr < pn {
		msgKey, err := kdf2.DeriveMessageKey(chain.CK)
		if err != nil {
			return err
		}

		var mk [32]byte
		copy(mk[:], msgKey)
		// HE mode indexes skipped keys by header key, not ratchet PK.
		if err := s.mkSkipped.StoreHK(s.hkr.Key, chain.Nr, mk); err != nil {
			return err
		}

		newCKr, _, err := kdf2.ChainKDFDerive(chain.CK)
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

// DecryptHeader decrypts an encrypted header using hkr or nhkr.
// Returns (header, dhRatchetFlag, error).
// DhRatchetFlag is true if decryption succeeded with nhkr (triggers DH ratchet).
func (s *HESession) DecryptHeader(encHeader EncryptedHeader) (Header, bool, error) {
	if pt, ok := crypto2.HDECRYPT(s.hkr.Key, encHeader.Ciphertext); ok {
		header, err := decodeHeader(pt)
		if err != nil {
			return Header{}, false, err
		}
		return header, false, nil
	}

	if pt, ok := crypto2.HDECRYPT(s.nhkr.Key, encHeader.Ciphertext); ok {
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
	if s.dhRatchetPerformed || s.cks == nil {
		if err := s.performDHRatchetSendHE(); err != nil {
			return EncryptedHeader{}, Message{}, err
		}
	}

	if s.cks == nil {
		return EncryptedHeader{}, Message{}, ErrInvalidTransition
	}

	msgKey, err := deriveMessageKey(s.cks)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	newCKs, err := advanceChainKey(s.cks)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	// Advance chain state before encryption (spec §3 ordering).
	zeroBytes(s.cks)
	s.cks = newCKs
	n := s.ns
	s.ns++

	pubKey, err := crypto2.PublicKeyFromPrivate(s.dhs)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}
	header := Header{
		RatchetPublicKey: pubKey,
		PN:               s.pn,
		N:                n,
	}

	headerBytes := encodeHeader(header)

	encHeaderBytes, err := crypto2.HENCRYPT(&s.hks, headerBytes)
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}
	encHeader := EncryptedHeader{Ciphertext: encHeaderBytes}

	combinedAD := s.buildAD(encHeaderBytes, ad, true)
	ct, err := suite.Encrypt(msgKey, plaintext, combinedAD, s.config.effectiveEncryptInfo())
	if err != nil {
		return EncryptedHeader{}, Message{}, err
	}

	return encHeader, Message{Ciphertext: ct}, nil
}

// DecryptHE decrypts a message with an encrypted header.
// Rolls back all state (including header keys) on authentication failure.
func (s *HESession) DecryptHE(encHeader EncryptedHeader, msg Message, ad []byte) ([]byte, error) {
	s.invariants.Record(s.ns, s.pn, s.rk, s.dhs, s.dhr, s.cks, s.recvChains, s.mkSkipped, s.dhRSet)
	hksSnap := s.hks
	hkrSnap := s.hkr
	nhksSnap := s.nhks
	nhkrSnap := s.nhkr

	rollbackAll := func() {
		s.rollback()
		s.hks = hksSnap
		s.hkr = hkrSnap
		s.nhks = nhksSnap
		s.nhkr = nhkrSnap
	}

	if msgKey, found := s.trySkippedMessageKeysHE(encHeader.Ciphertext); found {
		combinedAD := s.buildAD(encHeader.Ciphertext, ad, false)
		pt, err := suite.Decrypt(msgKey, msg.Ciphertext, combinedAD, s.config.effectiveEncryptInfo())
		if err != nil {
			rollbackAll()
			return nil, ErrAuthFailure
		}
		return pt, nil
	}

	header, dhRatchet, err := s.DecryptHeader(encHeader)
	if err != nil {
		rollbackAll()
		return nil, err
	}

	newRemotePK := !s.hasRemoteRatchetKey() || !hkBytesEqual(s.dhr[:], header.RatchetPublicKey[:])

	if newRemotePK || dhRatchet {
		// Strict rejection: if DHr changed but header decrypted with current hkr
		// (not nhkr), the message is anomalous — spec §4 always couples DH ratchet
		// with header key rotation. Only allow this path before DHr has ever been set
		// (Bob's first received message where hkr is still zeroed and nhkr succeeds).
		if newRemotePK && !dhRatchet && s.hasRemoteRatchetKey() {
			rollbackAll()
			return nil, ErrInvalidTransition
		}

		if err := s.performDHRatchetRecvHE(header, dhRatchet); err != nil {
			rollbackAll()
			return nil, err
		}
	}

	// Look up the active receive chain (s.dhr updated by performDHRatchetRecvHE if called).
	chain := s.recvChains.Get(s.dhr)
	if chain == nil {
		rollbackAll()
		return nil, ErrInvalidTransition
	}

	if header.N > chain.Nr && header.N-chain.Nr > s.config.EffectiveMaxSkip() {
		rollbackAll()
		return nil, ErrMaxSkipExceeded
	}

	if err := s.SkipMessageKeysHE(header.N); err != nil {
		rollbackAll()
		return nil, err
	}

	msgKey, err := s.deriveRecvMessageKey(s.dhr, chain, header.N)
	if err != nil {
		rollbackAll()
		return nil, err
	}

	combinedAD2 := s.buildAD(encHeader.Ciphertext, ad, false)
	pt, err := suite.Decrypt(msgKey, msg.Ciphertext, combinedAD2, s.config.effectiveEncryptInfo())
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
	if !crypto2.VerifyPublicKey(header.RatchetPublicKey) {
		return ErrInvalidInput
	}

	// Look up old chain for PN-skip loop.
	var prevCKr []byte
	prevNr := uint32(0)
	prevHKr := s.hkr
	if s.dhRSet {
		if oldChain := s.recvChains.Get(s.dhr); oldChain != nil {
			prevCKr = append([]byte(nil), oldChain.CK...)
			prevNr = oldChain.Nr
		}
	}

	if promoteNextHeaderKey {
		s.hkr = s.nhkr
	}

	dhOut, err := crypto2.SharedSecret(s.dhs, header.RatchetPublicKey)
	if err != nil {
		zeroBytes(prevCKr)
		return err
	}

	newRK, ckr, nhkr, err := kdf2.RRKHE(s.rk, dhOut, s.config.effectiveHEKDFInfo())
	if err != nil {
		zeroBytes(prevCKr)
		return err
	}

	// Zero superseded root key before replacing (§8.1 secure deletion).
	zeroBytes(s.rk)
	s.rk = newRK
	s.nhkr = crypto2.HeaderKey{Key: nhkr}

	// Store skipped keys from the previous chain.
	if header.PN > prevNr && prevCKr != nil {
		if header.PN-prevNr > s.config.EffectiveMaxSkip() {
			zeroBytes(prevCKr)
			zeroBytes(ckr)
			return ErrMaxSkipExceeded
		}
		ckrTmp := append([]byte(nil), prevCKr...)
		for n := prevNr; n < header.PN; n++ {
			msgKey, err := kdf2.DeriveMessageKey(ckrTmp)
			if err != nil {
				zeroBytes(ckrTmp)
				zeroBytes(prevCKr)
				zeroBytes(ckr)
				return err
			}
			var mk [32]byte
			copy(mk[:], msgKey)
			if err := s.mkSkipped.StoreHK(prevHKr.Key, n, mk); err != nil {
				zeroBytes(ckrTmp)
				zeroBytes(prevCKr)
				zeroBytes(ckr)
				return err
			}
			newCkrTmp, _, err := kdf2.ChainKDFDerive(ckrTmp)
			if err != nil {
				zeroBytes(ckrTmp)
				zeroBytes(prevCKr)
				zeroBytes(ckr)
				return err
			}
			zeroBytes(ckrTmp)
			ckrTmp = newCkrTmp
		}
		zeroBytes(ckrTmp)
	}
	zeroBytes(prevCKr)

	// Push new receive chain (may evict oldest if at capacity).
	s.recvChains.Push(header.RatchetPublicKey, ckr)
	zeroBytes(ckr)

	s.dhr = header.RatchetPublicKey
	s.dhRSet = true
	zeroBytes(s.cks)
	s.cks = nil
	s.dhRatchetPerformed = true // consistent with base DR flag convention

	return nil
}

// performDHRatchetSendHE performs the sending-side DH ratchet step for header encryption.
func (s *HESession) performDHRatchetSendHE() error {
	if !s.hasRemoteRatchetKey() {
		return ErrSessionNotInitialized
	}

	s.pn = s.ns
	s.ns = 0
	s.hks = s.nhks

	newPriv, _, err := crypto2.GenerateKeyPair()
	if err != nil {
		return err
	}

	dhOut, err := crypto2.SharedSecret(newPriv, s.dhr)
	if err != nil {
		return err
	}

	newRK, cks, nhks, err := kdf2.RRKHE(s.rk, dhOut, s.config.effectiveHEKDFInfo())
	if err != nil {
		return err
	}

	// Zero superseded key material before replacing (§8.1 secure deletion).
	zeroBytes(s.rk)
	s.rk = newRK
	zeroBytes(s.cks)
	s.cks = cks
	s.nhks = crypto2.HeaderKey{Key: nhks}
	for i := range s.dhs {
		s.dhs[i] = 0
	}
	s.dhs = newPriv
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

func (s *HESession) trySkippedMessageKeysHE(encHeader []byte) ([]byte, bool) {
	return s.mkSkipped.TryAllHeaderKeys(encHeader, crypto2.HDECRYPT)
}
