package doubleratchet

import (
	"github.com/KushnerykPavel/go-doubleratchet/internal/kdf"
	"github.com/KushnerykPavel/go-doubleratchet/internal/state"
	"github.com/KushnerykPavel/go-doubleratchet/internal/suite"
	"github.com/KushnerykPavel/go-doubleratchet/scka"
)

const (
	// SharedSecretSize is the required shared secret size (32 bytes).
	SharedSecretSize = 32
)

// SPQRSession represents a Sparse Post-Quantum Ratchet session.
type SPQRSession struct {
	scka      scka.Provider
	kdfChains map[uint32]*state.KDFChainPair
	mkSkipped map[uint32]map[uint32][]byte
	config    *Config
	rk        []byte
	epoch     uint32
	maxSkip   uint32
	direction state.Direction
}

// InitInitiatorSCKA initializes a SPQR session for the Initiator.
func InitInitiatorSCKA(sk []byte, sckaProvider scka.Provider, cfg *Config) (*SPQRSession, error) {
	if len(sk) < SharedSecretSize {
		return nil, ErrInvalidInput
	}
	if sckaProvider == nil {
		return nil, ErrInvalidInput
	}

	if err := sckaProvider.InitInitiator(sk); err != nil {
		return nil, err
	}

	rk, cks, ckr, err := kdf.SCKAInit(sk)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}

	s := &SPQRSession{
		rk:        rk,
		epoch:     0,
		kdfChains: make(map[uint32]*state.KDFChainPair),
		mkSkipped: make(map[uint32]map[uint32][]byte),
		direction: state.DirectionA2B,
		scka:      sckaProvider,
		maxSkip:   cfg.EffectiveMaxSkip(),
		config:    cfg,
	}

	s.kdfChains[0] = &state.KDFChainPair{
		Send:    &state.KDFChain{CK: cks, N: 0},
		Receive: &state.KDFChain{CK: ckr, N: 0},
	}

	return s, nil
}

// InitResponderSCKA initializes a SPQR session for the Responder.
func InitResponderSCKA(sk []byte, sckaProvider scka.Provider, cfg *Config) (*SPQRSession, error) {
	if len(sk) < SharedSecretSize {
		return nil, ErrInvalidInput
	}
	if sckaProvider == nil {
		return nil, ErrInvalidInput
	}

	if err := sckaProvider.InitResponder(sk); err != nil {
		return nil, err
	}

	// Responder swaps CKs/CKr so Initiator's send chain matches Responder's receive chain.
	rk, ckr, cks, err := kdf.SCKAInit(sk)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}

	s := &SPQRSession{
		rk:        rk,
		epoch:     0,
		kdfChains: make(map[uint32]*state.KDFChainPair),
		mkSkipped: make(map[uint32]map[uint32][]byte),
		direction: state.DirectionB2A,
		scka:      sckaProvider,
		maxSkip:   cfg.EffectiveMaxSkip(),
		config:    cfg,
	}

	s.kdfChains[0] = &state.KDFChainPair{
		Send:    &state.KDFChain{CK: cks, N: 0},
		Receive: &state.KDFChain{CK: ckr, N: 0},
	}

	return s, nil
}

// Close zeros all key material in the SPQR session and closes the SCKA provider.
// Callers must not use the session after Close returns.
func (s *SPQRSession) Close() error {
	zeroBytes(s.rk)
	for epoch, pair := range s.kdfChains {
		if pair.Send != nil {
			zeroBytes(pair.Send.CK)
		}
		if pair.Receive != nil {
			zeroBytes(pair.Receive.CK)
		}
		delete(s.kdfChains, epoch)
	}
	for epoch, keys := range s.mkSkipped {
		for n, mk := range keys {
			zeroBytes(mk)
			delete(keys, n)
		}
		delete(s.mkSkipped, epoch)
	}
	if s.scka != nil {
		return s.scka.Close()
	}
	return nil
}

// SendKey derives the next message key for sending.
// Message numbers are 0-indexed: first message has N=0.
func (s *SPQRSession) SendKey() (msg []byte, sendingEpoch, n uint32, mk []byte, err error) {
	msg, sendingEpoch, outputKey, keyEpoch, err := s.scka.Send()
	if err != nil {
		return nil, 0, 0, nil, err
	}

	if outputKey != nil {
		if s.epoch+1 != keyEpoch {
			return nil, 0, 0, nil, ErrEpochMismatch
		}

		newRK, cks, ckr, err := kdf.SCKARatchetRK(s.rk, outputKey)
		if err != nil {
			return nil, 0, 0, nil, err
		}
		s.rk = newRK

		if s.direction == state.DirectionB2A {
			cks, ckr = ckr, cks
		}

		s.kdfChains[keyEpoch] = &state.KDFChainPair{
			Send:    &state.KDFChain{CK: cks, N: 0},
			Receive: &state.KDFChain{CK: ckr, N: 0},
		}
		s.epoch = keyEpoch
		s.ClearOldEpochs(sendingEpoch)
	}

	// Clear send chain of the epoch before sendingEpoch (forward secrecy).
	if sendingEpoch > 0 {
		if pair, ok := s.kdfChains[sendingEpoch-1]; ok && pair != nil && pair.Send != nil {
			zeroBytes(pair.Send.CK)
			pair.Send = nil
		}
	}

	chain, ok := s.kdfChains[sendingEpoch]
	if !ok || chain == nil || chain.Send == nil {
		return nil, 0, 0, nil, ErrInvalidTransition
	}

	// 0-indexed: current N is the message number, then advance.
	n = chain.Send.N
	chain.Send.CK, mk, err = kdf.SCKARatchetCK(chain.Send.CK, n)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	chain.Send.N = n + 1

	return msg, sendingEpoch, n, mk, nil
}

// Encrypt encrypts a plaintext message using the SPQR.
func (s *SPQRSession) Encrypt(plaintext, ad []byte) (header *SCKAHeader, ciphertext []byte, err error) {
	msg, _, n, mk, err := s.SendKey()
	if err != nil {
		return nil, nil, err
	}

	header = &SCKAHeader{Msg: msg, N: n}

	ciphertext, err = encryptMessageSPQR(s.config, mk, plaintext, header, ad, s.config.effectiveEncryptInfo())
	if err != nil {
		return nil, nil, err
	}

	return header, ciphertext, nil
}

// ReceiveKey processes a header and returns the message key.
// Message numbers are 0-indexed: first message has N=0.
func (s *SPQRSession) ReceiveKey(header *SCKAHeader) (receivingEpoch uint32, mk []byte, err error) {
	receivingEpoch, outputKey, keyEpoch, err := s.scka.Receive(header.Msg)
	if err != nil {
		return 0, nil, err
	}

	if outputKey != nil {
		if s.epoch+1 != keyEpoch {
			return 0, nil, ErrEpochMismatch
		}

		newRK, cks, ckr, err := kdf.SCKARatchetRK(s.rk, outputKey)
		if err != nil {
			return 0, nil, err
		}
		s.rk = newRK

		if s.direction == state.DirectionB2A {
			cks, ckr = ckr, cks
		}

		s.kdfChains[keyEpoch] = &state.KDFChainPair{
			Send:    &state.KDFChain{CK: cks, N: 0},
			Receive: &state.KDFChain{CK: ckr, N: 0},
		}
		s.epoch = keyEpoch
		s.ClearOldEpochs(receivingEpoch)
	}

	mk = s.TrySkippedMessageKeys(receivingEpoch, header.N)
	if mk != nil {
		return receivingEpoch, mk, nil
	}

	if err := s.SkipMessageKeys(receivingEpoch, header.N); err != nil {
		return 0, nil, err
	}

	chain, ok := s.kdfChains[receivingEpoch]
	if !ok || chain == nil || chain.Receive == nil {
		return 0, nil, ErrInvalidTransition
	}
	// 0-indexed: next expected message number is current N counter.
	nextN := chain.Receive.N
	if nextN != header.N {
		return 0, nil, ErrSkippedKeyNotFound
	}

	chain.Receive.CK, mk, err = kdf.SCKARatchetCK(chain.Receive.CK, nextN)
	if err != nil {
		return 0, nil, err
	}
	chain.Receive.N = nextN + 1

	return receivingEpoch, mk, nil
}

// Decrypt decrypts a ciphertext message.
// KDF chain state is rolled back if authentication fails.
// Note: SCKA state cannot be rolled back if epoch advancement already occurred.
func (s *SPQRSession) Decrypt(header *SCKAHeader, ciphertext, ad []byte) ([]byte, error) {
	// Snapshot all mutable state before processing.
	rkSnap := append([]byte(nil), s.rk...)
	epochSnap := s.epoch
	chainsSnap := s.cloneChains()
	skippedSnap := s.cloneSkipped()
	sckaSnap := s.scka.Snapshot()

	_, mk, err := s.ReceiveKey(header)
	if err != nil {
		return nil, err
	}

	pt, err := decryptMessageSPQR(s.config, mk, ciphertext, header, ad, s.config.effectiveEncryptInfo())
	if err != nil {
		// Auth failed — zero intermediate key material before restoring snapshot (§8.1).
		zeroBytes(s.rk)
		for _, pair := range s.kdfChains {
			if pair != nil {
				if pair.Send != nil {
					zeroBytes(pair.Send.CK)
				}
				if pair.Receive != nil {
					zeroBytes(pair.Receive.CK)
				}
			}
		}
		s.rk = rkSnap
		s.epoch = epochSnap
		s.kdfChains = chainsSnap
		s.mkSkipped = skippedSnap
		s.scka.Restore(sckaSnap)
		return nil, ErrAuthFailure
	}

	return pt, nil
}

// TrySkippedMessageKeys retrieves and deletes a skipped message key.
func (s *SPQRSession) TrySkippedMessageKeys(epoch, n uint32) []byte {
	epochKeys, ok := s.mkSkipped[epoch]
	if !ok {
		return nil
	}

	mk, ok := epochKeys[n]
	if !ok {
		return nil
	}

	delete(epochKeys, n)
	if len(epochKeys) == 0 {
		delete(s.mkSkipped, epoch)
	}

	mkCopy := make([]byte, len(mk))
	copy(mkCopy, mk)
	for i := range mk {
		mk[i] = 0
	}

	return mkCopy
}

// SkipMessageKeys stores skipped message keys from the current position up to (but not including) until.
func (s *SPQRSession) SkipMessageKeys(epoch, until uint32) error {
	chain, ok := s.kdfChains[epoch]
	if !ok || chain == nil || chain.Receive == nil {
		return nil
	}

	// Overflow-safe MaxSkip check.
	if until > chain.Receive.N && until-chain.Receive.N > s.maxSkip {
		return ErrMaxSkipExceeded
	}

	for chain.Receive.N < until {
		n := chain.Receive.N
		nextCK, mk, err := kdf.SCKARatchetCK(chain.Receive.CK, n)
		if err != nil {
			return err
		}
		chain.Receive.CK = nextCK
		chain.Receive.N = n + 1

		if s.mkSkipped[epoch] == nil {
			s.mkSkipped[epoch] = make(map[uint32][]byte)
		}
		mkCopy := make([]byte, len(mk))
		copy(mkCopy, mk)
		s.mkSkipped[epoch][n] = mkCopy
	}

	return nil
}

// ClearOldEpochs removes epoch state older than sendingEpoch-1.
func (s *SPQRSession) ClearOldEpochs(sendingEpoch uint32) {
	if sendingEpoch <= 1 {
		return
	}

	keepFrom := sendingEpoch - 1
	for epoch := range s.kdfChains {
		if epoch < keepFrom {
			// Zero key material before dropping the epoch (§8.1 secure deletion).
			pair := s.kdfChains[epoch]
			if pair != nil {
				if pair.Send != nil {
					zeroBytes(pair.Send.CK)
				}
				if pair.Receive != nil {
					zeroBytes(pair.Receive.CK)
				}
			}
			delete(s.kdfChains, epoch)
		}
	}
	for epoch := range s.mkSkipped {
		if epoch < keepFrom {
			for _, mk := range s.mkSkipped[epoch] {
				zeroBytes(mk)
			}
			delete(s.mkSkipped, epoch)
		}
	}
}

// cloneChains returns a deep copy of KDFChains.
func (s *SPQRSession) cloneChains() map[uint32]*state.KDFChainPair {
	clone := make(map[uint32]*state.KDFChainPair, len(s.kdfChains))
	for epoch, pair := range s.kdfChains {
		p := &state.KDFChainPair{}
		if pair.Send != nil {
			ck := append([]byte(nil), pair.Send.CK...)
			p.Send = &state.KDFChain{CK: ck, N: pair.Send.N}
		}
		if pair.Receive != nil {
			ck := append([]byte(nil), pair.Receive.CK...)
			p.Receive = &state.KDFChain{CK: ck, N: pair.Receive.N}
		}
		clone[epoch] = p
	}
	return clone
}

// cloneSkipped returns a deep copy of MkSkipped.
func (s *SPQRSession) cloneSkipped() map[uint32]map[uint32][]byte {
	clone := make(map[uint32]map[uint32][]byte, len(s.mkSkipped))
	for epoch, keys := range s.mkSkipped {
		kclone := make(map[uint32][]byte, len(keys))
		for n, mk := range keys {
			kclone[n] = append([]byte(nil), mk...)
		}
		clone[epoch] = kclone
	}
	return clone
}

func encryptMessageSPQR(cfg *Config, key, plaintext []byte, header *SCKAHeader, ad, info []byte) ([]byte, error) {
	headerBytes, err := encodeSCKAHeader(header)
	if err != nil {
		return nil, err
	}
	prefix := cfg.identityADPrefix(true)
	combinedAD := make([]byte, 0, len(prefix)+len(ad)+len(headerBytes))
	combinedAD = append(combinedAD, prefix...)
	combinedAD = append(combinedAD, ad...)
	combinedAD = append(combinedAD, headerBytes...)
	return suite.Encrypt(key, plaintext, combinedAD, info)
}

func decryptMessageSPQR(cfg *Config, key, ciphertext []byte, header *SCKAHeader, ad, info []byte) ([]byte, error) {
	headerBytes, err := encodeSCKAHeader(header)
	if err != nil {
		return nil, err
	}
	prefix := cfg.identityADPrefix(false)
	combinedAD := make([]byte, 0, len(prefix)+len(ad)+len(headerBytes))
	combinedAD = append(combinedAD, prefix...)
	combinedAD = append(combinedAD, ad...)
	combinedAD = append(combinedAD, headerBytes...)
	return suite.Decrypt(key, ciphertext, combinedAD, info)
}

func encodeSCKAHeader(h *SCKAHeader) ([]byte, error) {
	if h == nil {
		return nil, ErrInvalidInput
	}
	msgLen := len(h.Msg)
	size := 4 + msgLen + 4
	buf := make([]byte, size)
	buf[0] = byte(msgLen >> 24) //nolint:gosec // msgLen bounded by slice allocation
	buf[1] = byte(msgLen >> 16) //nolint:gosec // msgLen bounded by slice allocation
	buf[2] = byte(msgLen >> 8)  //nolint:gosec // msgLen bounded by slice allocation
	buf[3] = byte(msgLen)       //nolint:gosec // msgLen bounded by slice allocation
	copy(buf[4:], h.Msg)
	buf[size-4] = byte(h.N >> 24)
	buf[size-3] = byte(h.N >> 16) //nolint:gosec // uint32 shift always fits in byte
	buf[size-2] = byte(h.N >> 8)  //nolint:gosec // uint32 shift always fits in byte
	buf[size-1] = byte(h.N)       //nolint:gosec // uint32 low byte always fits in byte
	return buf, nil
}
