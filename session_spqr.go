// Package doubleratchet provides SPQR session implementation.
package doubleratchet

import (
	"crypto/hmac"
	"crypto/sha256"

	"doubleratchet/internal/kdf"
	"doubleratchet/internal/scka"
	"doubleratchet/internal/state"
	"doubleratchet/internal/suite"
)

const (
	// SharedSecretSize is the required shared secret size (32 bytes).
	SharedSecretSize = 32
)

// SPQRSession represents a Sparse Post-Quantum Ratchet session.
type SPQRSession struct {
	// RK is the current root key.
	RK []byte
	// Epoch is the latest epoch with SCKA keys incorporated.
	Epoch uint32
	// KDFChains holds KDF chains indexed by epoch.
	KDFChains map[uint32]*state.KDFChainPair
	// MkSkipped stores skipped message keys by epoch and message number.
	MkSkipped map[uint32]map[uint32][]byte
	// Direction indicates the message flow direction.
	Direction state.Direction
	// SCKA is the SCKA provider.
	SCKA scka.SCKAProvider
	// MaxSkip is the maximum skipped keys allowed per epoch.
	MaxSkip uint32
}

// InitAliceSCKA initializes a SPQR session for Alice.
func InitAliceSCKA(SK []byte, scka scka.SCKAProvider, cfg *Config) (*SPQRSession, error) {
	if len(SK) < SharedSecretSize {
		return nil, ErrInvalidInput
	}
	if scka == nil {
		return nil, ErrInvalidInput
	}

	if err := scka.InitAlice(SK); err != nil {
		return nil, err
	}

	rk, cks, ckr, err := kdf.KDF_SCKA_INIT(SK)
	if err != nil {
		return nil, err
	}

	var maxSkip uint32 = DefaultMaxSkip
	if cfg != nil {
		maxSkip = cfg.EffectiveMaxSkip()
	}

	s := &SPQRSession{
		RK:        rk,
		Epoch:     0,
		KDFChains: make(map[uint32]*state.KDFChainPair),
		MkSkipped: make(map[uint32]map[uint32][]byte),
		Direction: state.DirectionA2B,
		SCKA:      scka,
		MaxSkip:   maxSkip,
	}

	// Initialize epoch 0 chains.
	s.KDFChains[0] = &state.KDFChainPair{
		Send: &state.KDFChain{
			CK: cks,
			N:  0,
		},
		Receive: &state.KDFChain{
			CK: ckr,
			N:  0,
		},
	}

	return s, nil
}

// InitBobSCKA initializes a SPQR session for Bob.
func InitBobSCKA(SK []byte, scka scka.SCKAProvider, cfg *Config) (*SPQRSession, error) {
	if len(SK) < SharedSecretSize {
		return nil, ErrInvalidInput
	}
	if scka == nil {
		return nil, ErrInvalidInput
	}

	if err := scka.InitBob(SK); err != nil {
		return nil, err
	}

	// Bob derives with swapped CKs/CKr.
	rk, ckr, cks, err := kdf.KDF_SCKA_INIT(SK)
	if err != nil {
		return nil, err
	}

	var maxSkip uint32 = DefaultMaxSkip
	if cfg != nil {
		maxSkip = cfg.EffectiveMaxSkip()
	}

	s := &SPQRSession{
		RK:        rk,
		Epoch:     0,
		KDFChains: make(map[uint32]*state.KDFChainPair),
		MkSkipped: make(map[uint32]map[uint32][]byte),
		Direction: state.DirectionB2A,
		SCKA:      scka,
		MaxSkip:   maxSkip,
	}

	// Initialize epoch 0 chains.
	s.KDFChains[0] = &state.KDFChainPair{
		Send: &state.KDFChain{
			CK: cks,
			N:  0,
		},
		Receive: &state.KDFChain{
			CK: ckr,
			N:  0,
		},
	}

	return s, nil
}

// SendKey derives the next message key for sending.
func (s *SPQRSession) SendKey() (msg []byte, sendingEpoch uint32, n uint32, mk []byte, err error) {
	msg, sendingEpoch, outputKey, keyEpoch, err := s.SCKA.Send()
	if err != nil {
		return nil, 0, 0, nil, err
	}

	// Handle epoch advancement.
	if outputKey != nil {
		if s.Epoch+1 != keyEpoch {
			return nil, 0, 0, nil, ErrEpochMismatch
		}

		newRK, cks, ckr, err := kdf.KDF_SCKA_RK(s.RK, outputKey)
		if err != nil {
			return nil, 0, 0, nil, err
		}
		s.RK = newRK

		// Swap CKs/CKr for B2A direction.
		if s.Direction == state.DirectionB2A {
			cks, ckr = ckr, cks
		}

		s.KDFChains[keyEpoch] = &state.KDFChainPair{
			Send: &state.KDFChain{
				CK: cks,
				N:  0,
			},
			Receive: &state.KDFChain{
				CK: ckr,
				N:  0,
			},
		}
		s.Epoch = keyEpoch

		// Clear old epochs.
		s.ClearOldEpochs(sendingEpoch)
	}

	// Clear previous sending chain.
	if sendingEpoch > 0 {
		if pair, ok := s.KDFChains[sendingEpoch-1]; ok && pair != nil {
			pair.Send = nil
		}
	}

	// Advance current sending chain.
	chain, ok := s.KDFChains[sendingEpoch]
	if !ok || chain == nil || chain.Send == nil {
		return nil, 0, 0, nil, ErrInvalidTransition
	}

	n = chain.Send.N
	chain.Send.N++

	chain.Send.CK, mk, err = kdf.KDF_SCKA_CK(chain.Send.CK, n)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	return msg, sendingEpoch, n, mk, nil
}

// Encrypt encrypts a plaintext message using the SPQR.
func (s *SPQRSession) Encrypt(plaintext, AD []byte) (header *SCKAHeader, ciphertext []byte, err error) {
	msg, _, n, mk, err := s.SendKey()
	if err != nil {
		return nil, nil, err
	}

	header = &SCKAHeader{
		Msg: msg,
		N:   n,
	}

	ciphertext, err = encryptMessageSPQR(mk, plaintext, header, AD)
	if err != nil {
		return nil, nil, err
	}

	return header, ciphertext, nil
}

// ReceiveKey processes a header and returns the message key.
func (s *SPQRSession) ReceiveKey(header *SCKAHeader) (receivingEpoch uint32, mk []byte, err error) {
	receivingEpoch, outputKey, keyEpoch, err := s.SCKA.Receive(header.Msg)
	if err != nil {
		return 0, nil, err
	}

	// Handle epoch advancement.
	if outputKey != nil {
		if s.Epoch+1 != keyEpoch {
			return 0, nil, ErrEpochMismatch
		}

		newRK, cks, ckr, err := kdf.KDF_SCKA_RK(s.RK, outputKey)
		if err != nil {
			return 0, nil, err
		}
		s.RK = newRK

		// Swap CKs/CKr for B2A direction.
		if s.Direction == state.DirectionB2A {
			cks, ckr = ckr, cks
		}

		s.KDFChains[keyEpoch] = &state.KDFChainPair{
			Send: &state.KDFChain{
				CK: cks,
				N:  0,
			},
			Receive: &state.KDFChain{
				CK: ckr,
				N:  0,
			},
		}
		s.Epoch = keyEpoch

		// Clear old epochs on receive-side advancement as well.
		s.ClearOldEpochs(receivingEpoch)
	}

	// Try skipped message keys first.
	mk = s.TrySkippedMessageKeys(receivingEpoch, header.N)
	if mk != nil {
		return receivingEpoch, mk, nil
	}

	// Skip message keys.
	if err := s.SkipMessageKeys(receivingEpoch, header.N); err != nil {
		return 0, nil, err
	}

	// Advance receiving chain.
	chain, ok := s.KDFChains[receivingEpoch]
	if !ok || chain == nil || chain.Receive == nil {
		return 0, nil, ErrInvalidTransition
	}
	if chain.Receive.N != header.N {
		return 0, nil, ErrSkippedKeyNotFound
	}

	chain.Receive.CK, mk, err = kdf.KDF_SCKA_CK(chain.Receive.CK, chain.Receive.N)
	if err != nil {
		return 0, nil, err
	}
	chain.Receive.N++

	return receivingEpoch, mk, nil
}

// Decrypt decrypts a ciphertext message.
func (s *SPQRSession) Decrypt(header *SCKAHeader, ciphertext, AD []byte) ([]byte, error) {
	_, mk, err := s.ReceiveKey(header)
	if err != nil {
		return nil, err
	}

	pt, err := decryptMessageSPQR(mk, ciphertext, header, AD)
	if err != nil {
		return nil, ErrAuthFailure
	}

	return pt, nil
}

// TrySkippedMessageKeys attempts to retrieve a skipped message key.
func (s *SPQRSession) TrySkippedMessageKeys(epoch, n uint32) []byte {
	epochKeys, ok := s.MkSkipped[epoch]
	if !ok {
		return nil
	}

	mk, ok := epochKeys[n]
	if !ok {
		return nil
	}

	// Delete the key (one-time use).
	delete(epochKeys, n)
	if len(epochKeys) == 0 {
		delete(s.MkSkipped, epoch)
	}

	// Zero the key before returning.
	mkCopy := make([]byte, len(mk))
	copy(mkCopy, mk)
	for i := range mk {
		mk[i] = 0
	}

	return mkCopy
}

// SkipMessageKeys stores skipped message keys from current position up to until.
func (s *SPQRSession) SkipMessageKeys(epoch, until uint32) error {
	chain, ok := s.KDFChains[epoch]
	if !ok || chain == nil || chain.Receive == nil {
		return nil
	}

	// Check MaxSkip limit.
	if chain.Receive.N+s.MaxSkip < until {
		return ErrMaxSkipExceeded
	}

	for chain.Receive.N < until {
		n := chain.Receive.N
		nextCK, mk, err := kdf.KDF_SCKA_CK(chain.Receive.CK, n)
		if err != nil {
			return err
		}
		chain.Receive.CK = nextCK
		chain.Receive.N++

		// Store the skipped key.
		if s.MkSkipped[epoch] == nil {
			s.MkSkipped[epoch] = make(map[uint32][]byte)
		}
		mkCopy := make([]byte, len(mk))
		copy(mkCopy, mk)
		s.MkSkipped[epoch][n] = mkCopy
	}

	return nil
}

// ClearOldEpochs removes epoch state older than current-1.
func (s *SPQRSession) ClearOldEpochs(sendingEpoch uint32) {
	// Clear epochs older than sendingEpoch - 1.
	clearEpoch := sendingEpoch - 1
	if clearEpoch > 0 {
		delete(s.KDFChains, clearEpoch-1)
		delete(s.MkSkipped, clearEpoch-1)
	}
}

// encryptMessageSPQR encrypts a message using the internal suite.
func encryptMessageSPQR(key, plaintext []byte, header *SCKAHeader, ad []byte) ([]byte, error) {
	headerBytes, err := encodeSCKAHeader(header)
	if err != nil {
		return nil, err
	}

	// Derive AES and HMAC keys from the message key.
	aesKey, macKey := deriveMessageKeysSPQR(key)
	combinedKey := append(aesKey, macKey...)

	combinedAD := append(append([]byte(nil), ad...), headerBytes...)

	return suite.Encrypt(combinedKey, plaintext, combinedAD)
}

// decryptMessageSPQR decrypts a message using the internal suite.
func decryptMessageSPQR(key, ciphertext []byte, header *SCKAHeader, ad []byte) ([]byte, error) {
	headerBytes, err := encodeSCKAHeader(header)
	if err != nil {
		return nil, err
	}

	aesKey, macKey := deriveMessageKeysSPQR(key)
	combinedKey := append(aesKey, macKey...)

	combinedAD := append(append([]byte(nil), ad...), headerBytes...)

	return suite.Decrypt(combinedKey, ciphertext, combinedAD)
}

// deriveMessageKeysSPQR derives AES and HMAC keys from a message key.
func deriveMessageKeysSPQR(key []byte) (aesKey, macKey []byte) {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("SPQRMessage"))
	h.Write([]byte("aes"))
	aesKey = h.Sum(nil)[:32]

	h = hmac.New(sha256.New, key)
	h.Write([]byte("SPQRMessage"))
	h.Write([]byte("mac"))
	macKey = h.Sum(nil)[:32]

	return
}

// encodeSCKAHeader encodes SCKAHeader to bytes.
func encodeSCKAHeader(h *SCKAHeader) ([]byte, error) {
	if h == nil {
		return nil, ErrInvalidInput
	}
	// Format: len(msg) (4 bytes) || msg || n (4 bytes).
	msgLen := len(h.Msg)
	size := 4 + msgLen + 4
	buf := make([]byte, size)
	buf[0] = byte(msgLen >> 24)
	buf[1] = byte(msgLen >> 16)
	buf[2] = byte(msgLen >> 8)
	buf[3] = byte(msgLen)
	copy(buf[4:], h.Msg)
	buf[size-4] = byte(h.N >> 24)
	buf[size-3] = byte(h.N >> 16)
	buf[size-2] = byte(h.N >> 8)
	buf[size-1] = byte(h.N)
	return buf, nil
}
