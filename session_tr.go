package doubleratchet

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
	"github.com/KushnerykPavel/go-doubleratchet/internal/kdf"
	"github.com/KushnerykPavel/go-doubleratchet/internal/suite"
	"github.com/KushnerykPavel/go-doubleratchet/scka"
)

// TripleRatchetSession combines the base Double Ratchet (EC) and the SPQR (PQ)
// in parallel for hybrid security per spec §6.
//
// Encryption derives a message key from both components and combines them via
// KDF_HYBRID before encrypting, so compromise of either component alone reveals
// nothing. Composite headers carry both EC and SCKA routing information.
type TripleRatchetSession struct {
	// dr is the Double Ratchet (elliptic curve) component.
	dr *Session
	// spqr is the Sparse Post-Quantum Ratchet component.
	spqr *SPQRSession
	// config holds session configuration.
	config *Config
}

// InitInitiatorTripleRatchet initializes a Triple Ratchet session for the Initiator.
//
// SharedSecret is expanded into separate EC and PQ keys per spec §7.
// BobDRPK is the Responder's initial EC ratchet public key.
// SckaProvider is the post-quantum SCKA implementation.
func InitInitiatorTripleRatchet(sharedSecret []byte, bobDRPK [32]byte, sckaProvider scka.Provider, cfg *Config) (*TripleRatchetSession, error) {
	if len(sharedSecret) < 32 {
		return nil, fmt.Errorf("doubleratchet: init initiator triple ratchet: %w", ErrSharedSecretTooShort)
	}
	if sckaProvider == nil {
		return nil, fmt.Errorf("doubleratchet: init initiator triple ratchet: %w", ErrNilProvider)
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator triple ratchet: %w", err)
	}

	skec, skscka, err := expandSK(sharedSecret[:32])
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator triple ratchet: %w", err)
	}

	dr, err := InitInitiator(skec, bobDRPK, cfg)
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator triple ratchet: %w", err)
	}

	spqr, err := InitInitiatorSCKA(skscka, sckaProvider, cfg)
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init initiator triple ratchet: %w", err)
	}

	return &TripleRatchetSession{dr: dr, spqr: spqr, config: cfg}, nil
}

// InitResponderTripleRatchet initializes a Triple Ratchet session for the Responder.
//
// SharedSecret is expanded into separate EC and PQ keys per spec §7.
// BobKeyPair is the Responder's EC ratchet key pair.
// SckaProvider is the post-quantum SCKA implementation.
func InitResponderTripleRatchet(sharedSecret []byte, bobKeyPair crypto.KeyPair, sckaProvider scka.Provider, cfg *Config) (*TripleRatchetSession, error) {
	if len(sharedSecret) < 32 {
		return nil, fmt.Errorf("doubleratchet: init responder triple ratchet: %w", ErrSharedSecretTooShort)
	}
	if sckaProvider == nil {
		return nil, fmt.Errorf("doubleratchet: init responder triple ratchet: %w", ErrNilProvider)
	}
	if cfg == nil {
		cfg = &Config{MaxSkip: DefaultMaxSkip}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("doubleratchet: init responder triple ratchet: %w", err)
	}

	skec, skscka, err := expandSK(sharedSecret[:32])
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init responder triple ratchet: %w", err)
	}

	dr, err := InitResponder(skec, bobKeyPair, cfg)
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init responder triple ratchet: %w", err)
	}

	spqr, err := InitResponderSCKA(skscka, sckaProvider, cfg)
	if err != nil {
		return nil, fmt.Errorf("doubleratchet: init responder triple ratchet: %w", err)
	}

	return &TripleRatchetSession{dr: dr, spqr: spqr, config: cfg}, nil
}

// Encrypt encrypts plaintext using the Triple Ratchet.
//
// Derives message keys from both EC and PQ components, combines via KDF_HYBRID,
// and encrypts with the combined key. Both components are rolled back atomically
// if any step fails.
func (s *TripleRatchetSession) Encrypt(plaintext, ad []byte) (TripleRatchetMessage, error) {
	// Snapshot both components before any state mutation.
	s.dr.invariants.Record(s.dr.ns, s.dr.pn, s.dr.rk, s.dr.dhs, s.dr.dhr, s.dr.cks, s.dr.recvChains, s.dr.mkSkipped, s.dr.dhRSet)
	rkSnap := append([]byte(nil), s.spqr.rk...)
	epochSnap := s.spqr.epoch
	chainsSnap := s.spqr.cloneChains()
	skippedSnap := s.spqr.cloneSkipped()
	sckaSnap := s.spqr.scka.Snapshot()

	rollback := func() {
		s.dr.rollback() // zeroes DR's current RK/CKs/recvChains before restoring snapshot
		// Zero SPQR's current key material before restoring snapshot (§8.1).
		crypto.ZeroBytes(s.spqr.rk)
		for _, pair := range s.spqr.kdfChains {
			if pair != nil {
				if pair.Send != nil {
					crypto.ZeroBytes(pair.Send.CK)
				}
				if pair.Receive != nil {
					crypto.ZeroBytes(pair.Receive.CK)
				}
			}
		}
		s.spqr.rk = rkSnap
		s.spqr.epoch = epochSnap
		s.spqr.kdfChains = chainsSnap
		s.spqr.mkSkipped = skippedSnap
		s.spqr.scka.Restore(sckaSnap)
	}

	// Step 1: derive EC component key and header.
	ecHeader, ecMK, err := s.dr.ratchetSendKey()
	if err != nil {
		rollback()
		return TripleRatchetMessage{}, err
	}

	// Step 2: derive PQ component key and SCKA message.
	sckaMsg, pqN, pqMK, err := s.spqr.sendKey()
	if err != nil {
		rollback()
		return TripleRatchetMessage{}, err
	}

	// Step 3: combine via KDF_HYBRID — pqMK as salt, ecMK as IKM.
	combinedMK, err := kdf.Hybrid(pqMK, ecMK, s.config.effectiveHybridInfo())
	if err != nil {
		rollback()
		return TripleRatchetMessage{}, err
	}

	sckaHeader := &SCKAHeader{Msg: sckaMsg, N: pqN}
	header := TripleRatchetHeader{EC: ecHeader, SCKA: sckaHeader}

	// Step 4: encode composite header for AD binding.
	headerBytes, err := encodeTRHeader(header)
	if err != nil {
		rollback()
		return TripleRatchetMessage{}, err
	}

	// Step 5: encrypt with combined key. AD = [identityPrefix] || caller_AD || header_bytes.
	prefix := s.config.identityADPrefix(true)
	combinedAD := make([]byte, 0, len(prefix)+len(ad)+len(headerBytes))
	combinedAD = append(combinedAD, prefix...)
	combinedAD = append(combinedAD, ad...)
	combinedAD = append(combinedAD, headerBytes...)
	ct, err := suite.Encrypt(combinedMK, plaintext, combinedAD, s.config.effectiveEncryptInfo())
	if err != nil {
		rollback()
		return TripleRatchetMessage{}, err
	}

	return TripleRatchetMessage{Header: header, Ciphertext: ct}, nil
}

// Decrypt decrypts a Triple Ratchet message.
//
// Derives and combines EC and PQ message keys, authenticates, and decrypts.
// Both components are rolled back atomically on authentication failure.
func (s *TripleRatchetSession) Decrypt(msg TripleRatchetMessage, ad []byte) ([]byte, error) {
	if msg.Header.SCKA == nil {
		return nil, ErrNilSCKAHeader
	}

	// Snapshot both components.
	s.dr.invariants.Record(s.dr.ns, s.dr.pn, s.dr.rk, s.dr.dhs, s.dr.dhr, s.dr.cks, s.dr.recvChains, s.dr.mkSkipped, s.dr.dhRSet)
	rkSnap := append([]byte(nil), s.spqr.rk...)
	epochSnap := s.spqr.epoch
	chainsSnap := s.spqr.cloneChains()
	skippedSnap := s.spqr.cloneSkipped()
	sckaSnap := s.spqr.scka.Snapshot()

	rollback := func() {
		s.dr.rollback() // zeroes DR's current RK/CKs/CKr before restoring snapshot
		// Zero SPQR's current key material before restoring snapshot (§8.1).
		crypto.ZeroBytes(s.spqr.rk)
		for _, pair := range s.spqr.kdfChains {
			if pair != nil {
				if pair.Send != nil {
					crypto.ZeroBytes(pair.Send.CK)
				}
				if pair.Receive != nil {
					crypto.ZeroBytes(pair.Receive.CK)
				}
			}
		}
		s.spqr.rk = rkSnap
		s.spqr.epoch = epochSnap
		s.spqr.kdfChains = chainsSnap
		s.spqr.mkSkipped = skippedSnap
		s.spqr.scka.Restore(sckaSnap)
	}

	// Step 1: derive EC component key.
	ecMK, err := s.dr.ratchetReceiveKey(msg.Header.EC)
	if err != nil {
		rollback()
		return nil, err
	}

	// Step 2: derive PQ component key.
	_, pqMK, err := s.spqr.receiveKey(msg.Header.SCKA)
	if err != nil {
		rollback()
		return nil, err
	}

	// Step 3: combine via KDF_HYBRID.
	combinedMK, err := kdf.Hybrid(pqMK, ecMK, s.config.effectiveHybridInfo())
	if err != nil {
		rollback()
		return nil, err
	}

	// Step 4: reconstruct combined AD.
	headerBytes, err := encodeTRHeader(msg.Header)
	if err != nil {
		rollback()
		return nil, err
	}
	prefix := s.config.identityADPrefix(false)
	combinedAD := make([]byte, 0, len(prefix)+len(ad)+len(headerBytes))
	combinedAD = append(combinedAD, prefix...)
	combinedAD = append(combinedAD, ad...)
	combinedAD = append(combinedAD, headerBytes...)

	// Step 5: decrypt and authenticate.
	pt, err := suite.Decrypt(combinedMK, msg.Ciphertext, combinedAD, s.config.effectiveEncryptInfo())
	if err != nil {
		rollback()
		return nil, ErrAuthFailure
	}

	return pt, nil
}

// Close zeros all key material in both EC and PQ components.
func (s *TripleRatchetSession) Close() error {
	drErr := s.dr.Close()
	spqrErr := s.spqr.Close()
	if drErr != nil {
		return drErr
	}
	return spqrErr
}

// expandSK expands a 32-byte shared secret into separate EC and PQ keys per spec §7.
// Uses HKDF with distinct info labels so SKec and SKscka are cryptographically
// independent even when derived from the same root secret.
func expandSK(sk []byte) (skec, skscka []byte, err error) {
	skec = make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, sk, nil, []byte("TripleRatchetEC")), skec); err != nil {
		return nil, nil, err
	}

	skscka = make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, sk, nil, []byte("TripleRatchetSCKA")), skscka); err != nil {
		return nil, nil, err
	}

	return skec, skscka, nil
}

// encodeTRHeader encodes the composite Triple Ratchet header for AD binding.
// Format: EC_header (40 bytes fixed) || SCKA_header (4 + len(Msg) + 4 bytes).
// Both sub-encodings are deterministic so the same header always produces the
// same bytes on both sides.
func encodeTRHeader(h TripleRatchetHeader) ([]byte, error) {
	ecBytes := encodeHeader(h.EC)
	sckaBytes, err := encodeSCKAHeader(h.SCKA)
	if err != nil {
		return nil, err
	}
	return append(ecBytes, sckaBytes...), nil
}
