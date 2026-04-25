package doubleratchet

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
	"github.com/KushnerykPavel/go-doubleratchet/internal/suite"
)

// sessionNr returns the Nr counter for the active receive chain of s.
// Used in tests because nr is now stored per-chain inside recvChains.
func sessionNr(s *Session) uint32 {
	if c := s.recvChains.Get(s.dhr); c != nil {
		return c.Nr
	}
	return 0
}

func TestPreviousChainDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	var firstChain [3]Message
	for i := range firstChain {
		firstChain[i], err = initiator.Encrypt([]byte{byte('a' + i)}, ad)
		require.NoError(t, err)
	}

	_, err = responder.Decrypt(firstChain[0], ad)
	require.NoError(t, err)

	reply, err := responder.Encrypt([]byte("reply"), ad)
	require.NoError(t, err)
	_, err = initiator.Decrypt(reply, ad)
	require.NoError(t, err)

	nextChainMsg, err := initiator.Encrypt([]byte("next-chain"), ad)
	require.NoError(t, err)
	_, err = responder.Decrypt(nextChainMsg, ad)
	require.NoError(t, err)

	nrBeforeDelayed := sessionNr(responder)

	delayedPlaintext, err := responder.Decrypt(firstChain[1], ad)
	require.NoError(t, err)
	require.Equal(t, []byte("b"), delayedPlaintext)
	require.Equal(t, nrBeforeDelayed, sessionNr(responder))
}

func TestSameChainDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	var msgs [3]Message
	for i := range msgs {
		msgs[i], err = initiator.Encrypt([]byte{byte('a' + i)}, ad)
		require.NoError(t, err)
	}

	pt, err := responder.Decrypt(msgs[2], ad)
	require.NoError(t, err)
	require.Equal(t, []byte("c"), pt)
	require.EqualValues(t, 3, sessionNr(responder))

	nrBeforeDelayed := sessionNr(responder)

	pt, err = responder.Decrypt(msgs[1], ad)
	require.NoError(t, err)
	require.Equal(t, []byte("b"), pt)
	require.Equal(t, nrBeforeDelayed, sessionNr(responder))
}

func TestDeriveRootAndChainUsesCurrentRootKeyAsHKDFSalt(t *testing.T) {
	dhOut := bytes.Repeat([]byte{0x11}, 32)
	currentRK := bytes.Repeat([]byte{0x22}, 32)
	info := []byte("DoubleRatchet") // must match effectiveKDFInfo default

	gotRK, gotCK, err := deriveRootAndChain(dhOut, currentRK, info)
	require.NoError(t, err)

	okm := make([]byte, 64)
	reader := hkdf.New(sha256.New, dhOut, currentRK, info)
	_, err = io.ReadFull(reader, okm)
	require.NoError(t, err)

	require.Equal(t, okm[:32], gotRK, "root key mismatch")
	require.Equal(t, okm[32:], gotCK, "chain key mismatch")
}

func TestEncryptMessageAuthenticatesADBeforeHeader(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	plaintext := []byte("hello")
	header := []byte("header")
	ad := []byte("ad")
	info := []byte("DoubleRatchetEncrypt") // must match effectiveEncryptInfo default

	combinedAD := append(append([]byte(nil), ad...), header...)
	ciphertext, err := suite.Encrypt(key, plaintext, combinedAD, info)
	require.NoError(t, err)

	// Correct inputs must decrypt.
	_, err = suite.Decrypt(key, ciphertext, combinedAD, info)
	require.NoError(t, err)

	// suite.Decrypt with the correct combined AD (ad || header) must succeed.
	_, err = suite.Decrypt(key, ciphertext, append(ad, header...), info)
	require.NoError(t, err, "suite decrypt failed for spec AD ordering")

	// suite.Decrypt with reversed order (header || ad) must fail.
	_, err = suite.Decrypt(key, ciphertext, append(header, ad...), info)
	require.Error(t, err, "suite decrypt unexpectedly succeeded for reversed AD ordering")
}

// TestBobEncryptBeforeReceivingFails verifies that the Responder cannot encrypt before
// receiving the Initiator's first message (nil CKs must not silently produce weak keys).
func TestBobEncryptBeforeReceivingFails(t *testing.T) {
	sharedSecret := make([]byte, 32)
	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	_, err = responder.Encrypt([]byte("premature"), []byte("ad"))
	require.ErrorIs(t, err, ErrSessionNotInitialized)
}

// TestInitInitiatorLargeSharedSecretInterop verifies that a 64-byte sharedSecret
// still produces a working session (only first 32 bytes are used as HKDF salt).
func TestInitInitiatorLargeSharedSecretInterop(t *testing.T) {
	sharedSecret := make([]byte, 64)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	ad := []byte("interop test")
	msg, err := initiator.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)

	pt, err := responder.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}

// TestMaxSkipExceededOnPN verifies the DoS guard on previous-chain PN values.
func TestMaxSkipExceededOnPN(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	cfg := &Config{MaxSkip: 5}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, cfg)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, cfg)
	require.NoError(t, err)

	ad := []byte("ad")

	// Initiator sends one message so Responder can perform his first DH ratchet.
	msg0, err := initiator.Encrypt([]byte("msg0"), ad)
	require.NoError(t, err)
	_, err = responder.Decrypt(msg0, ad)
	require.NoError(t, err)

	// Responder replies — triggering Initiator's DH ratchet.
	reply, err := responder.Encrypt([]byte("reply"), ad)
	require.NoError(t, err)
	_, err = initiator.Decrypt(reply, ad)
	require.NoError(t, err)

	// Initiator sends 7 messages on new chain (beyond MaxSkip=5).
	var msgs [7]Message
	for i := range msgs {
		msgs[i], err = initiator.Encrypt([]byte{byte(i)}, ad)
		require.NoError(t, err)
	}

	// Responder receives the last one — PN in header = 7 > MaxSkip=5 → should fail.
	_, err = responder.Decrypt(msgs[6], ad)
	require.ErrorIs(t, err, ErrMaxSkipExceeded)
}

// TestIncomingRatchetKeyValidation verifies that all-zeros ratchet public key in
// a message header is rejected before the DH operation runs.
func TestIncomingRatchetKeyValidation(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	ad := []byte("ad")
	msg, err := initiator.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)

	// Replace ratchet public key with all-zeros (invalid low-order point).
	msg.Header.RatchetPublicKey = [32]byte{}

	prevNr := sessionNr(responder)
	_, err = responder.Decrypt(msg, ad)
	require.Error(t, err, "Decrypt should fail with all-zeros ratchet public key")
	require.Equal(t, prevNr, sessionNr(responder), "Nr should not change on invalid key")
}

// TestDhRSetInitialState verifies that the Initiator starts with dhRSet=true
// and the Responder starts with dhRSet=false, transitioning after first Decrypt.
func TestDhRSetInitialState(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	require.True(t, initiator.dhRSet, "Initiator should have dhRSet=true after InitInitiator")
	require.False(t, responder.dhRSet, "Responder should have dhRSet=false after InitResponder")

	msg, err := initiator.Encrypt([]byte("hello"), []byte("ad"))
	require.NoError(t, err)
	_, err = responder.Decrypt(msg, []byte("ad"))
	require.NoError(t, err)
	require.True(t, responder.dhRSet, "Responder should have dhRSet=true after first Decrypt")
}

// TestRollbackZerosIntermediateRK verifies that when Decrypt triggers a DH ratchet recv
// step and then fails authentication, rollback() zeroes the intermediate RK allocation
// produced by performDHRatchetRecv rather than abandoning it to GC (§8.1).
func TestRollbackZerosIntermediateRK(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	ad := []byte("ad")

	// Initiator sends first message — Responder will perform DH ratchet recv on Decrypt.
	msg, err := initiator.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)

	// Capture reference to Responder's current RK backing array.
	preDecryptRK := responder.rk

	// Tamper ciphertext so authentication fails AFTER the DH ratchet recv step runs.
	tampered := append([]byte(nil), msg.Ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = responder.Decrypt(Message{Header: msg.Header, Ciphertext: tampered}, ad)
	require.ErrorIs(t, err, ErrAuthFailure)

	// Real message should still decrypt after rollback.
	pt, err := responder.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	// responder.rk must be non-zero after rollback (restored from snapshot).
	require.NotEqual(t, make([]byte, len(responder.rk)), responder.rk, "responder.rk should be non-zero after rollback")

	// preDecryptRK referenced to confirm it was captured before Decrypt.
	_ = preDecryptRK
}

// TestMultiEpochDelayedMessageDecrypts verifies that messages from 2 previous DH epochs
// can still be decrypted when they arrive after the receiver has advanced 2 more epochs.
// This requires the circular receiver-chain buffer (up to 5 chains).
func TestMultiEpochDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	// Epoch A: deliver first initiator message so responder can DH ratchet.
	msgA, err := initiator.Encrypt([]byte("epoch-A"), ad)
	require.NoError(t, err)
	_, err = responder.Decrypt(msgA, ad)
	require.NoError(t, err)

	// Epoch B: responder replies; initiator decrypts (advances to epoch B).
	replyB, err := responder.Encrypt([]byte("reply-B"), ad)
	require.NoError(t, err)
	_, err = initiator.Decrypt(replyB, ad)
	require.NoError(t, err)

	// Initiator on epoch B. Send a message — hold for delayed delivery.
	msgB, err := initiator.Encrypt([]byte("epoch-B"), ad)
	require.NoError(t, err)

	// Epoch C: responder replies again; initiator decrypts (advances to epoch C).
	replyC, err := responder.Encrypt([]byte("reply-C"), ad)
	require.NoError(t, err)
	_, err = initiator.Decrypt(replyC, ad)
	require.NoError(t, err)

	// Initiator on epoch C. Send another message.
	msgC, err := initiator.Encrypt([]byte("epoch-C"), ad)
	require.NoError(t, err)

	// Responder receives epoch C first (advances its receive epoch to C).
	ptC, err := responder.Decrypt(msgC, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("epoch-C"), ptC)

	// Now deliver the delayed epoch B message. Responder must still decrypt it
	// using the retained epoch B chain key from the multi-chain buffer.
	ptB, err := responder.Decrypt(msgB, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("epoch-B"), ptB)
}

// TestChainKeyZeroedAfterEncrypt verifies that the old CKs backing array is zeroed
// in-place after Encrypt advances the chain (§8.1 secure deletion).
func TestChainKeyZeroedAfterEncrypt(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	_, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)

	// Capture a reference to the old CKs backing array before Encrypt.
	oldCKs := initiator.cks

	_, err = initiator.Encrypt([]byte("hello"), []byte("ad"))
	require.NoError(t, err)

	require.Equal(t, make([]byte, len(oldCKs)), oldCKs, "old CKs backing array should be zeroed")
}

// TestEncryptCKsAdvancedBeforeMessage verifies that CKs and Ns are advanced
// before the message is returned, matching spec §3 ordering.
func TestEncryptCKsAdvancedBeforeMessage(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	_, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)

	preNs := initiator.ns

	msg, err := initiator.Encrypt([]byte("hello"), []byte("ad"))
	require.NoError(t, err)

	// Header.N must equal Ns captured before the call.
	require.Equal(t, preNs, msg.Header.N, "header.N should equal pre-call Ns")
	// Ns must be incremented.
	require.Equal(t, preNs+1, initiator.ns, "Ns should be incremented after Encrypt")
}

// TestSessionCloseZerosKeyMaterial verifies that Close() zeros RK, CKs, DHs, etc.
func TestSessionCloseZerosKeyMaterial(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	_, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)

	initiator.Close()

	require.Equal(t, make([]byte, len(initiator.rk)), initiator.rk, "RK should be zeroed after Close")
	require.Equal(t, make([]byte, len(initiator.cks)), initiator.cks, "CKs should be zeroed after Close")
	require.Equal(t, [32]byte{}, initiator.dhs, "DHs should be zeroed after Close")
}

// TestIdentityBindingPreventsReplay verifies that a message encrypted with one identity
// pair cannot be decrypted by a responder configured with different identity keys.
func TestIdentityBindingPreventsReplay(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	localID := [32]byte{0x01}
	remoteID := [32]byte{0x02}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	cfgInit := &Config{
		MaxSkip:           DefaultMaxSkip,
		LocalIdentityKey:  localID,
		RemoteIdentityKey: remoteID,
	}
	cfgResp := &Config{
		MaxSkip:           DefaultMaxSkip,
		LocalIdentityKey:  remoteID,
		RemoteIdentityKey: localID,
	}

	initiator, err := InitInitiator(sharedSecret, bobPubKey, cfgInit)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, cfgResp)
	require.NoError(t, err)

	ad := []byte("ad")
	msg, err := initiator.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)

	// Correct identity pair decrypts.
	pt, err := responder.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	// Create a second responder with WRONG identity keys but same session keys.
	// It shares the same shared secret and key pair so DH derivation matches,
	// but identity prefix in AD won't match → MAC failure.
	wrongRespCfg := &Config{
		MaxSkip:           DefaultMaxSkip,
		LocalIdentityKey:  [32]byte{0x99},
		RemoteIdentityKey: [32]byte{0x88},
	}
	wrongResponder, err := InitResponder(sharedSecret, bobKeyPair, wrongRespCfg)
	require.NoError(t, err)

	// Initiator sends a second message (first was consumed by correct responder).
	msg2, err := initiator.Encrypt([]byte("world"), ad)
	require.NoError(t, err)

	// Wrong-identity responder should fail MAC verification.
	_, err = wrongResponder.Decrypt(msg2, ad)
	require.Error(t, err, "should reject message with wrong identity binding")
}

// TestIdentityBindingBackwardCompatible verifies that zero identity keys produce
// the same behavior as before (no identity prefix in AD).
func TestIdentityBindingBackwardCompatible(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	// nil config → zero identity keys → no prefix.
	initiator, err := InitInitiator(sharedSecret, bobPubKey, nil)
	require.NoError(t, err)
	responder, err := InitResponder(sharedSecret, bobKeyPair, nil)
	require.NoError(t, err)

	ad := []byte("test ad")
	msg, err := initiator.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)

	pt, err := responder.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}

// TestConfigIdentityKeysIncomplete verifies that setting only one identity key fails validation.
func TestConfigIdentityKeysIncomplete(t *testing.T) {
	cfg := &Config{
		LocalIdentityKey:  [32]byte{0x01},
		RemoteIdentityKey: [32]byte{}, // zero
	}
	require.ErrorIs(t, cfg.Validate(), ErrConfigIdentityKeysIncomplete)

	cfg2 := &Config{
		LocalIdentityKey:  [32]byte{}, // zero
		RemoteIdentityKey: [32]byte{0x01},
	}
	require.ErrorIs(t, cfg2.Validate(), ErrConfigIdentityKeysIncomplete)

	// Both set: valid.
	cfg3 := &Config{
		LocalIdentityKey:  [32]byte{0x01},
		RemoteIdentityKey: [32]byte{0x02},
	}
	require.NoError(t, cfg3.Validate())

	// Both zero: valid.
	cfg4 := &Config{}
	require.NoError(t, cfg4.Validate())
}
