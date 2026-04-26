package doubleratchet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
)

// heSessionNr returns the Nr counter for the active receive chain of s.
func heSessionNr(s *HESession) uint32 {
	if c := s.dr.recvChains.Get(s.dr.dhr); c != nil {
		return c.Nr
	}
	return 0
}

// TestHEInitiatorResponderInitialization tests that Initiator and Responder HE initialization
// matches Section 4.4 spec requirements.
func TestHEInitiatorResponderInitialization(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	// Shared header keys.
	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	// Generate Responder's initial key pair for Initiator's initialization.
	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	// Initiator initializes HE session.
	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	// Responder initializes HE session.
	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	// Verify Initiator's initial state per Section 4.4:
	// - HKs = sharedHKA
	// - HKr = zeroed
	// - NHKs = derived via KDF_RK_HE (not zeroed)
	// - NHKr = sharedNHKB
	require.Equal(t, sharedHKA, initiator.hks.Key, "Initiator HKs mismatch")
	require.Equal(t, make([]byte, 32), initiator.hkr.Key[:], "Initiator HKr should be zeroed")
	require.NotEqual(t, make([]byte, 32), initiator.nhks.Key[:], "Initiator NHKs should be derived, not zeroed")
	require.Equal(t, sharedNHKB, initiator.nhkr.Key, "Initiator NHKr mismatch")

	// Verify Responder's initial state per Section 4.4:
	// - HKs = zeroed
	// - HKr = zeroed
	// - NHKs = sharedNHKB
	// - NHKr = sharedHKA
	require.Equal(t, make([]byte, 32), responder.hks.Key[:], "Responder HKs should be zeroed")
	require.Equal(t, make([]byte, 32), responder.hkr.Key[:], "Responder HKr should be zeroed")
	require.Equal(t, sharedNHKB, responder.nhks.Key, "Responder NHKs mismatch")
	require.Equal(t, sharedHKA, responder.nhkr.Key, "Responder NHKr mismatch")

	// Both should have RK derived from sharedSecret.
	require.NotEmpty(t, initiator.dr.rk, "Initiator RK should be set")
	require.NotEmpty(t, responder.dr.rk, "Responder RK should be set")
}

// TestHEInitiatorSendsResponderReceives tests the first message flow:
// Initiator encrypts with HKs (sharedHKA), Responder receives and performs DH ratchet.
func TestHEInitiatorSendsResponderReceives(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	// Generate Responder's key pair.
	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	// Initiator encrypts a message.
	ad := []byte("test ad")
	plaintext := []byte("Hello, Bob!")

	encHeader, msg, err := initiator.EncryptHE(plaintext, ad)
	require.NoError(t, err)

	// Verify encrypted header is present.
	require.NotEmpty(t, encHeader.Ciphertext, "Encrypted header ciphertext should not be empty")
	require.Equal(t, Header{}, msg.Header, "EncryptHE leaked plaintext header in Message")

	// Responder receives and decrypts.
	responderPlaintext, err := responder.DecryptHE(encHeader, msg, ad)
	require.NoError(t, err)
	require.Equal(t, plaintext, responderPlaintext)

	// After receiving, Responder should have performed DH ratchet.
	require.EqualValues(t, 1, heSessionNr(responder), "Responder Nr should be 1 after receiving")

	// Verify Responder's DHr is now Initiator's public key.
	initiatorPubKey, _ := crypto.PublicKeyFromPrivate(initiator.dr.dhs)
	require.Equal(t, initiatorPubKey, responder.dr.dhr, "Responder DHr should be Initiator's public key after ratchet")
}

// TestHEResponderRepliesInitiatorReceives tests the reply flow after first message.
func TestHEResponderRepliesInitiatorReceives(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	// Initiator sends first message.
	plaintext1 := []byte("Hello, Bob!")
	encHeader1, msg1, err := initiator.EncryptHE(plaintext1, ad)
	require.NoError(t, err)

	_, err = responder.DecryptHE(encHeader1, msg1, ad)
	require.NoError(t, err)

	// Responder replies.
	plaintext2 := []byte("Hello, Alice!")
	encHeader2, msg2, err := responder.EncryptHE(plaintext2, ad)
	require.NoError(t, err)

	// Initiator receives reply.
	initiatorPlaintext2, err := initiator.DecryptHE(encHeader2, msg2, ad)
	require.NoError(t, err)
	require.Equal(t, plaintext2, initiatorPlaintext2)

	// After receiving reply, Initiator has performed the recv-side DH ratchet.
	require.True(t, initiator.dr.dhRatchetPerformed, "dhRatchetPerformed should be true after Initiator processes Responder's reply")
}

// TestHESameChainMessages tests same-chain messages use current header keys.
func TestHESameChainMessages(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	// Initiator sends 3 messages.
	messages := []string{"Message 1", "Message 2", "Message 3"}

	for i, msg := range messages {
		encHeader, m, err := initiator.EncryptHE([]byte(msg), ad)
		require.NoError(t, err, "Initiator EncryptHE %d failed", i)

		pt, err := responder.DecryptHE(encHeader, m, ad)
		require.NoError(t, err, "Responder DecryptHE %d failed", i)
		require.Equal(t, []byte(msg), pt, "Message %d mismatch", i)
	}

	// Responder should have received all 3 messages.
	require.EqualValues(t, 3, heSessionNr(responder))
}

// TestHEOutOfOrderMessages tests out-of-order message decryption via skipped keys.
func TestHEOutOfOrderMessages(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	// Small MaxSkip to test skipping.
	cfg := &Config{MaxSkip: 10}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, cfg)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, cfg)
	require.NoError(t, err)

	ad := []byte("test ad")

	// Initiator sends 5 messages.
	var encHeaders [5]EncryptedHeader
	var msgs [5]Message

	for i := range 5 {
		encHeaders[i], msgs[i], err = initiator.EncryptHE([]byte("Message"), ad)
		require.NoError(t, err, "Initiator EncryptHE %d failed", i)
	}

	// Responder receives messages out of order: 0, 2, 4, 1, 3.
	order := []int{0, 2, 4, 1, 3}

	for i, idx := range order {
		pt, err := responder.DecryptHE(encHeaders[idx], msgs[idx], ad)
		require.NoError(t, err, "Responder DecryptHE (msg %d, order %d) failed", idx, i)
		require.Equal(t, []byte("Message"), pt, "Message %d mismatch", idx)
	}

	// All 5 messages should be received.
	require.EqualValues(t, 5, heSessionNr(responder))
}

// TestHEMaxSkipExceeded tests that MaxSkip is enforced in HE mode.
func TestHEMaxSkipExceeded(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	// Very small MaxSkip.
	cfg := &Config{MaxSkip: 3}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, cfg)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, cfg)
	require.NoError(t, err)

	ad := []byte("test ad")

	// Initiator sends 10 messages.
	var encHeaders [10]EncryptedHeader
	var msgs [10]Message

	for i := range 10 {
		encHeaders[i], msgs[i], err = initiator.EncryptHE([]byte("Message"), ad)
		require.NoError(t, err, "Initiator EncryptHE %d failed", i)
	}

	// Responder receives message 0 successfully.
	_, err = responder.DecryptHE(encHeaders[0], msgs[0], ad)
	require.NoError(t, err)

	// Responder receives messages 5 through 9 (skipping more than MaxSkip).
	for i := 5; i < 10; i++ {
		_, err = responder.DecryptHE(encHeaders[i], msgs[i], ad)
		require.ErrorIs(t, err, ErrMaxSkipExceeded, "Responder DecryptHE %d should return ErrMaxSkipExceeded", i)
	}
}

// TestHEAuthFailureRollback tests that auth failure rolls back state.
func TestHEAuthFailureRollback(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	// Initiator sends a message.
	encHeader, msg, err := initiator.EncryptHE([]byte("Hello"), ad)
	require.NoError(t, err)

	// Save Responder's state before failed decryption.
	prevNr := heSessionNr(responder)

	// Tamper with ciphertext.
	msg.Ciphertext[0] ^= 0xFF

	// Responder attempts decryption (should fail).
	_, err = responder.DecryptHE(encHeader, msg, ad)
	require.Error(t, err, "DecryptHE should fail with tampered ciphertext")

	// State should be rolled back.
	require.Equal(t, prevNr, heSessionNr(responder), "Responder Nr should be rolled back")
}

// TestHEPayloadADConstruction tests that payload AD includes encrypted header.
func TestHEPayloadADConstruction(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	ad := []byte("test ad")
	plaintext := []byte("Hello, Bob!")

	encHeader, msg, err := initiator.EncryptHE(plaintext, ad)
	require.NoError(t, err)

	// Decrypt with correct AD should succeed.
	_, err = responder.DecryptHE(encHeader, msg, ad)
	require.NoError(t, err)

	// Decrypt with wrong AD should fail.
	_, err = responder.DecryptHE(encHeader, msg, []byte("wrong ad"))
	require.Error(t, err, "DecryptHE should fail with wrong AD")
}

func TestHEPreviousChainDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	var firstChainHeaders [3]EncryptedHeader
	var firstChainMsgs [3]Message
	for i := range firstChainMsgs {
		firstChainHeaders[i], firstChainMsgs[i], err = initiator.EncryptHE([]byte{byte('a' + i)}, ad)
		require.NoError(t, err, "Initiator first-chain EncryptHE %d failed", i)
	}

	_, err = responder.DecryptHE(firstChainHeaders[0], firstChainMsgs[0], ad)
	require.NoError(t, err)

	replyHeader, replyMsg, err := responder.EncryptHE([]byte("reply"), ad)
	require.NoError(t, err)
	_, err = initiator.DecryptHE(replyHeader, replyMsg, ad)
	require.NoError(t, err)

	nextHeader, nextMsg, err := initiator.EncryptHE([]byte("next-chain"), ad)
	require.NoError(t, err)
	_, err = responder.DecryptHE(nextHeader, nextMsg, ad)
	require.NoError(t, err)

	nrBeforeDelayed := heSessionNr(responder)

	delayedPlaintext, err := responder.DecryptHE(firstChainHeaders[1], firstChainMsgs[1], ad)
	require.NoError(t, err)
	require.Equal(t, []byte("b"), delayedPlaintext)
	require.Equal(t, nrBeforeDelayed, heSessionNr(responder))
}

func TestHESameChainDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	var encHeaders [3]EncryptedHeader
	var msgs [3]Message
	for i := range msgs {
		encHeaders[i], msgs[i], err = initiator.EncryptHE([]byte{byte('a' + i)}, ad)
		require.NoError(t, err, "Initiator EncryptHE %d failed", i)
	}

	pt, err := responder.DecryptHE(encHeaders[2], msgs[2], ad)
	require.NoError(t, err)
	require.Equal(t, []byte("c"), pt)
	require.EqualValues(t, 3, heSessionNr(responder))

	nrBeforeDelayed := heSessionNr(responder)

	pt, err = responder.DecryptHE(encHeaders[1], msgs[1], ad)
	require.NoError(t, err)
	require.Equal(t, []byte("b"), pt)
	require.Equal(t, nrBeforeDelayed, heSessionNr(responder))
}

// TestHEResponderEncryptBeforeReceivingFails verifies that the Responder cannot encrypt before
// receiving the Initiator's first message (would produce a weak key from zeroed DHr).
func TestHEResponderEncryptBeforeReceivingFails(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1}
	sharedNHKB := [32]byte{0xC1}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	responder, err := InitResponderHE(sharedSecret, crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	_, _, err = responder.EncryptHE([]byte("premature"), []byte("ad"))
	require.ErrorIs(t, err, ErrSessionNotInitialized)
}

// TestHESessionCloseZerosKeyMaterial verifies that Close() zeros all key material.
func TestHESessionCloseZerosKeyMaterial(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	_, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	initiator.Close()

	require.Equal(t, make([]byte, len(initiator.dr.rk)), initiator.dr.rk, "RK should be zeroed after Close")
	require.Equal(t, make([]byte, len(initiator.dr.cks)), initiator.dr.cks, "CKs should be zeroed after Close")
	require.Equal(t, make([]byte, 32), initiator.hks.Key[:], "HKs.Key should be zeroed after Close")
	require.Equal(t, make([]byte, 32), initiator.nhks.Key[:], "NHKs.Key should be zeroed after Close")
	require.Equal(t, make([]byte, 32), initiator.nhkr.Key[:], "NHKr.Key should be zeroed after Close")
}

// TestHEAuthFailureRollbackIncludesHeaderKeys verifies that header key state
// is fully restored after a failed DecryptHE attempt.
func TestHEAuthFailureRollbackIncludesHeaderKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)
	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	// Initiator sends a valid message — triggers Responder's first DH ratchet on receipt.
	encHeader, msg, err := initiator.EncryptHE([]byte("hello"), ad)
	require.NoError(t, err)

	// Snapshot Responder's header key state before failed decrypt.
	prevHKr := responder.hkr
	prevNHKr := responder.nhkr
	prevNr := heSessionNr(responder)

	// Tamper with payload ciphertext — header decrypts fine but payload auth fails.
	tamperedMsg := Message{Ciphertext: append([]byte(nil), msg.Ciphertext...)}
	tamperedMsg.Ciphertext[0] ^= 0xFF

	_, err = responder.DecryptHE(encHeader, tamperedMsg, ad)
	require.Error(t, err, "DecryptHE should fail with tampered payload")

	// Header key state must be fully rolled back.
	require.Equal(t, prevHKr.Key, responder.hkr.Key, "HKr.Key should be rolled back after failed DecryptHE")
	require.Equal(t, prevNHKr.Key, responder.nhkr.Key, "NHKr.Key should be rolled back after failed DecryptHE")
	require.Equal(t, prevNr, heSessionNr(responder), "Nr should be rolled back")

	// Responder should still be able to decrypt the real message.
	pt, err := responder.DecryptHE(encHeader, msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}

// TestHEAnomalousNewDHrWithCurrentHKrRejected verifies strict rejection of
// messages where DHr changed but header was decrypted with current HKr (not NHKr).
// Spec §4 always couples DH key change with header key rotation.
func TestHEAnomalousNewDHrWithCurrentHKrRejected(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)
	responder, err := InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	ad := []byte("test ad")

	// Complete a full round-trip so Responder has a real DHr set (not zeroed).
	encHeader1, msg1, err := initiator.EncryptHE([]byte("msg1"), ad)
	require.NoError(t, err)
	_, err = responder.DecryptHE(encHeader1, msg1, ad)
	require.NoError(t, err)
	responderReply, replyMsg, err := responder.EncryptHE([]byte("reply"), ad)
	require.NoError(t, err)
	_, err = initiator.DecryptHE(responderReply, replyMsg, ad)
	require.NoError(t, err)

	// Initiator sends a second message (on new chain after receiving Responder's reply).
	encHeader2, msg2, err := initiator.EncryptHE([]byte("msg2"), ad)
	require.NoError(t, err)
	pt, err := responder.DecryptHE(encHeader2, msg2, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("msg2"), pt)
}

// TestHEIncomingRatchetKeyValidation verifies that all-zeros ratchet public key
// in decoded header is rejected before the DH operation runs.
func TestHEIncomingRatchetKeyValidation(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	_, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	initiator, err := InitInitiatorHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	require.NoError(t, err)

	// Initiator should have dhRSet=true (DHr=bobPubKey from init).
	require.True(t, initiator.dr.dhRSet, "Initiator should have dhRSet=true after InitInitiatorHE")
}

// TestHESCKAClose is not directly applicable here (SCKA is SPQR-specific).
// Verify SPQRSession.Close calls SCKA.Close in session_spqr_test.go.
