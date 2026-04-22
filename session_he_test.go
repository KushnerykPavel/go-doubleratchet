// Package doubleratchet provides conformance tests for header encryption sessions.
package doubleratchet

import (
	"bytes"
	"testing"

	"doubleratchet/internal/crypto"
)

// TestHEAliceBobInitialization tests that Alice and Bob HE initialization
// matches Section 4.4 spec requirements.
func TestHEAliceBobInitialization(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	// Shared header keys.
	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	// Generate Bob's initial key pair for Alice's initialization.
	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	// Alice initializes HE session.
	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	// Bob initializes HE session.
	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	// Verify Alice's initial state per Section 4.4:
	// - HKs = sharedHKA
	// - HKr = zeroed
	// - NHKs = derived via KDF_RK_HE (not zeroed)
	// - NHKr = sharedNHKB
	if alice.HKs.Key != sharedHKA {
		t.Errorf("Alice HKs mismatch")
	}
	if !isZeroed(alice.HKr.Key[:]) {
		t.Error("Alice HKr should be zeroed")
	}
	if isZeroed(alice.NHKs.Key[:]) {
		t.Error("Alice NHKs should be derived, not zeroed")
	}
	if alice.NHKr.Key != sharedNHKB {
		t.Errorf("Alice NHKr mismatch")
	}

	// Verify Bob's initial state per Section 4.4:
	// - HKs = zeroed
	// - HKr = zeroed
	// - NHKs = sharedNHKB
	// - NHKr = sharedHKA
	if !isZeroed(bob.HKs.Key[:]) {
		t.Error("Bob HKs should be zeroed")
	}
	if !isZeroed(bob.HKr.Key[:]) {
		t.Error("Bob HKr should be zeroed")
	}
	if bob.NHKs.Key != sharedNHKB {
		t.Errorf("Bob NHKs mismatch")
	}
	if bob.NHKr.Key != sharedHKA {
		t.Errorf("Bob NHKr mismatch")
	}

	// Both should have RK derived from sharedSecret.
	if len(alice.RK) == 0 || len(bob.RK) == 0 {
		t.Error("RK should be set")
	}
}

// TestHEAliceSendsBobReceives tests the first message flow:
// Alice encrypts with HKs (sharedHKA), Bob receives and performs DH ratchet.
func TestHEAliceSendsBobReceives(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	// Generate Bob's key pair.
	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	// Alice encrypts a message.
	ad := []byte("test ad")
	plaintext := []byte("Hello, Bob!")

	encHeader, msg, err := alice.EncryptHE(plaintext, ad)
	if err != nil {
		t.Fatalf("EncryptHE failed: %v", err)
	}

	// Verify encrypted header is present.
	if len(encHeader.Ciphertext) == 0 {
		t.Error("Encrypted header ciphertext should not be empty")
	}
	if msg.Header != (Header{}) {
		t.Fatalf("EncryptHE leaked plaintext header in Message: %+v", msg.Header)
	}

	// Bob receives and decrypts.
	bobPlaintext, err := bob.DecryptHE(encHeader, msg, ad)
	if err != nil {
		t.Fatalf("DecryptHE failed: %v", err)
	}

	if !bytes.Equal(bobPlaintext, plaintext) {
		t.Errorf("Decrypted plaintext mismatch\ngot:  %s\nwant: %s", bobPlaintext, plaintext)
	}

	// After receiving, Bob should have performed DH ratchet.
	// Verify Bob's state reflects the ratchet.
	if bob.Nr != 1 {
		t.Errorf("Bob Nr = %d, want 1", bob.Nr)
	}

	// Verify Bob's DHr is now Alice's public key.
	alicePubKey, _ := crypto.PublicKeyFromPrivate(alice.DHs)
	if bob.DHr != alicePubKey {
		t.Error("Bob DHr should be Alice's public key after ratchet")
	}
}

// TestHEBobRepliesAliceReceives tests the reply flow after first message.
func TestHEBobRepliesAliceReceives(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	ad := []byte("test ad")

	// Alice sends first message.
	plaintext1 := []byte("Hello, Bob!")
	encHeader1, msg1, err := alice.EncryptHE(plaintext1, ad)
	if err != nil {
		t.Fatalf("Alice EncryptHE failed: %v", err)
	}

	_, err = bob.DecryptHE(encHeader1, msg1, ad)
	if err != nil {
		t.Fatalf("Bob DecryptHE failed: %v", err)
	}

	// Bob replies.
	plaintext2 := []byte("Hello, Alice!")
	encHeader2, msg2, err := bob.EncryptHE(plaintext2, ad)
	if err != nil {
		t.Fatalf("Bob EncryptHE failed: %v", err)
	}

	// Alice receives reply.
	alicePlaintext2, err := alice.DecryptHE(encHeader2, msg2, ad)
	if err != nil {
		t.Fatalf("Alice DecryptHE failed: %v", err)
	}

	if !bytes.Equal(alicePlaintext2, plaintext2) {
		t.Errorf("Alice decrypted plaintext mismatch\ngot:  %s\nwant: %s", alicePlaintext2, plaintext2)
	}

	// After receiving reply, Alice's sending chain should have advanced.
	// dhRatchetPerformed flag should have been consumed.
	if alice.dhRatchetPerformed {
		t.Error("dhRatchetPerformed should be false after Alice processes reply")
	}
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
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	ad := []byte("test ad")

	// Alice sends 3 messages.
	messages := []string{"Message 1", "Message 2", "Message 3"}

	for i, msg := range messages {
		encHeader, m, err := alice.EncryptHE([]byte(msg), ad)
		if err != nil {
			t.Fatalf("Alice EncryptHE %d failed: %v", i, err)
		}

		pt, err := bob.DecryptHE(encHeader, m, ad)
		if err != nil {
			t.Fatalf("Bob DecryptHE %d failed: %v", i, err)
		}

		if !bytes.Equal(pt, []byte(msg)) {
			t.Errorf("Message %d mismatch\ngot:  %s\nwant: %s", i, pt, msg)
		}
	}

	// Bob should have received all 3 messages.
	if bob.Nr != 3 {
		t.Errorf("Bob Nr = %d, want 3", bob.Nr)
	}
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
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, cfg)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, cfg)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	ad := []byte("test ad")

	// Alice sends 5 messages.
	var encHeaders [5]EncryptedHeader
	var msgs [5]Message

	for i := 0; i < 5; i++ {
		encHeader, msg, err := alice.EncryptHE([]byte("Message"), ad)
		if err != nil {
			t.Fatalf("Alice EncryptHE %d failed: %v", i, err)
		}
		encHeaders[i] = encHeader
		msgs[i] = msg
	}

	// Bob receives messages out of order: 0, 2, 4, 1, 3.
	order := []int{0, 2, 4, 1, 3}

	for i, idx := range order {
		pt, err := bob.DecryptHE(encHeaders[idx], msgs[idx], ad)
		if err != nil {
			t.Fatalf("Bob DecryptHE (msg %d, order %d) failed: %v", idx, i, err)
		}
		if !bytes.Equal(pt, []byte("Message")) {
			t.Errorf("Message %d mismatch", idx)
		}
	}

	// All 5 messages should be received.
	if bob.Nr != 5 {
		t.Errorf("Bob Nr = %d, want 5", bob.Nr)
	}
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
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, cfg)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, cfg)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	ad := []byte("test ad")

	// Alice sends 10 messages.
	var encHeaders [10]EncryptedHeader
	var msgs [10]Message

	for i := 0; i < 10; i++ {
		encHeader, msg, err := alice.EncryptHE([]byte("Message"), ad)
		if err != nil {
			t.Fatalf("Alice EncryptHE %d failed: %v", i, err)
		}
		encHeaders[i] = encHeader
		msgs[i] = msg
	}

	// Bob receives message 0 successfully.
	_, err = bob.DecryptHE(encHeaders[0], msgs[0], ad)
	if err != nil {
		t.Fatalf("Bob DecryptHE 0 failed: %v", err)
	}

	// Bob receives messages 5 through 9 (skipping more than MaxSkip).
	for i := 5; i < 10; i++ {
		_, err = bob.DecryptHE(encHeaders[i], msgs[i], ad)
		if err != ErrMaxSkipExceeded {
			t.Errorf("Bob DecryptHE %d should return ErrMaxSkipExceeded, got: %v", i, err)
		}
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
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	ad := []byte("test ad")

	// Alice sends a message.
	encHeader, msg, err := alice.EncryptHE([]byte("Hello"), ad)
	if err != nil {
		t.Fatalf("Alice EncryptHE failed: %v", err)
	}

	// Save Bob's state before failed decryption.
	prevNr := bob.Nr

	// Tamper with ciphertext.
	msg.Ciphertext[0] ^= 0xFF

	// Bob attempts decryption (should fail).
	_, err = bob.DecryptHE(encHeader, msg, ad)
	if err == nil {
		t.Fatal("DecryptHE should fail with tampered ciphertext")
	}

	// State should be rolled back.
	if bob.Nr != prevNr {
		t.Errorf("Bob Nr should be rolled back to %d, got %d", prevNr, bob.Nr)
	}
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
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	ad := []byte("test ad")
	plaintext := []byte("Hello, Bob!")

	encHeader, msg, err := alice.EncryptHE(plaintext, ad)
	if err != nil {
		t.Fatalf("EncryptHE failed: %v", err)
	}

	// Decrypt with correct AD should succeed.
	_, err = bob.DecryptHE(encHeader, msg, ad)
	if err != nil {
		t.Fatalf("DecryptHE failed with correct AD: %v", err)
	}

	// Decrypt with wrong AD should fail.
	_, err = bob.DecryptHE(encHeader, msg, []byte("wrong ad"))
	if err == nil {
		t.Error("DecryptHE should fail with wrong AD")
	}
}

func TestHEPreviousChainDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	ad := []byte("test ad")

	var firstChainHeaders [3]EncryptedHeader
	var firstChainMsgs [3]Message
	for i := range firstChainMsgs {
		firstChainHeaders[i], firstChainMsgs[i], err = alice.EncryptHE([]byte{byte('a' + i)}, ad)
		if err != nil {
			t.Fatalf("Alice first-chain EncryptHE %d failed: %v", i, err)
		}
	}

	if _, err := bob.DecryptHE(firstChainHeaders[0], firstChainMsgs[0], ad); err != nil {
		t.Fatalf("Bob failed to decrypt first message: %v", err)
	}

	replyHeader, replyMsg, err := bob.EncryptHE([]byte("reply"), ad)
	if err != nil {
		t.Fatalf("Bob EncryptHE reply failed: %v", err)
	}
	if _, err := alice.DecryptHE(replyHeader, replyMsg, ad); err != nil {
		t.Fatalf("Alice DecryptHE reply failed: %v", err)
	}

	nextHeader, nextMsg, err := alice.EncryptHE([]byte("next-chain"), ad)
	if err != nil {
		t.Fatalf("Alice next-chain EncryptHE failed: %v", err)
	}
	if _, err := bob.DecryptHE(nextHeader, nextMsg, ad); err != nil {
		t.Fatalf("Bob failed to decrypt next-chain message: %v", err)
	}

	nrBeforeDelayed := bob.Nr

	delayedPlaintext, err := bob.DecryptHE(firstChainHeaders[1], firstChainMsgs[1], ad)
	if err != nil {
		t.Fatalf("Bob failed to decrypt delayed previous-chain HE message: %v", err)
	}
	if !bytes.Equal(delayedPlaintext, []byte("b")) {
		t.Fatalf("Unexpected delayed plaintext: got %q want %q", delayedPlaintext, []byte("b"))
	}
	if bob.Nr != nrBeforeDelayed {
		t.Fatalf("Nr changed after skipped HE key decrypt: got %d want %d", bob.Nr, nrBeforeDelayed)
	}
}

func TestHESameChainDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	sharedHKA := [32]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0}
	sharedNHKB := [32]byte{0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAliceHE(sharedSecret, bobPubKey, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitAliceHE failed: %v", err)
	}

	bob, err := InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		t.Fatalf("InitBobHE failed: %v", err)
	}

	ad := []byte("test ad")

	var encHeaders [3]EncryptedHeader
	var msgs [3]Message
	for i := range msgs {
		encHeaders[i], msgs[i], err = alice.EncryptHE([]byte{byte('a' + i)}, ad)
		if err != nil {
			t.Fatalf("Alice EncryptHE %d failed: %v", i, err)
		}
	}

	pt, err := bob.DecryptHE(encHeaders[2], msgs[2], ad)
	if err != nil {
		t.Fatalf("Bob failed to decrypt out-of-order HE message: %v", err)
	}
	if !bytes.Equal(pt, []byte("c")) {
		t.Fatalf("Unexpected plaintext for message 2: got %q want %q", pt, []byte("c"))
	}
	if bob.Nr != 3 {
		t.Fatalf("Nr after receiving newest same-chain HE message = %d, want 3", bob.Nr)
	}

	nrBeforeDelayed := bob.Nr

	pt, err = bob.DecryptHE(encHeaders[1], msgs[1], ad)
	if err != nil {
		t.Fatalf("Bob failed to decrypt delayed same-chain HE message: %v", err)
	}
	if !bytes.Equal(pt, []byte("b")) {
		t.Fatalf("Unexpected delayed plaintext: got %q want %q", pt, []byte("b"))
	}
	if bob.Nr != nrBeforeDelayed {
		t.Fatalf("Nr changed after delayed same-chain HE decrypt: got %d want %d", bob.Nr, nrBeforeDelayed)
	}
}

// isZeroed checks if a byte slice is all zeros.
func isZeroed(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
