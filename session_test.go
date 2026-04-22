package doubleratchet

import (
	"bytes"
	"testing"

	"doubleratchet/internal/crypto"
)

func TestPreviousChainDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAlice(sharedSecret, bobPubKey, nil)
	if err != nil {
		t.Fatalf("InitAlice failed: %v", err)
	}
	bob, err := InitBob(sharedSecret, bobKeyPair, nil)
	if err != nil {
		t.Fatalf("InitBob failed: %v", err)
	}

	ad := []byte("test ad")

	var firstChain [3]Message
	for i := range firstChain {
		firstChain[i], err = alice.Encrypt([]byte{byte('a' + i)}, ad)
		if err != nil {
			t.Fatalf("Alice first-chain Encrypt %d failed: %v", i, err)
		}
	}

	if _, err := bob.Decrypt(firstChain[0], ad); err != nil {
		t.Fatalf("Bob failed to decrypt first message: %v", err)
	}

	reply, err := bob.Encrypt([]byte("reply"), ad)
	if err != nil {
		t.Fatalf("Bob Encrypt reply failed: %v", err)
	}
	if _, err := alice.Decrypt(reply, ad); err != nil {
		t.Fatalf("Alice Decrypt reply failed: %v", err)
	}

	nextChainMsg, err := alice.Encrypt([]byte("next-chain"), ad)
	if err != nil {
		t.Fatalf("Alice next-chain Encrypt failed: %v", err)
	}
	if _, err := bob.Decrypt(nextChainMsg, ad); err != nil {
		t.Fatalf("Bob failed to decrypt next-chain message: %v", err)
	}

	nrBeforeDelayed := bob.Nr

	delayedPlaintext, err := bob.Decrypt(firstChain[1], ad)
	if err != nil {
		t.Fatalf("Bob failed to decrypt delayed previous-chain message: %v", err)
	}
	if !bytes.Equal(delayedPlaintext, []byte("b")) {
		t.Fatalf("Unexpected delayed plaintext: got %q want %q", delayedPlaintext, []byte("b"))
	}
	if bob.Nr != nrBeforeDelayed {
		t.Fatalf("Nr changed after skipped-key decrypt: got %d want %d", bob.Nr, nrBeforeDelayed)
	}
}

func TestSameChainDelayedMessageDecrypts(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	alice, err := InitAlice(sharedSecret, bobPubKey, nil)
	if err != nil {
		t.Fatalf("InitAlice failed: %v", err)
	}
	bob, err := InitBob(sharedSecret, bobKeyPair, nil)
	if err != nil {
		t.Fatalf("InitBob failed: %v", err)
	}

	ad := []byte("test ad")

	var msgs [3]Message
	for i := range msgs {
		msgs[i], err = alice.Encrypt([]byte{byte('a' + i)}, ad)
		if err != nil {
			t.Fatalf("Alice Encrypt %d failed: %v", i, err)
		}
	}

	pt, err := bob.Decrypt(msgs[2], ad)
	if err != nil {
		t.Fatalf("Bob failed to decrypt out-of-order message: %v", err)
	}
	if !bytes.Equal(pt, []byte("c")) {
		t.Fatalf("Unexpected plaintext for third message: got %q want %q", pt, []byte("c"))
	}
	if bob.Nr != 3 {
		t.Fatalf("Nr after decrypting third message = %d, want 3", bob.Nr)
	}

	nrBeforeDelayed := bob.Nr

	pt, err = bob.Decrypt(msgs[1], ad)
	if err != nil {
		t.Fatalf("Bob failed to decrypt delayed same-chain message: %v", err)
	}
	if !bytes.Equal(pt, []byte("b")) {
		t.Fatalf("Unexpected delayed plaintext: got %q want %q", pt, []byte("b"))
	}
	if bob.Nr != nrBeforeDelayed {
		t.Fatalf("Nr changed after delayed same-chain decrypt: got %d want %d", bob.Nr, nrBeforeDelayed)
	}
}
