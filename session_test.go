package doubleratchet

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"testing"

	"doubleratchet/internal/crypto"
	"doubleratchet/internal/suite"
	"golang.org/x/crypto/hkdf"
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

func TestDeriveRootAndChainUsesCurrentRootKeyAsHKDFSalt(t *testing.T) {
	dhOut := bytes.Repeat([]byte{0x11}, 32)
	currentRK := bytes.Repeat([]byte{0x22}, 32)

	gotRK, gotCK, err := deriveRootAndChain(dhOut, currentRK)
	if err != nil {
		t.Fatalf("deriveRootAndChain failed: %v", err)
	}

	okm := make([]byte, 64)
	reader := hkdf.New(sha256.New, dhOut, currentRK, nil)
	if _, err := io.ReadFull(reader, okm); err != nil {
		t.Fatalf("hkdf read failed: %v", err)
	}

	wantRK := okm[:32]
	wantCK := okm[32:]

	if !bytes.Equal(gotRK, wantRK) {
		t.Fatalf("root key mismatch\n got: %x\nwant: %x", gotRK, wantRK)
	}
	if !bytes.Equal(gotCK, wantCK) {
		t.Fatalf("chain key mismatch\n got: %x\nwant: %x", gotCK, wantCK)
	}
}

func TestEncryptMessageAuthenticatesADBeforeHeader(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	plaintext := []byte("hello")
	header := []byte("header")
	ad := []byte("ad")

	ciphertext, err := encryptMessage(key, plaintext, header, ad)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}

	if _, err := decryptMessage(key, ciphertext, header, ad); err != nil {
		t.Fatalf("decryptMessage failed with matching inputs: %v", err)
	}

	aesKey, macKey := deriveSuiteKeysForTest(key, "DoubleratchetMessage")
	combinedKey := append(aesKey, macKey...)

	if _, err := suite.Decrypt(combinedKey, ciphertext, append(ad, header...)); err != nil {
		t.Fatalf("suite decrypt failed for spec AD ordering: %v", err)
	}

	if _, err := suite.Decrypt(combinedKey, ciphertext, append(header, ad...)); err == nil {
		t.Fatal("suite decrypt unexpectedly succeeded for legacy AD ordering")
	}
}

func deriveSuiteKeysForTest(masterKey []byte, label string) (aesKey, macKey []byte) {
	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte(label))
	h.Write([]byte("aes"))
	aesKey = h.Sum(nil)

	h = hmac.New(sha256.New, masterKey)
	h.Write([]byte(label))
	h.Write([]byte("mac"))
	macKey = h.Sum(nil)

	return aesKey, macKey
}
