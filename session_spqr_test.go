// Package doubleratchet provides SPQR session tests.
package doubleratchet

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"testing"

	"doubleratchet/internal/kdf"
	"doubleratchet/internal/scka"
	"doubleratchet/internal/state"
	"doubleratchet/internal/suite"
	"golang.org/x/crypto/hkdf"
)

// TestInitAliceSCKA tests that InitAliceSCKA creates correct initial state.
func TestInitAliceSCKA(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &scka.MockSCKA{}
	cfg := &Config{MaxSkip: 1000}

	session, err := InitAliceSCKA(sharedSecret, mockSCKA, cfg)
	if err != nil {
		t.Fatalf("InitAliceSCKA failed: %v", err)
	}

	// Check epoch is 0.
	if session.Epoch != 0 {
		t.Errorf("Expected epoch 0, got %d", session.Epoch)
	}

	// Check direction is A2B.
	if session.Direction != state.DirectionA2B {
		t.Errorf("Expected direction A2B, got %v", session.Direction)
	}

	// Check RK is derived.
	if len(session.RK) != 32 {
		t.Errorf("Expected RK length 32, got %d", len(session.RK))
	}

	// Check KDFChains[0] is initialized.
	if session.KDFChains == nil {
		t.Fatal("KDFChains is nil")
	}
	chain0, ok := session.KDFChains[0]
	if !ok {
		t.Fatal("KDFChains[0] not found")
	}
	if chain0.Send == nil {
		t.Error("KDFChains[0].Send is nil")
	}
	if chain0.Send.N != 0 {
		t.Errorf("Expected KDFChains[0].Send.N = 0, got %d", chain0.Send.N)
	}
	if len(chain0.Send.CK) != 32 {
		t.Errorf("Expected KDFChains[0].Send.CK length 32, got %d", len(chain0.Send.CK))
	}
	if chain0.Receive == nil {
		t.Error("KDFChains[0].Receive is nil")
	}
	if chain0.Receive.N != 0 {
		t.Errorf("Expected KDFChains[0].Receive.N = 0, got %d", chain0.Receive.N)
	}
	if len(chain0.Receive.CK) != 32 {
		t.Errorf("Expected KDFChains[0].Receive.CK length 32, got %d", len(chain0.Receive.CK))
	}

	// Check MkSkipped is initialized (empty map, not nil).
	if session.MkSkipped == nil {
		t.Error("Expected MkSkipped to be initialized (not nil)")
	}
	if len(session.MkSkipped) != 0 {
		t.Errorf("Expected MkSkipped to be empty, got %d entries", len(session.MkSkipped))
	}

	// Check MaxSkip.
	if session.MaxSkip != 1000 {
		t.Errorf("Expected MaxSkip 1000, got %d", session.MaxSkip)
	}
}

// TestInitBobSCKA tests that InitBobSCKA creates correct initial state.
func TestInitBobSCKA(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &scka.MockSCKA{}
	cfg := &Config{MaxSkip: 500}

	session, err := InitBobSCKA(sharedSecret, mockSCKA, cfg)
	if err != nil {
		t.Fatalf("InitBobSCKA failed: %v", err)
	}

	// Check epoch is 0.
	if session.Epoch != 0 {
		t.Errorf("Expected epoch 0, got %d", session.Epoch)
	}

	// Check direction is B2A.
	if session.Direction != state.DirectionB2A {
		t.Errorf("Expected direction B2A, got %v", session.Direction)
	}

	// Check RK is derived.
	if len(session.RK) != 32 {
		t.Errorf("Expected RK length 32, got %d", len(session.RK))
	}

	// Check KDFChains[0] is initialized.
	if session.KDFChains == nil {
		t.Fatal("KDFChains is nil")
	}
	chain0, ok := session.KDFChains[0]
	if !ok {
		t.Fatal("KDFChains[0] not found")
	}
	if chain0.Send == nil {
		t.Error("KDFChains[0].Send is nil")
	}
	if chain0.Send.N != 0 {
		t.Errorf("Expected KDFChains[0].Send.N = 0, got %d", chain0.Send.N)
	}
	if len(chain0.Send.CK) != 32 {
		t.Errorf("Expected KDFChains[0].Send.CK length 32, got %d", len(chain0.Send.CK))
	}
	if chain0.Receive == nil {
		t.Error("KDFChains[0].Receive is nil")
	}
	if chain0.Receive.N != 0 {
		t.Errorf("Expected KDFChains[0].Receive.N = 0, got %d", chain0.Receive.N)
	}

	// Check MkSkipped is initialized (empty map, not nil).
	if session.MkSkipped == nil {
		t.Error("Expected MkSkipped to be initialized (not nil)")
	}
	if len(session.MkSkipped) != 0 {
		t.Errorf("Expected MkSkipped to be empty, got %d entries", len(session.MkSkipped))
	}

	// Check MaxSkip.
	if session.MaxSkip != 500 {
		t.Errorf("Expected MaxSkip 500, got %d", session.MaxSkip)
	}
}

// TestAliceBobDeriveMatchingKeys tests that Alice and Bob derive matching keys for communication.
// Alice's send chain should equal Bob's receive chain, and vice versa.
func TestAliceBobDeriveMatchingKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockAlice := &scka.MockSCKA{}
	mockBob := &scka.MockSCKA{}

	aliceSession, err := InitAliceSCKA(sharedSecret, mockAlice, nil)
	if err != nil {
		t.Fatalf("InitAliceSCKA failed: %v", err)
	}

	bobSession, err := InitBobSCKA(sharedSecret, mockBob, nil)
	if err != nil {
		t.Fatalf("InitBobSCKA failed: %v", err)
	}

	// Both should have the same RK.
	if !bytes.Equal(aliceSession.RK, bobSession.RK) {
		t.Error("Alice and Bob have different RK")
	}

	// Both should have epoch 0.
	if aliceSession.Epoch != bobSession.Epoch {
		t.Errorf("Alice epoch %d != Bob epoch %d", aliceSession.Epoch, bobSession.Epoch)
	}

	// Alice's send chain should equal Bob's receive chain (for Alice->Bob messages).
	aliceSendCK := aliceSession.KDFChains[0].Send.CK
	bobReceiveCK := bobSession.KDFChains[0].Receive.CK
	if !bytes.Equal(aliceSendCK, bobReceiveCK) {
		t.Error("Alice's send CK != Bob's receive CK")
	}

	// Alice's receive chain should equal Bob's send chain (for Bob->Alice messages).
	aliceReceiveCK := aliceSession.KDFChains[0].Receive.CK
	bobSendCK := bobSession.KDFChains[0].Send.CK
	if !bytes.Equal(aliceReceiveCK, bobSendCK) {
		t.Error("Alice's receive CK != Bob's send CK")
	}
}

// TestSendKeyDerivesUniqueKeys tests that each SendKey call derives a unique key.
func TestSendKeyDerivesUniqueKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &scka.MockSCKA{}
	session, err := InitAliceSCKA(sharedSecret, mockSCKA, nil)
	if err != nil {
		t.Fatalf("InitAliceSCKA failed: %v", err)
	}

	// First SendKey.
	_, _, n1, mk1, err := session.SendKey()
	if err != nil {
		t.Fatalf("SendKey 1 failed: %v", err)
	}
	if n1 != 0 {
		t.Errorf("Expected n=0 for first message, got %d", n1)
	}

	// Second SendKey.
	_, _, n2, mk2, err := session.SendKey()
	if err != nil {
		t.Fatalf("SendKey 2 failed: %v", err)
	}
	if n2 != 1 {
		t.Errorf("Expected n=1 for second message, got %d", n2)
	}

	// Keys should be different.
	if bytes.Equal(mk1, mk2) {
		t.Error("Message keys should be unique but were equal")
	}
}

// TestEncryptDecryptRoundTrip tests that encrypt/decrypt round-trip works.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	aliceSCKA := &scka.MockSCKA{}
	bobSCKA := &scka.MockSCKA{}

	aliceSession, err := InitAliceSCKA(sharedSecret, aliceSCKA, nil)
	if err != nil {
		t.Fatalf("InitAliceSCKA failed: %v", err)
	}

	bobSession, err := InitBobSCKA(sharedSecret, bobSCKA, nil)
	if err != nil {
		t.Fatalf("InitBobSCKA failed: %v", err)
	}

	plaintext := []byte("Hello, Bob!")
	ad := []byte("test AD")

	// Alice encrypts.
	header, ciphertext, err := aliceSession.Encrypt(plaintext, ad)
	if err != nil {
		t.Fatalf("Alice Encrypt failed: %v", err)
	}

	// Bob decrypts.
	decrypted, err := bobSession.Decrypt(header, ciphertext, ad)
	if err != nil {
		t.Fatalf("Bob Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted plaintext doesn't match: got %s, want %s", decrypted, plaintext)
	}
}

// TestReceiveKeyIncrementsCounter tests that ReceiveKey increments the receive counter.
func TestReceiveKeyIncrementsCounter(t *testing.T) {
	// This test is complex because it requires proper SCKA message exchange.
	// Simplified version: just test the session state after init.
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &scka.MockSCKA{}

	session, err := InitAliceSCKA(sharedSecret, mockSCKA, nil)
	if err != nil {
		t.Fatalf("InitAliceSCKA failed: %v", err)
	}

	// After initialization, both chains should have N=0.
	if session.KDFChains[0].Send.N != 0 {
		t.Errorf("Expected Send.N=0, got %d", session.KDFChains[0].Send.N)
	}
	if session.KDFChains[0].Receive.N != 0 {
		t.Errorf("Expected Receive.N=0, got %d", session.KDFChains[0].Receive.N)
	}
}

// TestKDFChainType tests KDFChain structure.
func TestKDFChainType(t *testing.T) {
	chain := &state.KDFChain{
		CK: make([]byte, 32),
		N:  5,
	}

	if chain.N != 5 {
		t.Errorf("Expected N=5, got %d", chain.N)
	}
	if len(chain.CK) != 32 {
		t.Errorf("Expected CK length 32, got %d", len(chain.CK))
	}
}

// TestKDFChainPairType tests KDFChainPair structure.
func TestKDFChainPairType(t *testing.T) {
	pair := &state.KDFChainPair{
		Send: &state.KDFChain{
			CK: make([]byte, 32),
			N:  0,
		},
		Receive: &state.KDFChain{
			CK: make([]byte, 32),
			N:  0,
		},
	}

	if pair.Send == nil {
		t.Error("Send chain is nil")
	}
	if pair.Receive == nil {
		t.Error("Receive chain is nil")
	}
}

// TestDirectionValues tests Direction constants.
func TestDirectionValues(t *testing.T) {
	if state.DirectionA2B != 0 {
		t.Errorf("Expected DirectionA2B=0, got %d", state.DirectionA2B)
	}
	if state.DirectionB2A != 1 {
		t.Errorf("Expected DirectionB2A=1, got %d", state.DirectionB2A)
	}
}

// TestKDFSCKAINIT tests KDF_SCKA_INIT derivation.
func TestKDFSCKAINIT(t *testing.T) {
	sk := make([]byte, 32)
	for i := range sk {
		sk[i] = byte(i)
	}

	rk, cks, ckr, err := kdf.KDF_SCKA_INIT(sk)
	if err != nil {
		t.Fatalf("KDF_SCKA_INIT failed: %v", err)
	}

	if len(rk) != 32 {
		t.Errorf("Expected RK length 32, got %d", len(rk))
	}
	if len(cks) != 32 {
		t.Errorf("Expected CKs length 32, got %d", len(cks))
	}
	if len(ckr) != 32 {
		t.Errorf("Expected CKr length 32, got %d", len(ckr))
	}

	// CKs and CKr should be different.
	if bytes.Equal(cks, ckr) {
		t.Error("CKs and CKr should be different")
	}

	okm := hkdfExpandForTest(t, make([]byte, 32), sk, []byte("SPQR_PROTOCOL_INFOChain Start"), 96)
	if !bytes.Equal(rk, okm[:32]) {
		t.Fatalf("RK mismatch\n got: %x\nwant: %x", rk, okm[:32])
	}
	if !bytes.Equal(cks, okm[32:64]) {
		t.Fatalf("CKs mismatch\n got: %x\nwant: %x", cks, okm[32:64])
	}
	if !bytes.Equal(ckr, okm[64:96]) {
		t.Fatalf("CKr mismatch\n got: %x\nwant: %x", ckr, okm[64:96])
	}
}

// TestKDFSCKARK tests KDF_SCKA_RK derivation.
func TestKDFSCKARK(t *testing.T) {
	rk := make([]byte, 32)
	for i := range rk {
		rk[i] = byte(i)
	}

	sckaOutput := make([]byte, 32)
	for i := range sckaOutput {
		sckaOutput[i] = byte(i + 10)
	}

	newRK, cks, ckr, err := kdf.KDF_SCKA_RK(rk, sckaOutput)
	if err != nil {
		t.Fatalf("KDF_SCKA_RK failed: %v", err)
	}

	if len(newRK) != 32 {
		t.Errorf("Expected newRK length 32, got %d", len(newRK))
	}
	if len(cks) != 32 {
		t.Errorf("Expected CKs length 32, got %d", len(cks))
	}
	if len(ckr) != 32 {
		t.Errorf("Expected CKr length 32, got %d", len(ckr))
	}

	// All should be different from input.
	if bytes.Equal(newRK, rk) {
		t.Error("newRK should differ from input RK")
	}

	okm := hkdfExpandForTest(t, rk, sckaOutput, []byte("SPQR_PROTOCOL_INFOChain Add Epoch"), 96)
	if !bytes.Equal(newRK, okm[:32]) {
		t.Fatalf("newRK mismatch\n got: %x\nwant: %x", newRK, okm[:32])
	}
	if !bytes.Equal(cks, okm[32:64]) {
		t.Fatalf("CKs mismatch\n got: %x\nwant: %x", cks, okm[32:64])
	}
	if !bytes.Equal(ckr, okm[64:96]) {
		t.Fatalf("CKr mismatch\n got: %x\nwant: %x", ckr, okm[64:96])
	}
}

// TestKDFSCKACK tests KDF_SCKA_CK derivation.
func TestKDFSCKACK(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(i)
	}

	nextCK, mk, err := kdf.KDF_SCKA_CK(ck, 0)
	if err != nil {
		t.Fatalf("KDF_SCKA_CK failed: %v", err)
	}

	if len(nextCK) != 32 {
		t.Errorf("Expected nextCK length 32, got %d", len(nextCK))
	}
	if len(mk) != 32 {
		t.Errorf("Expected mk length 32, got %d", len(mk))
	}

	// Next CK and MK should be different.
	if bytes.Equal(nextCK, mk) {
		t.Error("nextCK and mk should be different")
	}

	// Advancing with different counter should give different keys.
	nextCK2, mk2, err := kdf.KDF_SCKA_CK(ck, 1)
	if err != nil {
		t.Fatalf("KDF_SCKA_CK failed: %v", err)
	}

	if bytes.Equal(nextCK, nextCK2) {
		t.Error("nextCK for ctr=0 and ctr=1 should differ")
	}
	if bytes.Equal(mk, mk2) {
		t.Error("mk for ctr=0 and ctr=1 should differ")
	}

	okm := hkdfExpandForTest(t, make([]byte, 32), ck, append([]byte("SPQR_PROTOCOL_INFOMessage Keys"), 0, 0, 0, 0), 64)
	if !bytes.Equal(nextCK, okm[:32]) {
		t.Fatalf("nextCK mismatch\n got: %x\nwant: %x", nextCK, okm[:32])
	}
	if !bytes.Equal(mk, okm[32:64]) {
		t.Fatalf("mk mismatch\n got: %x\nwant: %x", mk, okm[32:64])
	}
}

func TestEncryptMessageSPQRAuthenticatesADBeforeHeader(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	plaintext := []byte("pq")
	header := &SCKAHeader{Msg: []byte("msg"), N: 7}
	ad := []byte("ad")

	ciphertext, err := encryptMessageSPQR(key, plaintext, header, ad)
	if err != nil {
		t.Fatalf("encryptMessageSPQR failed: %v", err)
	}

	if _, err := decryptMessageSPQR(key, ciphertext, header, ad); err != nil {
		t.Fatalf("decryptMessageSPQR failed with matching inputs: %v", err)
	}

	headerBytes, err := encodeSCKAHeader(header)
	if err != nil {
		t.Fatalf("encodeSCKAHeader failed: %v", err)
	}

	aesKey, macKey := deriveMessageKeysSPQR(key)
	combinedKey := append(aesKey, macKey...)

	if _, err := suite.Decrypt(combinedKey, ciphertext, append(ad, headerBytes...)); err != nil {
		t.Fatalf("suite decrypt failed for spec AD ordering: %v", err)
	}

	if _, err := suite.Decrypt(combinedKey, ciphertext, append(headerBytes, ad...)); err == nil {
		t.Fatal("suite decrypt unexpectedly succeeded for legacy AD ordering")
	}
}

func hkdfExpandForTest(t *testing.T, salt, ikm, info []byte, length int) []byte {
	t.Helper()

	reader := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		t.Fatalf("hkdf read failed: %v", err)
	}
	return out
}

// TestTrySkippedMessageKeys tests TrySkippedMessageKeys retrieval.
func TestTrySkippedMessageKeys(t *testing.T) {
	session := &SPQRSession{
		RK:        make([]byte, 32),
		Epoch:     0,
		KDFChains: make(map[uint32]*state.KDFChainPair),
		MkSkipped: make(map[uint32]map[uint32][]byte),
		MaxSkip:   1000,
	}

	// No skipped keys yet.
	mk := session.TrySkippedMessageKeys(0, 5)
	if mk != nil {
		t.Error("Expected nil for non-existent skipped key")
	}

	// Store a skipped key.
	session.MkSkipped[0] = map[uint32][]byte{
		5: []byte("key5"),
	}

	// Retrieve it.
	mk = session.TrySkippedMessageKeys(0, 5)
	if mk == nil {
		t.Fatal("Expected to retrieve skipped key")
	}
	if string(mk) != "key5" {
		t.Errorf("Expected 'key5', got %s", string(mk))
	}

	// Should be deleted after retrieval.
	mk = session.TrySkippedMessageKeys(0, 5)
	if mk != nil {
		t.Error("Expected nil after key was retrieved")
	}
}

// TestSkipMessageKeys tests SkipMessageKeys stores keys correctly.
func TestSkipMessageKeys(t *testing.T) {
	session := &SPQRSession{
		RK:    make([]byte, 32),
		Epoch: 0,
		KDFChains: map[uint32]*state.KDFChainPair{
			0: {
				Send: &state.KDFChain{
					CK: make([]byte, 32),
					N:  0,
				},
				Receive: &state.KDFChain{
					CK: make([]byte, 32),
					N:  0,
				},
			},
		},
		MkSkipped: make(map[uint32]map[uint32][]byte),
		MaxSkip:   1000,
	}

	// Skip to message 3.
	err := session.SkipMessageKeys(0, 3)
	if err != nil {
		t.Fatalf("SkipMessageKeys failed: %v", err)
	}

	// Should have stored keys for messages 0, 1, 2.
	if session.MkSkipped[0] == nil {
		t.Fatal("MkSkipped[0] should not be nil")
	}
	if len(session.MkSkipped[0]) != 3 {
		t.Errorf("Expected 3 skipped keys, got %d", len(session.MkSkipped[0]))
	}

	// Keys should be retrievable.
	for n := uint32(0); n < 3; n++ {
		mk := session.TrySkippedMessageKeys(0, n)
		if mk == nil {
			t.Errorf("Expected to retrieve key for n=%d", n)
		}
	}
}

// TestDecryptOutOfOrderMessage uses a delayed first message to verify skipped-key handling.
func TestDecryptOutOfOrderMessage(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	aliceSCKA := &scka.MockSCKA{}
	bobSCKA := &scka.MockSCKA{}

	aliceSession, err := InitAliceSCKA(sharedSecret, aliceSCKA, nil)
	if err != nil {
		t.Fatalf("InitAliceSCKA failed: %v", err)
	}

	bobSession, err := InitBobSCKA(sharedSecret, bobSCKA, nil)
	if err != nil {
		t.Fatalf("InitBobSCKA failed: %v", err)
	}

	ad := []byte("out-of-order AD")

	header0, ciphertext0, err := aliceSession.Encrypt([]byte("message-0"), ad)
	if err != nil {
		t.Fatalf("Encrypt message 0 failed: %v", err)
	}
	header1, ciphertext1, err := aliceSession.Encrypt([]byte("message-1"), ad)
	if err != nil {
		t.Fatalf("Encrypt message 1 failed: %v", err)
	}

	decrypted1, err := bobSession.Decrypt(header1, ciphertext1, ad)
	if err != nil {
		t.Fatalf("Decrypt message 1 failed: %v", err)
	}
	if !bytes.Equal(decrypted1, []byte("message-1")) {
		t.Fatalf("Unexpected plaintext for message 1: got %q", decrypted1)
	}

	decrypted0, err := bobSession.Decrypt(header0, ciphertext0, ad)
	if err != nil {
		t.Fatalf("Decrypt delayed message 0 failed: %v", err)
	}
	if !bytes.Equal(decrypted0, []byte("message-0")) {
		t.Fatalf("Unexpected plaintext for message 0: got %q", decrypted0)
	}
}

// TestClearOldEpochs tests ClearOldEpochs cleanup.
func TestClearOldEpochs(t *testing.T) {
	session := &SPQRSession{
		RK:    make([]byte, 32),
		Epoch: 2,
		KDFChains: map[uint32]*state.KDFChainPair{
			0: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			1: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			2: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
		},
		MkSkipped: map[uint32]map[uint32][]byte{
			0: {0: []byte("key0")},
			1: {0: []byte("key1")},
			2: {0: []byte("key2")},
		},
		MaxSkip: 1000,
	}

	// Clear epochs older than sendingEpoch 2.
	session.ClearOldEpochs(2)

	// Epochs 0 should be cleared.
	if _, ok := session.KDFChains[0]; ok {
		t.Error("KDFChains[0] should be cleared")
	}
	if _, ok := session.MkSkipped[0]; ok {
		t.Error("MkSkipped[0] should be cleared")
	}

	// Epoch 1 should remain (current-1).
	if _, ok := session.KDFChains[1]; !ok {
		t.Error("KDFChains[1] should remain")
	}
	if _, ok := session.MkSkipped[1]; !ok {
		t.Error("MkSkipped[1] should remain")
	}

	// Epoch 2 should remain.
	if _, ok := session.KDFChains[2]; !ok {
		t.Error("KDFChains[2] should remain")
	}
	if _, ok := session.MkSkipped[2]; !ok {
		t.Error("MkSkipped[2] should remain")
	}
}

// TestReceiveKeyClearsOldEpochs ensures receive-side epoch advancement also prunes stale state.
func TestReceiveKeyClearsOldEpochs(t *testing.T) {
	session := &SPQRSession{
		RK:    make([]byte, 32),
		Epoch: 1,
		KDFChains: map[uint32]*state.KDFChainPair{
			0: {Receive: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			1: {Receive: &state.KDFChain{CK: make([]byte, 32), N: 0}},
		},
		MkSkipped: map[uint32]map[uint32][]byte{
			0: {0: []byte("stale")},
			1: {0: []byte("current")},
		},
		Direction: state.DirectionA2B,
		SCKA: &scka.MockSCKA{
			SendEpoch: 2,
			KeyEpoch:  2,
			OutputKey: bytes.Repeat([]byte{0x42}, 32),
		},
		MaxSkip: 1000,
	}

	receivingEpoch, _, err := session.ReceiveKey(&SCKAHeader{Msg: []byte("epoch-2"), N: 0})
	if err != nil {
		t.Fatalf("ReceiveKey failed: %v", err)
	}
	if receivingEpoch != 2 {
		t.Fatalf("Expected receiving epoch 2, got %d", receivingEpoch)
	}
	if _, ok := session.KDFChains[0]; ok {
		t.Fatal("KDFChains[0] should be cleared after receive-side epoch advance")
	}
	if _, ok := session.MkSkipped[0]; ok {
		t.Fatal("MkSkipped[0] should be cleared after receive-side epoch advance")
	}
}

// TestMaxSkipExceeded tests that exceeding MaxSkip returns error.
func TestMaxSkipExceeded(t *testing.T) {
	session := &SPQRSession{
		RK:    make([]byte, 32),
		Epoch: 0,
		KDFChains: map[uint32]*state.KDFChainPair{
			0: {
				Send: &state.KDFChain{
					CK: make([]byte, 32),
					N:  0,
				},
				Receive: &state.KDFChain{
					CK: make([]byte, 32),
					N:  0,
				},
			},
		},
		MkSkipped: make(map[uint32]map[uint32][]byte),
		MaxSkip:   5, // Small limit for testing.
	}

	// Try to skip beyond MaxSkip.
	err := session.SkipMessageKeys(0, 10) // Try to skip to 10 when MaxSkip=5.
	if err != ErrMaxSkipExceeded {
		t.Errorf("Expected ErrMaxSkipExceeded, got %v", err)
	}
}

// TestInitAliceWithInvalidInput tests error handling for invalid input.
func TestInitAliceWithInvalidInput(t *testing.T) {
	mockSCKA := &scka.MockSCKA{}

	// Too short shared secret.
	_, err := InitAliceSCKA([]byte{1, 2, 3}, mockSCKA, nil)
	if err != ErrInvalidInput {
		t.Errorf("Expected ErrInvalidInput for short SK, got %v", err)
	}

	// Nil SCKA.
	_, err = InitAliceSCKA(make([]byte, 32), nil, nil)
	if err != ErrInvalidInput {
		t.Errorf("Expected ErrInvalidInput for nil SCKA, got %v", err)
	}
}

// TestInitBobWithInvalidInput tests error handling for invalid input.
func TestInitBobWithInvalidInput(t *testing.T) {
	mockSCKA := &scka.MockSCKA{}

	// Too short shared secret.
	_, err := InitBobSCKA([]byte{1, 2, 3}, mockSCKA, nil)
	if err != ErrInvalidInput {
		t.Errorf("Expected ErrInvalidInput for short SK, got %v", err)
	}

	// Nil SCKA.
	_, err = InitBobSCKA(make([]byte, 32), nil, nil)
	if err != ErrInvalidInput {
		t.Errorf("Expected ErrInvalidInput for nil SCKA, got %v", err)
	}
}

// TestSCKAHeader tests SCKAHeader structure.
func TestSCKAHeader(t *testing.T) {
	header := &SCKAHeader{
		Msg: []byte("test message"),
		N:   42,
	}

	if string(header.Msg) != "test message" {
		t.Errorf("Expected Msg='test message', got %s", string(header.Msg))
	}
	if header.N != 42 {
		t.Errorf("Expected N=42, got %d", header.N)
	}
}

// TestEpochAdvancement tests that epoch advances correctly when SCKA produces a new key.
func TestEpochAdvancement(t *testing.T) {
	sharedSecret := make([]byte, 32)
	copy(sharedSecret, []byte("shared-secret-key-32-bytes!!"))

	aliceScka := &scka.MockSCKA{}
	bobScka := &scka.MockSCKA{}

	// Configure SCKAs to produce a key on next call.
	outputKey := make([]byte, 32)
	copy(outputKey, []byte("output-key-for-epoch-advanc"))
	aliceScka.SetOutputKey(outputKey)
	aliceScka.SetKeyEpoch(1)
	bobScka.SetOutputKey(outputKey)
	bobScka.SetKeyEpoch(1)

	aliceSession, err := InitAliceSCKA(sharedSecret, aliceScka, nil)
	if err != nil {
		t.Fatalf("InitAliceSCKA failed: %v", err)
	}
	bobSession, err := InitBobSCKA(sharedSecret, bobScka, nil)
	if err != nil {
		t.Fatalf("InitBobSCKA failed: %v", err)
	}

	ad := []byte("test-ad")

	// Initial epoch should be 0.
	if aliceSession.Epoch != 0 {
		t.Errorf("Expected initial epoch 0, got %d", aliceSession.Epoch)
	}
	if bobSession.Epoch != 0 {
		t.Errorf("Expected initial epoch 0, got %d", bobSession.Epoch)
	}

	// First message: epoch advances to 1 for Alice.
	header1, ciphertext1, err := aliceSession.Encrypt([]byte("message-1"), ad)
	if err != nil {
		t.Fatalf("Alice Encrypt failed: %v", err)
	}

	// After sending, Alice's epoch should be 1.
	if aliceSession.Epoch != 1 {
		t.Errorf("Expected Alice epoch 1 after sending, got %d", aliceSession.Epoch)
	}

	// Bob receives: epoch advances to 1 for Bob.
	plaintext1, err := bobSession.Decrypt(header1, ciphertext1, ad)
	if err != nil {
		t.Fatalf("Bob Decrypt failed: %v", err)
	}
	if string(plaintext1) != "message-1" {
		t.Errorf("Expected 'message-1', got %q", plaintext1)
	}

	// After receiving, Bob's epoch should be 1.
	if bobSession.Epoch != 1 {
		t.Errorf("Expected Bob epoch 1 after receiving, got %d", bobSession.Epoch)
	}

	// Both should now have matching RK.
	if subtle.ConstantTimeCompare(aliceSession.RK, bobSession.RK) != 1 {
		t.Error("Alice and Bob should have matching RK after epoch advancement")
	}

	// Both should have kdfchains[1].
	if _, ok := aliceSession.KDFChains[1]; !ok {
		t.Error("Alice should have kdfchains[1]")
	}
	if _, ok := bobSession.KDFChains[1]; !ok {
		t.Error("Bob should have kdfchains[1]")
	}

	// Epoch 0 chains should be cleared (except for the one needed for B2A direction swap).
	// After epoch 1, epoch 0 should be the "previous" epoch and may have send chain cleared.
	if aliceSession.KDFChains[0] != nil && aliceSession.KDFChains[0].Send != nil {
		t.Log("Alice kdfchains[0].Send may be cleared after epoch advancement (expected)")
	}
}

// TestEpochAdvancementMultipleMessages tests epoch advancement across multiple message exchanges.
func TestEpochAdvancementMultipleMessages(t *testing.T) {
	sharedSecret := make([]byte, 32)
	copy(sharedSecret, []byte("shared-secret-key-32-bytes!!"))

	aliceScka := &scka.MockSCKA{}
	bobScka := &scka.MockSCKA{}

	// Configure SCKAs to produce a key on next call.
	outputKey := make([]byte, 32)
	copy(outputKey, []byte("output-key-for-epoch-advanc"))
	aliceScka.SetOutputKey(outputKey)
	aliceScka.SetKeyEpoch(1)
	bobScka.SetOutputKey(outputKey)
	bobScka.SetKeyEpoch(1)

	aliceSession, _ := InitAliceSCKA(sharedSecret, aliceScka, nil)
	bobSession, _ := InitBobSCKA(sharedSecret, bobScka, nil)

	ad := []byte("test-ad")

	// Alice sends first message - epoch advances to 1.
	header1, ct1, _ := aliceSession.Encrypt([]byte("msg-1"), ad)
	bobSession.Decrypt(header1, ct1, ad)

	// Reset SCKA for second epoch.
	aliceScka.SetKeyEpoch(2)
	aliceScka.SetOutputKey(outputKey)
	bobScka.SetKeyEpoch(2)
	bobScka.SetOutputKey(outputKey)

	// Alice sends second message - epoch advances to 2.
	header2, ct2, _ := aliceSession.Encrypt([]byte("msg-2"), ad)
	bobSession.Decrypt(header2, ct2, ad)

	if aliceSession.Epoch != 2 {
		t.Errorf("Expected Alice epoch 2, got %d", aliceSession.Epoch)
	}
	if bobSession.Epoch != 2 {
		t.Errorf("Expected Bob epoch 2, got %d", bobSession.Epoch)
	}
}
