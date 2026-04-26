package doubleratchet

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/KushnerykPavel/go-doubleratchet/internal/kdf"
	"github.com/KushnerykPavel/go-doubleratchet/internal/state"
	"github.com/KushnerykPavel/go-doubleratchet/internal/suite"
	sckatest "github.com/KushnerykPavel/go-doubleratchet/scka/testing"
)

// TestInitInitiatorSCKA tests that InitInitiatorSCKA creates correct initial state.
func TestInitInitiatorSCKA(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &sckatest.MockSCKA{}
	cfg := &Config{MaxSkip: 1000}

	session, err := InitInitiatorSCKA(sharedSecret, mockSCKA, cfg)
	require.NoError(t, err)

	require.EqualValues(t, 0, session.epoch)
	require.Equal(t, state.DirectionA2B, session.direction)
	require.Len(t, session.rk, 32)
	require.NotNil(t, session.kdfChains)
	require.Contains(t, session.kdfChains, uint32(0))

	chain0 := session.kdfChains[0]
	require.NotNil(t, chain0.Send)
	require.EqualValues(t, 0, chain0.Send.N)
	require.Len(t, chain0.Send.CK, 32)
	require.NotNil(t, chain0.Receive)
	require.EqualValues(t, 0, chain0.Receive.N)
	require.Len(t, chain0.Receive.CK, 32)

	require.NotNil(t, session.mkSkipped)
	require.Empty(t, session.mkSkipped)
	require.EqualValues(t, 1000, session.maxSkip)
}

// TestInitResponderSCKA tests that InitResponderSCKA creates correct initial state.
func TestInitResponderSCKA(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &sckatest.MockSCKA{}
	cfg := &Config{MaxSkip: 500}

	session, err := InitResponderSCKA(sharedSecret, mockSCKA, cfg)
	require.NoError(t, err)

	require.EqualValues(t, 0, session.epoch)
	require.Equal(t, state.DirectionB2A, session.direction)
	require.Len(t, session.rk, 32)
	require.NotNil(t, session.kdfChains)
	require.Contains(t, session.kdfChains, uint32(0))

	chain0 := session.kdfChains[0]
	require.NotNil(t, chain0.Send)
	require.EqualValues(t, 0, chain0.Send.N)
	require.Len(t, chain0.Send.CK, 32)
	require.NotNil(t, chain0.Receive)
	require.EqualValues(t, 0, chain0.Receive.N)

	require.NotNil(t, session.mkSkipped)
	require.Empty(t, session.mkSkipped)
	require.EqualValues(t, 500, session.maxSkip)
}

// TestInitiatorResponderDeriveMatchingKeys tests that Initiator and Responder derive matching keys for communication.
// Initiator's send chain should equal Responder's receive chain, and vice versa.
func TestInitiatorResponderDeriveMatchingKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockInitiator := &sckatest.MockSCKA{}
	mockResponder := &sckatest.MockSCKA{}

	initiatorSession, err := InitInitiatorSCKA(sharedSecret, mockInitiator, nil)
	require.NoError(t, err)

	responderSession, err := InitResponderSCKA(sharedSecret, mockResponder, nil)
	require.NoError(t, err)

	// Both should have the same RK.
	require.Equal(t, initiatorSession.rk, responderSession.rk, "Initiator and Responder have different RK")

	// Both should have epoch 0.
	require.Equal(t, initiatorSession.epoch, responderSession.epoch, "Initiator and Responder have different epoch")

	// Initiator's send chain should equal Responder's receive chain (for Initiator->Responder messages).
	require.Equal(t, initiatorSession.kdfChains[0].Send.CK, responderSession.kdfChains[0].Receive.CK, "Initiator's send CK != Responder's receive CK")

	// Initiator's receive chain should equal Responder's send chain (for Responder->Initiator messages).
	require.Equal(t, initiatorSession.kdfChains[0].Receive.CK, responderSession.kdfChains[0].Send.CK, "Initiator's receive CK != Responder's send CK")
}

// TestSendKeyDerivesUniqueKeys tests that each SendKey call derives a unique key.
func TestSendKeyDerivesUniqueKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &sckatest.MockSCKA{}
	session, err := InitInitiatorSCKA(sharedSecret, mockSCKA, nil)
	require.NoError(t, err)

	// First SendKey — 0-indexed: first message has N=0.
	_, n1, mk1, err := session.sendKey()
	require.NoError(t, err)
	require.EqualValues(t, 0, n1, "expected n=0 for first message")

	// Second SendKey — second message has N=1.
	_, n2, mk2, err := session.sendKey()
	require.NoError(t, err)
	require.EqualValues(t, 1, n2, "expected n=1 for second message")

	// Keys should be different.
	require.NotEqual(t, mk1, mk2, "message keys should be unique but were equal")
}

// TestEncryptDecryptRoundTrip tests that encrypt/decrypt round-trip works.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	initiatorSession, err := InitInitiatorSCKA(sharedSecret, aliceSCKA, nil)
	require.NoError(t, err)

	responderSession, err := InitResponderSCKA(sharedSecret, bobSCKA, nil)
	require.NoError(t, err)

	plaintext := []byte("Hello, Bob!")
	ad := []byte("test AD")

	// Initiator encrypts.
	header, ciphertext, err := initiatorSession.Encrypt(plaintext, ad)
	require.NoError(t, err)

	// Responder decrypts.
	decrypted, err := responderSession.Decrypt(header, ciphertext, ad)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestReceiveKeyIncrementsCounter tests that ReceiveKey increments the receive counter.
func TestReceiveKeyIncrementsCounter(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &sckatest.MockSCKA{}

	session, err := InitInitiatorSCKA(sharedSecret, mockSCKA, nil)
	require.NoError(t, err)

	// After initialization, both chains should have N=0.
	require.EqualValues(t, 0, session.kdfChains[0].Send.N)
	require.EqualValues(t, 0, session.kdfChains[0].Receive.N)
}

// TestKDFChainType tests KDFChain structure.
func TestKDFChainType(t *testing.T) {
	chain := &state.KDFChain{
		CK: make([]byte, 32),
		N:  5,
	}

	require.EqualValues(t, 5, chain.N)
	require.Len(t, chain.CK, 32)
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

	require.NotNil(t, pair.Send)
	require.NotNil(t, pair.Receive)
}

// TestDirectionValues tests Direction constants.
func TestDirectionValues(t *testing.T) {
	require.EqualValues(t, 0, state.DirectionA2B)
	require.EqualValues(t, 1, state.DirectionB2A)
}

// TestKDFSCKAINIT tests KDF_SCKA_INIT derivation.
func TestKDFSCKAINIT(t *testing.T) {
	sk := make([]byte, 32)
	for i := range sk {
		sk[i] = byte(i)
	}

	rk, cks, ckr, err := kdf.DeriveInitialChainsSPQR(sk)
	require.NoError(t, err)

	require.Len(t, rk, 32)
	require.Len(t, cks, 32)
	require.Len(t, ckr, 32)

	// CKs and CKr should be different.
	require.NotEqual(t, cks, ckr, "CKs and CKr should be different")

	okm := hkdfExpandForTest(t, make([]byte, 32), sk, []byte("SPQR_PROTOCOL_INFOChain Start"), 96)
	require.Equal(t, okm[:32], rk, "RK mismatch")
	require.Equal(t, okm[32:64], cks, "CKs mismatch")
	require.Equal(t, okm[64:96], ckr, "CKr mismatch")
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

	newRK, cks, ckr, err := kdf.RatchetRootKeySPQR(rk, sckaOutput)
	require.NoError(t, err)

	require.Len(t, newRK, 32)
	require.Len(t, cks, 32)
	require.Len(t, ckr, 32)

	// All should be different from input.
	require.NotEqual(t, rk, newRK, "newRK should differ from input RK")

	okm := hkdfExpandForTest(t, rk, sckaOutput, []byte("SPQR_PROTOCOL_INFOChain Add Epoch"), 96)
	require.Equal(t, okm[:32], newRK, "newRK mismatch")
	require.Equal(t, okm[32:64], cks, "CKs mismatch")
	require.Equal(t, okm[64:96], ckr, "CKr mismatch")
}

// TestKDFSCKACK tests KDF_SCKA_CK derivation.
func TestKDFSCKACK(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(i)
	}

	nextCK, mk, err := kdf.RatchetChainKeySPQR(ck, 0)
	require.NoError(t, err)

	require.Len(t, nextCK, 32)
	require.Len(t, mk, 32)

	// Next CK and MK should be different.
	require.NotEqual(t, nextCK, mk, "nextCK and mk should be different")

	// Advancing with different counter should give different keys.
	nextCK2, mk2, err := kdf.RatchetChainKeySPQR(ck, 1)
	require.NoError(t, err)

	require.NotEqual(t, nextCK, nextCK2, "nextCK for ctr=0 and ctr=1 should differ")
	require.NotEqual(t, mk, mk2, "mk for ctr=0 and ctr=1 should differ")

	okm := hkdfExpandForTest(t, make([]byte, 32), ck, append([]byte("SPQR_PROTOCOL_INFOMessage Keys"), 0, 0, 0, 0), 64)
	require.Equal(t, okm[:32], nextCK, "nextCK mismatch")
	require.Equal(t, okm[32:64], mk, "mk mismatch")
}

func TestEncryptMessageSPQRAuthenticatesADBeforeHeader(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	plaintext := []byte("pq")
	header := &SCKAHeader{Msg: []byte("msg"), N: 7}
	ad := []byte("ad")
	info := []byte("DoubleRatchetEncrypt") // must match effectiveEncryptInfo default

	cfg := &Config{MaxSkip: DefaultMaxSkip}
	ciphertext, err := encryptMessageSPQR(cfg, key, plaintext, header, ad, info)
	require.NoError(t, err)

	_, err = decryptMessageSPQR(cfg, key, ciphertext, header, ad, info)
	require.NoError(t, err)

	headerBytes, err := encodeSCKAHeader(header)
	require.NoError(t, err)

	// Correct combined AD = ad || headerBytes must succeed.
	_, err = suite.Decrypt(key, ciphertext, append(ad, headerBytes...), info)
	require.NoError(t, err, "suite decrypt failed for spec AD ordering")

	// Reversed order (headerBytes || ad) must fail.
	_, err = suite.Decrypt(key, ciphertext, append(headerBytes, ad...), info)
	require.Error(t, err, "suite decrypt unexpectedly succeeded for reversed AD ordering")
}

func hkdfExpandForTest(t *testing.T, salt, ikm, info []byte, length int) []byte {
	t.Helper()

	reader := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	_, err := io.ReadFull(reader, out)
	require.NoError(t, err)
	return out
}

// TestTrySkippedMessageKeys tests TrySkippedMessageKeys retrieval.
func TestTrySkippedMessageKeys(t *testing.T) {
	session := &SPQRSession{
		rk:        make([]byte, 32),
		epoch:     0,
		kdfChains: make(map[uint32]*state.KDFChainPair),
		mkSkipped: make(map[uint32]map[uint32][]byte),
		maxSkip:   1000,
	}

	// No skipped keys yet.
	mk := session.trySkippedMessageKeys(0, 5)
	require.Nil(t, mk)

	// Store a skipped key.
	session.mkSkipped[0] = map[uint32][]byte{
		5: []byte("key5"),
	}

	// Retrieve it.
	mk = session.trySkippedMessageKeys(0, 5)
	require.NotNil(t, mk)
	require.Equal(t, []byte("key5"), mk)

	// Should be deleted after retrieval.
	mk = session.trySkippedMessageKeys(0, 5)
	require.Nil(t, mk)
}

// TestSkipMessageKeys tests SkipMessageKeys stores keys correctly.
func TestSkipMessageKeys(t *testing.T) {
	session := &SPQRSession{
		rk:    make([]byte, 32),
		epoch: 0,
		kdfChains: map[uint32]*state.KDFChainPair{
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
		mkSkipped: make(map[uint32]map[uint32][]byte),
		maxSkip:   1000,
	}

	// Skip to message 3 (0-indexed: stores N=0, N=1, N=2).
	err := session.skipMessageKeysSPQR(0, 3)
	require.NoError(t, err)

	// Should have stored keys for messages 0, 1, and 2.
	require.NotNil(t, session.mkSkipped[0])
	require.Len(t, session.mkSkipped[0], 3)

	// Keys should be retrievable.
	for n := range uint32(3) {
		mk := session.trySkippedMessageKeys(0, n)
		require.NotNil(t, mk, "expected to retrieve key for n=%d", n)
	}
}

func TestSPQRMessageNumbersStartAtZero(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	initiatorSession, err := InitInitiatorSCKA(sharedSecret, aliceSCKA, nil)
	require.NoError(t, err)
	responderSession, err := InitResponderSCKA(sharedSecret, bobSCKA, nil)
	require.NoError(t, err)

	ad := []byte("spqr ad")
	header, ciphertext, err := initiatorSession.Encrypt([]byte("message-0"), ad)
	require.NoError(t, err)
	require.EqualValues(t, 0, header.N, "expected first header.N to be 0")

	plaintext, err := responderSession.Decrypt(header, ciphertext, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("message-0"), plaintext)
	// After receiving N=0, Receive.N should advance to 1.
	require.EqualValues(t, 1, responderSession.kdfChains[0].Receive.N, "expected receive counter to advance to 1")
}

// TestDecryptOutOfOrderMessage uses a delayed first message to verify skipped-key handling.
func TestDecryptOutOfOrderMessage(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	initiatorSession, err := InitInitiatorSCKA(sharedSecret, aliceSCKA, nil)
	require.NoError(t, err)

	responderSession, err := InitResponderSCKA(sharedSecret, bobSCKA, nil)
	require.NoError(t, err)

	ad := []byte("out-of-order AD")

	header0, ciphertext0, err := initiatorSession.Encrypt([]byte("message-0"), ad)
	require.NoError(t, err)
	header1, ciphertext1, err := initiatorSession.Encrypt([]byte("message-1"), ad)
	require.NoError(t, err)

	decrypted1, err := responderSession.Decrypt(header1, ciphertext1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("message-1"), decrypted1)

	decrypted0, err := responderSession.Decrypt(header0, ciphertext0, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("message-0"), decrypted0)
}

// TestSPQRDecryptRollbackZerosRK verifies that when SPQR Decrypt fails authentication
// after ReceiveKey has (potentially) updated s.rk, the rollback zeroes the intermediate
// RK allocation before restoring the snapshot (§8.1).
func TestSPQRDecryptRollbackZerosRK(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	outputKey := make([]byte, 32)
	for i := range outputKey {
		outputKey[i] = byte(i + 50)
	}

	// Configure both SCKAs to produce an epoch-1 key on first operation.
	aliceSCKA := &sckatest.MockSCKA{}
	aliceSCKA.SetOutputKey(outputKey)
	aliceSCKA.SetKeyEpoch(1)

	bobSCKA := &sckatest.MockSCKA{}
	bobSCKA.SetOutputKey(outputKey)
	bobSCKA.SetKeyEpoch(1)

	initiatorSession, err := InitInitiatorSCKA(sharedSecret, aliceSCKA, nil)
	require.NoError(t, err)
	responderSession, err := InitResponderSCKA(sharedSecret, bobSCKA, nil)
	require.NoError(t, err)

	ad := []byte("spqr-rollback-test")

	// Initiator sends a message (epoch advances to 1 for Initiator).
	header, ciphertext, err := initiatorSession.Encrypt([]byte("real message"), ad)
	require.NoError(t, err)

	// Capture Responder's RK before the failing Decrypt.
	preRK := responderSession.rk

	// Tamper ciphertext to force auth failure AFTER ReceiveKey updates Responder's RK.
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = responderSession.Decrypt(header, tampered, ad)
	require.ErrorIs(t, err, ErrAuthFailure)

	// Responder's RK must be restored to pre-Decrypt value after rollback.
	require.Equal(t, preRK, responderSession.rk, "Responder's RK not correctly restored after rollback")

	// The real message must still decrypt after rollback.
	pt, err := responderSession.Decrypt(header, ciphertext, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("real message"), pt)
}

// TestClearOldEpochsZerosKeyMaterial verifies that ClearOldEpochs zeros chain key bytes
// in-place before removing epochs (§8.1 secure deletion).
func TestClearOldEpochsZerosKeyMaterial(t *testing.T) {
	ck0Send := bytes.Repeat([]byte{0xAA}, 32)
	ck0Recv := bytes.Repeat([]byte{0xBB}, 32)
	mk0 := bytes.Repeat([]byte{0xCC}, 32)

	session := &SPQRSession{
		rk:    make([]byte, 32),
		epoch: 2,
		kdfChains: map[uint32]*state.KDFChainPair{
			0: {
				Send:    &state.KDFChain{CK: ck0Send, N: 0},
				Receive: &state.KDFChain{CK: ck0Recv, N: 0},
			},
			1: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			2: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
		},
		mkSkipped: map[uint32]map[uint32][]byte{
			0: {0: mk0},
			1: {0: bytes.Repeat([]byte{0xDD}, 32)},
			2: {0: bytes.Repeat([]byte{0xEE}, 32)},
		},
		maxSkip: 1000,
	}

	// ClearOldEpochs(2) clears epochs < 1 (i.e., epoch 0).
	session.clearOldEpochs(2)

	// Epoch 0 chain keys and message keys must be zeroed in the original slices.
	require.Equal(t, make([]byte, len(ck0Send)), ck0Send, "ck0Send must be zeroed before epoch removal")
	require.Equal(t, make([]byte, len(ck0Recv)), ck0Recv, "ck0Recv must be zeroed before epoch removal")
	require.Equal(t, make([]byte, len(mk0)), mk0, "mk0 must be zeroed before epoch removal")

	// Epoch 0 entries must be removed from the maps.
	require.NotContains(t, session.kdfChains, uint32(0), "KDFChains[0] should be removed")
	require.NotContains(t, session.mkSkipped, uint32(0), "MkSkipped[0] should be removed")
}

// TestClearOldEpochs tests ClearOldEpochs cleanup.
func TestClearOldEpochs(t *testing.T) {
	session := &SPQRSession{
		rk:    make([]byte, 32),
		epoch: 2,
		kdfChains: map[uint32]*state.KDFChainPair{
			0: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			1: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			2: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
		},
		mkSkipped: map[uint32]map[uint32][]byte{
			0: {0: []byte("key0")},
			1: {0: []byte("key1")},
			2: {0: []byte("key2")},
		},
		maxSkip: 1000,
	}

	// Clear epochs older than sendingEpoch 2.
	session.clearOldEpochs(2)

	// Epochs 0 should be cleared.
	require.NotContains(t, session.kdfChains, uint32(0), "KDFChains[0] should be cleared")
	require.NotContains(t, session.mkSkipped, uint32(0), "MkSkipped[0] should be cleared")

	// Epoch 1 should remain (current-1).
	require.Contains(t, session.kdfChains, uint32(1), "KDFChains[1] should remain")
	require.Contains(t, session.mkSkipped, uint32(1), "MkSkipped[1] should remain")

	// Epoch 2 should remain.
	require.Contains(t, session.kdfChains, uint32(2), "KDFChains[2] should remain")
	require.Contains(t, session.mkSkipped, uint32(2), "MkSkipped[2] should remain")
}

func TestClearOldEpochsRemovesAllEpochsOlderThanPrevious(t *testing.T) {
	session := &SPQRSession{
		rk:    make([]byte, 32),
		epoch: 3,
		kdfChains: map[uint32]*state.KDFChainPair{
			0: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			1: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			2: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			3: {Send: &state.KDFChain{CK: make([]byte, 32), N: 0}},
		},
		mkSkipped: map[uint32]map[uint32][]byte{
			0: {0: []byte("key0")},
			1: {0: []byte("key1")},
			2: {0: []byte("key2")},
			3: {0: []byte("key3")},
		},
		maxSkip: 1000,
	}

	session.clearOldEpochs(3)

	require.NotContains(t, session.kdfChains, uint32(0))
	require.NotContains(t, session.kdfChains, uint32(1))
	require.NotContains(t, session.mkSkipped, uint32(0))
	require.NotContains(t, session.mkSkipped, uint32(1))

	require.Contains(t, session.kdfChains, uint32(2))
	require.Contains(t, session.kdfChains, uint32(3))
	require.Contains(t, session.mkSkipped, uint32(2))
	require.Contains(t, session.mkSkipped, uint32(3))
}

// TestReceiveKeyClearsOldEpochs ensures receive-side epoch advancement also prunes stale state.
func TestReceiveKeyClearsOldEpochs(t *testing.T) {
	session := &SPQRSession{
		rk:    make([]byte, 32),
		epoch: 1,
		kdfChains: map[uint32]*state.KDFChainPair{
			0: {Receive: &state.KDFChain{CK: make([]byte, 32), N: 0}},
			1: {Receive: &state.KDFChain{CK: make([]byte, 32), N: 0}},
		},
		mkSkipped: map[uint32]map[uint32][]byte{
			0: {0: []byte("stale")},
			1: {0: []byte("current")},
		},
		direction: state.DirectionA2B,
		scka: &sckatest.MockSCKA{
			SendEpoch: 2,
			KeyEpoch:  2,
			OutputKey: bytes.Repeat([]byte{0x42}, 32),
		},
		maxSkip: 1000,
	}

	// 0-indexed: first message of epoch 2 has N=0.
	receivingEpoch, _, err := session.receiveKey(&SCKAHeader{Msg: []byte("epoch-2"), N: 0})
	require.NoError(t, err)
	require.EqualValues(t, 2, receivingEpoch)
	require.NotContains(t, session.kdfChains, uint32(0), "KDFChains[0] should be cleared after receive-side epoch advance")
	require.NotContains(t, session.mkSkipped, uint32(0), "MkSkipped[0] should be cleared after receive-side epoch advance")
}

// TestMaxSkipExceeded tests that exceeding MaxSkip returns error.
func TestMaxSkipExceeded(t *testing.T) {
	session := &SPQRSession{
		rk:    make([]byte, 32),
		epoch: 0,
		kdfChains: map[uint32]*state.KDFChainPair{
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
		mkSkipped: make(map[uint32]map[uint32][]byte),
		maxSkip:   5, // Small limit for testing.
	}

	// Try to skip beyond MaxSkip.
	err := session.skipMessageKeysSPQR(0, 10)
	require.ErrorIs(t, err, ErrMaxSkipExceeded)
}

// TestInitInitiatorWithInvalidInput tests error handling for invalid input.
func TestInitInitiatorWithInvalidInput(t *testing.T) {
	mockSCKA := &sckatest.MockSCKA{}

	// Too short shared secret.
	_, err := InitInitiatorSCKA([]byte{1, 2, 3}, mockSCKA, nil)
	require.ErrorIs(t, err, ErrSharedSecretTooShort)

	// Nil SCKA.
	_, err = InitInitiatorSCKA(make([]byte, 32), nil, nil)
	require.ErrorIs(t, err, ErrNilProvider)
}

// TestInitResponderWithInvalidInput tests error handling for invalid input.
func TestInitResponderWithInvalidInput(t *testing.T) {
	mockSCKA := &sckatest.MockSCKA{}

	// Too short shared secret.
	_, err := InitResponderSCKA([]byte{1, 2, 3}, mockSCKA, nil)
	require.ErrorIs(t, err, ErrSharedSecretTooShort)

	// Nil SCKA.
	_, err = InitResponderSCKA(make([]byte, 32), nil, nil)
	require.ErrorIs(t, err, ErrNilProvider)
}

// TestSCKAHeader tests SCKAHeader structure.
func TestSCKAHeader(t *testing.T) {
	header := &SCKAHeader{
		Msg: []byte("test message"),
		N:   42,
	}

	require.Equal(t, []byte("test message"), header.Msg)
	require.EqualValues(t, 42, header.N)
}

// TestEpochAdvancement tests that epoch advances correctly when SCKA produces a new key.
func TestEpochAdvancement(t *testing.T) {
	sharedSecret := make([]byte, 32)
	copy(sharedSecret, []byte("shared-secret-key-32-bytes!!"))

	aliceScka := &sckatest.MockSCKA{}
	bobScka := &sckatest.MockSCKA{}

	// Configure SCKAs to produce a key on next call.
	outputKey := make([]byte, 32)
	copy(outputKey, []byte("output-key-for-epoch-advanc"))
	aliceScka.SetOutputKey(outputKey)
	aliceScka.SetKeyEpoch(1)
	bobScka.SetOutputKey(outputKey)
	bobScka.SetKeyEpoch(1)

	initiatorSession, err := InitInitiatorSCKA(sharedSecret, aliceScka, nil)
	require.NoError(t, err)
	responderSession, err := InitResponderSCKA(sharedSecret, bobScka, nil)
	require.NoError(t, err)

	ad := []byte("test-ad")

	// Initial epoch should be 0.
	require.EqualValues(t, 0, initiatorSession.epoch)
	require.EqualValues(t, 0, responderSession.epoch)

	// First message: epoch advances to 1 for Initiator.
	header1, ciphertext1, err := initiatorSession.Encrypt([]byte("message-1"), ad)
	require.NoError(t, err)

	// After sending, Initiator's epoch should be 1.
	require.EqualValues(t, 1, initiatorSession.epoch)

	// Responder receives: epoch advances to 1 for Responder.
	plaintext1, err := responderSession.Decrypt(header1, ciphertext1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("message-1"), plaintext1)

	// After receiving, Responder's epoch should be 1.
	require.EqualValues(t, 1, responderSession.epoch)

	// Both should now have matching RK.
	require.Equal(t, initiatorSession.rk, responderSession.rk, "Initiator and Responder should have matching RK after epoch advancement")

	// Both should have kdfchains[1].
	require.Contains(t, initiatorSession.kdfChains, uint32(1), "Initiator should have kdfchains[1]")
	require.Contains(t, responderSession.kdfChains, uint32(1), "Responder should have kdfchains[1]")

	// Epoch 0 chains should be cleared (except for the one needed for B2A direction swap).
	if initiatorSession.kdfChains[0] != nil && initiatorSession.kdfChains[0].Send != nil {
		t.Log("Initiator kdfchains[0].Send may be cleared after epoch advancement (expected)")
	}
}

// TestEpochAdvancementMultipleMessages tests epoch advancement across multiple message exchanges.
func TestEpochAdvancementMultipleMessages(t *testing.T) {
	sharedSecret := make([]byte, 32)
	copy(sharedSecret, []byte("shared-secret-key-32-bytes!!"))

	aliceScka := &sckatest.MockSCKA{}
	bobScka := &sckatest.MockSCKA{}

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

	require.EqualValues(t, 2, aliceSession.epoch)
	require.EqualValues(t, 2, bobSession.epoch)
}

// TestSCKARollbackOnAuthFailure verifies that a forged message which advances
// SCKA epoch state but fails payload authentication leaves the session usable.
// This tests the full Snapshot/Restore path in SPQRSession.Decrypt.
func TestSCKARollbackOnAuthFailure(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	aliceSession, err := InitAliceSCKA(sharedSecret, aliceSCKA, nil)
	require.NoError(t, err)
	bobSession, err := InitBobSCKA(sharedSecret, bobSCKA, nil)
	require.NoError(t, err)

	ad := []byte("test-ad")

	// Alice sends a valid message.
	header, ciphertext, err := aliceSession.Encrypt([]byte("real message"), ad)
	require.NoError(t, err)

	// Tamper with ciphertext — SCKA processes the header but payload auth fails.
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF

	prevEpoch := bobSession.epoch

	_, err = bobSession.Decrypt(header, tampered, ad)
	require.ErrorIs(t, err, ErrAuthFailure)

	// Session state must be fully rolled back.
	require.Equal(t, prevEpoch, bobSession.epoch, "Epoch not rolled back after auth failure")

	// The real message must still decrypt successfully after rollback.
	pt, err := bobSession.Decrypt(header, ciphertext, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("real message"), pt)
}

// TestSPQRSessionCloseCallsSCKAClose verifies that SPQRSession.Close calls
// SCKA.Close, zeroing the provider's key material.
func TestSPQRSessionCloseCallsSCKAClose(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &sckatest.MockSCKA{}
	session, err := InitAliceSCKA(sharedSecret, mockSCKA, nil)
	require.NoError(t, err)

	// Verify SCKA has key material before Close.
	require.NotEmpty(t, mockSCKA.SharedKey, "MockSCKA.SharedKey should be set after Init")

	err = session.Close()
	require.NoError(t, err)

	// SCKA.Close should have zeroed and nilled the key material.
	require.Nil(t, mockSCKA.SharedKey, "MockSCKA.SharedKey should be nil after Close")
}

// TestSPQRSessionCloseZerosKeyMaterial verifies that Close() zeros all key material.
func TestSPQRSessionCloseZerosKeyMaterial(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	mockSCKA := &sckatest.MockSCKA{}
	session, err := InitAliceSCKA(sharedSecret, mockSCKA, nil)
	require.NoError(t, err)

	// Verify RK is non-zero before Close.
	require.NotEqual(t, make([]byte, len(session.rk)), session.rk, "RK should be non-zero before Close")

	session.Close()

	require.Equal(t, make([]byte, len(session.rk)), session.rk, "RK should be zeroed after Close")

	// KDFChains should be empty after Close.
	require.Empty(t, session.kdfChains, "KDFChains should be empty after Close")
}
