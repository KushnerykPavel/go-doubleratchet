package doubleratchet

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
	"github.com/KushnerykPavel/go-doubleratchet/internal/kdf"
	sckatest "github.com/KushnerykPavel/go-doubleratchet/scka/testing"
)

// --- Helpers ---

func newTRPair(t *testing.T) (alice, bob *TripleRatchetSession) {
	t.Helper()

	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	alice, err = InitAliceTripleRatchet(sharedSecret, bobPubKey, aliceSCKA, nil)
	require.NoError(t, err)
	bob, err = InitBobTripleRatchet(sharedSecret, bobKeyPair, bobSCKA, nil)
	require.NoError(t, err)
	return alice, bob
}

// --- Initialization ---

// TestTRInitExpandsSKIntoDistinctComponents verifies that expandSK produces
// different SKec and SKscka from the same root secret.
func TestTRInitExpandsSKIntoDistinctComponents(t *testing.T) {
	sk := bytes.Repeat([]byte{0xAB}, 32)

	skec, skscka, err := expandSK(sk)
	require.NoError(t, err)

	require.Len(t, skec, 32)
	require.Len(t, skscka, 32)
	require.NotEqual(t, skec, skscka, "SKec and SKscka must differ")
	require.NotEqual(t, skec, sk, "expanded keys must differ from input SK")
	require.NotEqual(t, skscka, sk, "expanded keys must differ from input SK")
}

// TestTRInitAliceHasDhRSet verifies Alice's DR component has DHr set after init.
func TestTRInitAliceHasDhRSet(t *testing.T) {
	alice, _ := newTRPair(t)
	require.True(t, alice.dr.dhRSet, "Alice DR should have dhRSet=true after InitAliceTripleRatchet")
}

// TestTRInitBobDhRNotSet verifies Bob's DR component has DHr unset after init.
func TestTRInitBobDhRNotSet(t *testing.T) {
	_, bob := newTRPair(t)
	require.False(t, bob.dr.dhRSet, "Bob DR should have dhRSet=false after InitBobTripleRatchet")
}

// TestTRAliceBobDeriveMatchingDRComponents verifies that Alice and Bob derive
// matching DR CKs/CKr for the EC component.
func TestTRAliceBobDeriveMatchingDRComponents(t *testing.T) {
	// Can't directly compare DR state since Alice does the first DH step.
	// Instead verify a round-trip works correctly.
	alice, bob := newTRPair(t)
	ad := []byte("tr-ad")

	msg, err := alice.Encrypt([]byte("hello"), ad)
	require.NoError(t, err)
	pt, err := bob.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}

// --- Hybrid key derivation ---

// TestKDFHybridProducesDistinctOutputForDifferentInputs verifies KDF_HYBRID
// is sensitive to changes in either key.
func TestKDFHybridProducesDistinctOutputForDifferentInputs(t *testing.T) {
	ecKey := bytes.Repeat([]byte{0x01}, 32)
	pqKey := bytes.Repeat([]byte{0x02}, 32)
	info := []byte("DoubleRatchetHybrid")

	mk1, err := kdf.Hybrid(pqKey, ecKey, info)
	require.NoError(t, err)

	// Different EC key.
	ecKey2 := bytes.Repeat([]byte{0x03}, 32)
	mk2, err := kdf.Hybrid(pqKey, ecKey2, info)
	require.NoError(t, err)
	require.NotEqual(t, mk1, mk2, "different EC keys must produce different combined keys")

	// Different PQ key.
	pqKey2 := bytes.Repeat([]byte{0x04}, 32)
	mk3, err := kdf.Hybrid(pqKey2, ecKey, info)
	require.NoError(t, err)
	require.NotEqual(t, mk1, mk3, "different PQ keys must produce different combined keys")

	// Different info.
	mk4, err := kdf.Hybrid(pqKey, ecKey, []byte("other"))
	require.NoError(t, err)
	require.NotEqual(t, mk1, mk4, "different info must produce different combined keys")
}

// TestKDFHybridPQKeyIsSalt verifies spec §7 ordering: PQ key is salt, EC key is IKM.
// Swapping salt and IKM must produce a different key.
func TestKDFHybridPQKeyIsSalt(t *testing.T) {
	ecKey := bytes.Repeat([]byte{0xAA}, 32)
	pqKey := bytes.Repeat([]byte{0xBB}, 32)
	info := []byte("DoubleRatchetHybrid")

	// pqKey=salt, ecKey=IKM (correct per spec)
	mk1, _ := kdf.Hybrid(pqKey, ecKey, info)
	// pqKey=IKM, ecKey=salt (inverted)
	mk2, _ := kdf.Hybrid(ecKey, pqKey, info)

	require.NotEqual(t, mk1, mk2, "swapping salt/IKM must produce different key — KDF_HYBRID arg order matters")
}

// --- Basic round-trips ---

// TestTREncryptDecryptRoundTrip tests basic Alice→Bob message.
func TestTREncryptDecryptRoundTrip(t *testing.T) {
	alice, bob := newTRPair(t)
	ad := []byte("tr-ad")
	plaintext := []byte("hello triple ratchet")

	msg, err := alice.Encrypt(plaintext, ad)
	require.NoError(t, err)
	require.NotNil(t, msg.Header.SCKA, "SCKA header must be non-nil")

	pt, err := bob.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, plaintext, pt)
}

// TestTRBidirectionalExchange tests full Alice↔Bob conversation.
func TestTRBidirectionalExchange(t *testing.T) {
	alice, bob := newTRPair(t)
	ad := []byte("tr-ad")

	// Alice → Bob
	msg1, err := alice.Encrypt([]byte("msg1"), ad)
	require.NoError(t, err)
	pt1, err := bob.Decrypt(msg1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("msg1"), pt1)

	// Bob → Alice
	msg2, err := bob.Encrypt([]byte("msg2"), ad)
	require.NoError(t, err)
	pt2, err := alice.Decrypt(msg2, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("msg2"), pt2)

	// Alice → Bob again (after DH ratchet)
	msg3, err := alice.Encrypt([]byte("msg3"), ad)
	require.NoError(t, err)
	pt3, err := bob.Decrypt(msg3, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("msg3"), pt3)
}

// TestTRMultipleMessages tests that sequential messages each have unique ciphertext.
func TestTRMultipleMessages(t *testing.T) {
	alice, bob := newTRPair(t)
	ad := []byte("tr-ad")

	plaintext := []byte("same plaintext")
	var msgs [3]TripleRatchetMessage

	for i := range msgs {
		var err error
		msgs[i], err = alice.Encrypt(plaintext, ad)
		require.NoError(t, err, "Alice Encrypt %d", i)
	}

	// Each ciphertext must be unique (different message keys each time).
	require.NotEqual(t, msgs[0].Ciphertext, msgs[1].Ciphertext, "successive messages must produce different ciphertexts")
	require.NotEqual(t, msgs[1].Ciphertext, msgs[2].Ciphertext, "successive messages must produce different ciphertexts")

	// All must decrypt correctly.
	for i, msg := range msgs {
		pt, err := bob.Decrypt(msg, ad)
		require.NoError(t, err, "Bob Decrypt %d", i)
		require.Equal(t, plaintext, pt, "msg %d plaintext mismatch", i)
	}
}

// --- Out-of-order handling ---

// TestTROutOfOrderMessages verifies delayed same-chain message decryption.
func TestTROutOfOrderMessages(t *testing.T) {
	alice, bob := newTRPair(t)
	ad := []byte("tr-ad")

	msg0, err := alice.Encrypt([]byte("msg0"), ad)
	require.NoError(t, err)
	msg1, err := alice.Encrypt([]byte("msg1"), ad)
	require.NoError(t, err)

	// Receive out of order: msg1 first, then msg0.
	pt1, err := bob.Decrypt(msg1, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("msg1"), pt1)

	pt0, err := bob.Decrypt(msg0, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("msg0"), pt0)
}

// --- Authentication ---

// TestTRWrongADFails verifies that mismatched AD causes auth failure.
func TestTRWrongADFails(t *testing.T) {
	alice, bob := newTRPair(t)

	msg, err := alice.Encrypt([]byte("secret"), []byte("correct-ad"))
	require.NoError(t, err)

	_, err = bob.Decrypt(msg, []byte("wrong-ad"))
	require.Error(t, err, "Decrypt with wrong AD must fail")
}

// TestTRTamperedCiphertextFails verifies that ciphertext tampering is detected.
func TestTRTamperedCiphertextFails(t *testing.T) {
	alice, bob := newTRPair(t)
	ad := []byte("ad")

	msg, err := alice.Encrypt([]byte("secret"), ad)
	require.NoError(t, err)

	msg.Ciphertext[0] ^= 0xFF

	_, err = bob.Decrypt(msg, ad)
	require.ErrorIs(t, err, ErrAuthFailure)
}

// TestTRAuthFailureRollbackAllowsRetry verifies that after auth failure both
// EC and PQ state are rolled back so the real message still decrypts.
func TestTRAuthFailureRollbackAllowsRetry(t *testing.T) {
	alice, bob := newTRPair(t)
	ad := []byte("ad")

	msg, err := alice.Encrypt([]byte("real"), ad)
	require.NoError(t, err)

	// Forge a tampered copy.
	tampered := TripleRatchetMessage{
		Header:     msg.Header,
		Ciphertext: append([]byte(nil), msg.Ciphertext...),
	}
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0xFF

	_, err = bob.Decrypt(tampered, ad)
	require.ErrorIs(t, err, ErrAuthFailure)

	// Real message must still decrypt after rollback.
	pt, err := bob.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("real"), pt)
}

// --- Hybrid security property ---

// TestTRCombinedKeyDiffersFromComponents verifies that the combined key is not
// equal to either component key — the KDF_HYBRID step is actually doing work.
func TestTRCombinedKeyDiffersFromComponents(t *testing.T) {
	ec := bytes.Repeat([]byte{0x11}, 32)
	pq := bytes.Repeat([]byte{0x22}, 32)
	info := []byte("DoubleRatchetHybrid")

	combined, err := kdf.Hybrid(pq, ec, info)
	require.NoError(t, err)
	require.NotEqual(t, combined, ec, "combined key must differ from EC key")
	require.NotEqual(t, combined, pq, "combined key must differ from PQ key")
}

// TestTRHeaderEncoding verifies that encodeTRHeader is deterministic and
// covers both EC and SCKA header fields.
func TestTRHeaderEncoding(t *testing.T) {
	var ecPK [32]byte
	for i := range ecPK {
		ecPK[i] = byte(i)
	}
	header := TripleRatchetHeader{
		EC:   Header{RatchetPublicKey: ecPK, PN: 3, N: 7},
		SCKA: &SCKAHeader{Msg: []byte("scka-msg"), N: 2},
	}

	b1, err := encodeTRHeader(header)
	require.NoError(t, err)
	b2, err := encodeTRHeader(header)
	require.NoError(t, err)
	require.Equal(t, b1, b2, "encodeTRHeader must be deterministic")
	// Must be at least 40 (EC) + 4 + 8 + 4 (SCKA) = 56 bytes.
	require.GreaterOrEqual(t, len(b1), 56, "header encoding too short")
}

// --- Epoch advancement ---

// TestTREpochAdvancement verifies that when SCKA produces a new epoch key,
// the Triple Ratchet session advances correctly and messages still decrypt.
func TestTREpochAdvancement(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPrivKey, bobPubKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	bobKeyPair := crypto.KeyPair{PrivateKey: bobPrivKey, PublicKey: bobPubKey}

	outputKey := bytes.Repeat([]byte{0x42}, 32)
	aliceSCKA := &sckatest.MockSCKA{}
	aliceSCKA.SetOutputKey(outputKey)
	aliceSCKA.SetKeyEpoch(1)
	bobSCKA := &sckatest.MockSCKA{}
	bobSCKA.SetOutputKey(outputKey)
	bobSCKA.SetKeyEpoch(1)

	alice, err := InitAliceTripleRatchet(sharedSecret, bobPubKey, aliceSCKA, nil)
	require.NoError(t, err)
	bob, err := InitBobTripleRatchet(sharedSecret, bobKeyPair, bobSCKA, nil)
	require.NoError(t, err)

	ad := []byte("epoch-ad")
	msg, err := alice.Encrypt([]byte("epoch-msg"), ad)
	require.NoError(t, err)

	require.EqualValues(t, 1, alice.spqr.epoch, "Alice SPQR epoch should advance to 1")

	pt, err := bob.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("epoch-msg"), pt)
	require.EqualValues(t, 1, bob.spqr.epoch, "Bob SPQR epoch should advance to 1")
}

// --- Close ---

// TestTRCloseZerosKeyMaterial verifies that Close zeros all key material
// in both EC and PQ components.
func TestTRCloseZerosKeyMaterial(t *testing.T) {
	alice, _ := newTRPair(t)

	err := alice.Close()
	require.NoError(t, err)

	require.Equal(t, make([]byte, len(alice.dr.rk)), alice.dr.rk, "DR.rk should be zeroed after Close")
	require.Equal(t, make([]byte, len(alice.dr.cks)), alice.dr.cks, "DR.cks should be zeroed after Close")
	require.Equal(t, make([]byte, len(alice.spqr.rk)), alice.spqr.rk, "SPQR.rk should be zeroed after Close")
}

// TestTRBobCannotEncryptBeforeReceiving verifies that Bob's DR component
// returns ErrSessionNotInitialized if RatchetSendKey is called before
// receiving Alice's first message.
func TestTRBobCannotEncryptBeforeReceiving(t *testing.T) {
	_, bob := newTRPair(t)
	_, err := bob.Encrypt([]byte("premature"), []byte("ad"))
	require.ErrorIs(t, err, ErrSessionNotInitialized)
}

// TestTRInvalidInputNilSCKAHeader verifies that Decrypt rejects messages
// with a nil SCKA header component.
func TestTRInvalidInputNilSCKAHeader(t *testing.T) {
	_, bob := newTRPair(t)
	msg := TripleRatchetMessage{
		Header:     TripleRatchetHeader{SCKA: nil},
		Ciphertext: []byte("ct"),
	}
	_, err := bob.Decrypt(msg, []byte("ad"))
	require.ErrorIs(t, err, ErrInvalidInput)
}
