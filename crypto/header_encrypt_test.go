// Package crypto provides tests for header encryption primitives.
package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHENCRYPTHDECRYPTRoundTrip tests that HENCRYPT and HDECRYPT round-trip correctly.
func TestHENCRYPTHDECRYPTRoundTrip(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	header := make([]byte, 40)
	header[0] = 0xA1
	header[36] = 0x01
	header[39] = 0x05

	ct, err := HENCRYPT(&hk, header)
	require.NoError(t, err)

	pt, ok := HDECRYPT(hk.Key, ct)
	require.True(t, ok, "HDECRYPT failed to decrypt")
	require.Equal(t, header, pt)
}

// TestHeaderNonceMonotonicity tests that repeated use of the same header key
// produces different ciphertexts (non-repeating nonces).
func TestHeaderNonceMonotonicity(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	header := make([]byte, 40)
	header[0] = 0xA1

	ciphertexts := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		ct, err := HENCRYPT(&hk, header)
		require.NoError(t, err)
		ciphertexts[i] = ct
	}

	// Nonces (first 16 bytes) must differ between encryptions.
	for i := 1; i < 5; i++ {
		require.NotEqual(t, ciphertexts[0][:16], ciphertexts[i][:16], "nonce collision at iteration %d", i)
	}

	// All ciphertexts must decrypt correctly.
	for i := 0; i < 5; i++ {
		pt, ok := HDECRYPT(hk.Key, ciphertexts[i])
		require.True(t, ok, "HDECRYPT failed at iteration %d", i)
		require.Equal(t, header, pt)
	}
}

// TestHeaderNoncePersistence tests that the nonce counter persists across calls.
func TestHeaderNoncePersistence(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	header := make([]byte, 40)

	_, err := HENCRYPT(&hk, header)
	require.NoError(t, err)
	require.EqualValues(t, 1, hk.NonceCounter)

	_, err = HENCRYPT(&hk, header)
	require.NoError(t, err)
	require.EqualValues(t, 2, hk.NonceCounter)
}

// TestHDECRYPTWrongKeyFails verifies that decryption with a different key fails.
func TestHDECRYPTWrongKeyFails(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}
	wrongKey := [32]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0}

	header := make([]byte, 40)
	ct, err := HENCRYPT(&hk, header)
	require.NoError(t, err)

	pt, ok := HDECRYPT(wrongKey, ct)
	require.False(t, ok, "HDECRYPT should fail with wrong key")
	require.Nil(t, pt)
}

// TestHDECRYPTTamperedFails verifies that tampered ciphertext is rejected.
func TestHDECRYPTTamperedFails(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	header := make([]byte, 40)
	ct, err := HENCRYPT(&hk, header)
	require.NoError(t, err)

	ct[32] ^= 0xFF

	pt, ok := HDECRYPT(hk.Key, ct)
	require.False(t, ok, "HDECRYPT should fail with tampered ciphertext")
	require.Nil(t, pt)
}

// TestHDECRYPTZeroedKeyFails verifies that a zeroed header key is rejected.
func TestHDECRYPTZeroedKeyFails(t *testing.T) {
	var zeroedKey [32]byte
	ct := make([]byte, 64)

	pt, ok := HDECRYPT(zeroedKey, ct)
	require.False(t, ok, "HDECRYPT should fail with zeroed key")
	require.Nil(t, pt)
}
