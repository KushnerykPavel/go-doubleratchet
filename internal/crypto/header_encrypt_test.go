// Package crypto provides tests for header encryption primitives.
package crypto

import (
	"bytes"
	"testing"
)

// TestHENCRYPTHDECRYPTRoundTrip tests that HENCRYPT and HDECRYPT round-trip correctly.
func TestHENCRYPTHDECRYPTRoundTrip(t *testing.T) {
	// Create a header key.
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	// Sample header bytes (40 bytes: 32 dh + 4 pn + 4 n).
	header := make([]byte, 40)
	header[0] = 0xA1
	header[36] = 0x01
	header[39] = 0x05

	ad := []byte("additional data")

	// Encrypt.
	ct, err := HENCRYPT(&hk, header, ad)
	if err != nil {
		t.Fatalf("HENCRYPT failed: %v", err)
	}

	// Decrypt.
	pt, ok := HDECRYPT(hk.Key, ct, ad)
	if !ok {
		t.Fatal("HDECRYPT failed to decrypt")
	}

	// Verify round-trip.
	if !bytes.Equal(pt, header) {
		t.Errorf("HDECRYPT output mismatch\ngot:  %x\nwant: %x", pt, header)
	}
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
	ad := []byte("additional data")

	// Encrypt same header multiple times.
	ciphertexts := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		ct, err := HENCRYPT(&hk, header, ad)
		if err != nil {
			t.Fatalf("HENCRYPT failed at iteration %d: %v", i, err)
		}
		ciphertexts[i] = ct
	}

	// Verify nonces are different (first 16 bytes).
	for i := 1; i < 5; i++ {
		if bytes.Equal(ciphertexts[0][:16], ciphertexts[i][:16]) {
			t.Errorf("Nonce collision detected at iteration %d: same nonce reused", i)
		}
	}

	// Verify all ciphertexts decrypt correctly.
	for i := 0; i < 5; i++ {
		pt, ok := HDECRYPT(hk.Key, ciphertexts[i], ad)
		if !ok {
			t.Errorf("HDECRYPT failed to decrypt ciphertext %d", i)
		}
		if !bytes.Equal(pt, header) {
			t.Errorf("HDECRYPT output mismatch at iteration %d", i)
		}
	}
}

// TestHeaderNoncePersistence tests that the nonce counter persists across calls.
func TestHeaderNoncePersistence(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	header := make([]byte, 40)
	ad := []byte("test ad")

	// Encrypt first message.
	_, err := HENCRYPT(&hk, header, ad)
	if err != nil {
		t.Fatalf("First HENCRYPT failed: %v", err)
	}

	if hk.NonceCounter != 1 {
		t.Errorf("NonceCounter = %d, want 1", hk.NonceCounter)
	}

	// Encrypt second message.
	_, err = HENCRYPT(&hk, header, ad)
	if err != nil {
		t.Fatalf("Second HENCRYPT failed: %v", err)
	}

	if hk.NonceCounter != 2 {
		t.Errorf("NonceCounter = %d, want 2", hk.NonceCounter)
	}
}

// TestHDECRYPTWrongKeyFails tests that decryption with wrong key fails.
func TestHDECRYPTWrongKeyFails(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	wrongKey := [32]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0}

	header := make([]byte, 40)
	ad := []byte("test ad")

	ct, err := HENCRYPT(&hk, header, ad)
	if err != nil {
		t.Fatalf("HENCRYPT failed: %v", err)
	}

	// Try decrypt with wrong key.
	pt, ok := HDECRYPT(wrongKey, ct, ad)
	if ok {
		t.Error("HDECRYPT should fail with wrong key")
	}
	if pt != nil {
		t.Error("HDECRYPT should return nil on failure")
	}
}

// TestHDECRYPTTamperedFails tests that decryption with tampered ciphertext fails.
func TestHDECRYPTTamperedFails(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	header := make([]byte, 40)
	ad := []byte("test ad")

	ct, err := HENCRYPT(&hk, header, ad)
	if err != nil {
		t.Fatalf("HENCRYPT failed: %v", err)
	}

	// Tamper with ciphertext.
	ct[32] ^= 0xFF

	pt, ok := HDECRYPT(hk.Key, ct, ad)
	if ok {
		t.Error("HDECRYPT should fail with tampered ciphertext")
	}
	if pt != nil {
		t.Error("HDECRYPT should return nil on failure")
	}
}

// TestHDECRYPTWrongADFails tests that decryption with wrong AD fails.
func TestHDECRYPTWrongADFails(t *testing.T) {
	hk := HeaderKey{
		Key:          [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		NonceCounter: 0,
	}

	header := make([]byte, 40)
	ad := []byte("correct ad")
	wrongAd := []byte("wrong ad")

	ct, err := HENCRYPT(&hk, header, ad)
	if err != nil {
		t.Fatalf("HENCRYPT failed: %v", err)
	}

	pt, ok := HDECRYPT(hk.Key, ct, wrongAd)
	if ok {
		t.Error("HDECRYPT should fail with wrong AD")
	}
	if pt != nil {
		t.Error("HDECRYPT should return nil on failure")
	}
}

// TestHDECRYPTZeroedKeyFails tests that decryption with zeroed key fails.
func TestHDECRYPTZeroedKeyFails(t *testing.T) {
	zeroedKey := [32]byte{0}

	ct := make([]byte, 64)
	ad := []byte("test ad")

	pt, ok := HDECRYPT(zeroedKey, ct, ad)
	if ok {
		t.Error("HDECRYPT should fail with zeroed key")
	}
	if pt != nil {
		t.Error("HDECRYPT should return nil on failure")
	}
}
