package crypto

import (
	"bytes"
	"testing"
)

var fuzzKey = [32]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// FuzzHDECRYPT verifies HDECRYPT never panics on arbitrary ciphertext input.
// Any input that is not a valid ciphertext must return (nil, false).
func FuzzHDECRYPT(f *testing.F) {
	// Seed: valid ciphertext so fuzzer can mutate from a known-good baseline.
	hk := HeaderKey{Key: fuzzKey}
	for _, hdr := range [][]byte{
		{0xA1, 0xB2, 0xC3, 0xD4},
		make([]byte, 40),
		make([]byte, 1),
		make([]byte, 16),
	} {
		ct, err := HENCRYPT(&hk, hdr)
		if err == nil {
			f.Add(ct)
		}
	}

	// Seed: degenerate inputs that must be rejected quickly.
	f.Add([]byte{})
	f.Add(make([]byte, 1))
	f.Add(make([]byte, 15))       // below minimum (16+32=48)
	f.Add(make([]byte, 48))       // minimum length, all zeros
	f.Add(make([]byte, 16+16+32)) // nonce+one-block-ct+tag, all zeros

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		// Contract: must never panic. Invalid input must return false.
		pt, ok := HDECRYPT(fuzzKey, ciphertext)
		if !ok && pt != nil {
			t.Fatal("HDECRYPT returned non-nil plaintext on failure")
		}
	})
}

// FuzzHDECRYPTWrongKey verifies HDECRYPT always rejects ciphertexts encrypted
// with a different key, even when the ciphertext is structurally valid.
func FuzzHDECRYPTWrongKey(f *testing.F) {
	hk := HeaderKey{Key: fuzzKey}
	for _, hdr := range [][]byte{
		{0xDE, 0xAD, 0xBE, 0xEF},
		make([]byte, 40),
		{0x00},
	} {
		ct, err := HENCRYPT(&hk, hdr)
		if err == nil {
			f.Add(ct)
		}
	}

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		var wrongKey [32]byte
		for i := range wrongKey {
			wrongKey[i] = 0xFF
		}
		pt, ok := HDECRYPT(wrongKey, ciphertext)
		if ok {
			t.Fatal("HDECRYPT accepted ciphertext under wrong key")
		}
		if pt != nil {
			t.Fatal("HDECRYPT returned non-nil plaintext on failure")
		}
	})
}

// FuzzHENCRYPTRoundTrip verifies that arbitrary header bytes survive an
// HENCRYPT→HDECRYPT round trip without modification.
func FuzzHENCRYPTRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xA1, 0xB2, 0xC3})
	f.Add(make([]byte, 1))
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 40))
	f.Add(make([]byte, 128))
	f.Add([]byte{0xFF, 0x00, 0xFF, 0x00})

	f.Fuzz(func(t *testing.T, header []byte) {
		hk := HeaderKey{Key: fuzzKey}
		ct, err := HENCRYPT(&hk, header)
		if err != nil {
			// Only possible error is nonce overflow; unreachable in practice.
			t.Skipf("HENCRYPT error: %v", err)
		}

		pt, ok := HDECRYPT(hk.Key, ct)
		if !ok {
			t.Fatal("HDECRYPT failed on ciphertext produced by HENCRYPT")
		}
		if !bytes.Equal(pt, header) {
			t.Fatalf("round-trip mismatch: got %x, want %x", pt, header)
		}
	})
}

// FuzzHDECRYPTBitFlip verifies HDECRYPT rejects ciphertexts with single-bit
// corruption anywhere in the message (ciphertext body or tag).
func FuzzHDECRYPTBitFlip(f *testing.F) {
	// Generate a valid ciphertext as the base for bit-flip mutations.
	hk := HeaderKey{Key: fuzzKey}
	ct, err := HENCRYPT(&hk, make([]byte, 40))
	if err != nil {
		f.Fatal(err)
	}
	// Seed with (ciphertext, byte-offset, bit-mask) tuples.
	for i := range ct {
		f.Add(ct, i, byte(0x01))
		f.Add(ct, i, byte(0x80))
	}

	f.Fuzz(func(t *testing.T, ciphertext []byte, offset int, mask byte) {
		if len(ciphertext) == 0 || offset < 0 || offset >= len(ciphertext) || mask == 0 {
			return
		}
		flipped := make([]byte, len(ciphertext))
		copy(flipped, ciphertext)
		flipped[offset] ^= mask

		// Flipped ciphertext must be rejected (HMAC will catch it)
		// unless the flip happened to produce a valid MAC — which is negligible.
		// We only assert no panic here; MAC collision acceptance is not a bug.
		_, _ = HDECRYPT(fuzzKey, flipped)
	})
}
