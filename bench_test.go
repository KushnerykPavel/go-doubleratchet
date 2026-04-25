package doubleratchet_test

import (
	"testing"

	doubleratchet "github.com/KushnerykPavel/go-doubleratchet"
	sckatest "github.com/KushnerykPavel/go-doubleratchet/scka/testing"
)

func newBaseSession(b *testing.B) (alice, bob *doubleratchet.Session) {
	b.Helper()
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}
	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	bobKP := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}
	alice, err = doubleratchet.InitAlice(sharedSecret, bobPub, nil)
	if err != nil {
		b.Fatal(err)
	}
	bob, err = doubleratchet.InitBob(sharedSecret, bobKP, nil)
	if err != nil {
		b.Fatal(err)
	}
	return alice, bob
}

// BenchmarkEncrypt measures the steady-state Encrypt throughput for the base Double Ratchet.
func BenchmarkEncrypt(b *testing.B) {
	alice, bob := newBaseSession(b)
	defer alice.Close()
	defer bob.Close()

	ad := []byte("bench-ad")
	plaintext := []byte("benchmark message payload")

	// Warm up: perform one exchange so Alice has a receive chain.
	msg, err := alice.Encrypt(plaintext, ad)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := bob.Decrypt(msg, ad); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, err := alice.Encrypt(plaintext, ad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecrypt measures the steady-state Decrypt throughput for the base Double Ratchet.
func BenchmarkDecrypt(b *testing.B) {
	alice, bob := newBaseSession(b)
	defer alice.Close()
	defer bob.Close()

	ad := []byte("bench-ad")
	plaintext := []byte("benchmark message payload")

	// Pre-encrypt all messages before timing decryption.
	msgs := make([]doubleratchet.Message, b.N)
	for i := range msgs {
		var err error
		msgs[i], err = alice.Encrypt(plaintext, ad)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for _, m := range msgs {
		_, err := bob.Decrypt(m, ad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptHE measures the steady-state EncryptHE throughput for the header-encryption variant.
func BenchmarkEncryptHE(b *testing.B) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}
	var sharedHKA, sharedNHKB [32]byte
	for i := range sharedHKA {
		sharedHKA[i] = byte(i + 0xA0)
		sharedNHKB[i] = byte(i + 0xB0)
	}
	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	bobKP := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}
	alice, err := doubleratchet.InitAliceHE(sharedSecret, bobPub, sharedHKA, sharedNHKB, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer alice.Close()
	bob, err := doubleratchet.InitBobHE(sharedSecret, bobKP, sharedHKA, sharedNHKB, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer bob.Close()

	ad := []byte("bench-ad")
	plaintext := []byte("benchmark message payload")

	// Warm up.
	encHdr, msg, err := alice.EncryptHE(plaintext, ad)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := bob.DecryptHE(encHdr, msg, ad); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, _, err := alice.EncryptHE(plaintext, ad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptSPQR measures the steady-state Encrypt throughput for the SPQR variant.
func BenchmarkEncryptSPQR(b *testing.B) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}
	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	alice, err := doubleratchet.InitAliceSCKA(sharedSecret, aliceSCKA, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer alice.Close()
	bob, err := doubleratchet.InitBobSCKA(sharedSecret, bobSCKA, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer bob.Close()

	ad := []byte("bench-ad")
	plaintext := []byte("benchmark message payload")

	// Warm up.
	hdr, ct, err := alice.Encrypt(plaintext, ad)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := bob.Decrypt(hdr, ct, ad); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, _, err := alice.Encrypt(plaintext, ad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptTriple measures the steady-state Encrypt throughput for the Triple Ratchet.
func BenchmarkEncryptTriple(b *testing.B) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}
	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	bobKP := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	alice, err := doubleratchet.InitAliceTripleRatchet(sharedSecret, bobPub, aliceSCKA, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer alice.Close()
	bob, err := doubleratchet.InitBobTripleRatchet(sharedSecret, bobKP, bobSCKA, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer bob.Close()

	ad := []byte("bench-ad")
	plaintext := []byte("benchmark message payload")

	// Warm up.
	msg, err := alice.Encrypt(plaintext, ad)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := bob.Decrypt(msg, ad); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, err := alice.Encrypt(plaintext, ad)
		if err != nil {
			b.Fatal(err)
		}
	}
}
