// Package doubleratchet_test provides runnable examples for all four protocol variants.
package doubleratchet_test

import (
	"fmt"

	doubleratchet "github.com/KushnerykPavel/go-doubleratchet"
	sckatest "github.com/KushnerykPavel/go-doubleratchet/scka/testing"
)

// ExampleInitAlice demonstrates the base Double Ratchet protocol (spec §3).
// Alice and Bob exchange messages with forward secrecy and break-in recovery.
func ExampleInitAlice() {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	// Bob generates his initial ratchet key pair.
	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	bobKeyPair := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}

	// Initialize sessions.
	alice, err := doubleratchet.InitAlice(sharedSecret, bobPub, nil)
	if err != nil {
		panic(err)
	}
	defer alice.Close()

	bob, err := doubleratchet.InitBob(sharedSecret, bobKeyPair, nil)
	if err != nil {
		panic(err)
	}
	defer bob.Close()

	ad := []byte("example-ad")

	// Alice → Bob
	msg, err := alice.Encrypt([]byte("hello"), ad)
	if err != nil {
		panic(err)
	}
	plaintext, err := bob.Decrypt(msg, ad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))

	// Bob → Alice (triggers DH ratchet on both sides)
	reply, err := bob.Encrypt([]byte("world"), ad)
	if err != nil {
		panic(err)
	}
	replyPT, err := alice.Decrypt(reply, ad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(replyPT))

	// Output:
	// hello
	// world
}

// ExampleInitAliceHE demonstrates the Double Ratchet with Header Encryption (spec §4).
// Message headers are encrypted, hiding session membership and ordering from eavesdroppers.
func ExampleInitAliceHE() {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	// Shared header keys negotiated out-of-band.
	var sharedHKA, sharedNHKB [32]byte
	for i := range sharedHKA {
		sharedHKA[i] = byte(i + 0xA0)
		sharedNHKB[i] = byte(i + 0xB0)
	}

	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	bobKeyPair := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}

	alice, err := doubleratchet.InitAliceHE(sharedSecret, bobPub, sharedHKA, sharedNHKB, nil)
	if err != nil {
		panic(err)
	}
	defer alice.Close()

	bob, err := doubleratchet.InitBobHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, nil)
	if err != nil {
		panic(err)
	}
	defer bob.Close()

	ad := []byte("example-ad")

	encHeader, msg, err := alice.EncryptHE([]byte("secret"), ad)
	if err != nil {
		panic(err)
	}

	plaintext, err := bob.DecryptHE(encHeader, msg, ad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))

	// Output:
	// secret
}

// ExampleInitAliceSCKA demonstrates the Sparse Post-Quantum Ratchet (spec §5).
// The SCKA provider drives epoch-based post-quantum ratcheting.
func ExampleInitAliceSCKA() {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	// Use the mock SCKA provider (for testing only; use a real PQ implementation in production).
	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	alice, err := doubleratchet.InitAliceSCKA(sharedSecret, aliceSCKA, nil)
	if err != nil {
		panic(err)
	}
	defer alice.Close()

	bob, err := doubleratchet.InitBobSCKA(sharedSecret, bobSCKA, nil)
	if err != nil {
		panic(err)
	}
	defer bob.Close()

	ad := []byte("example-ad")

	header, ciphertext, err := alice.Encrypt([]byte("pq-hello"), ad)
	if err != nil {
		panic(err)
	}

	plaintext, err := bob.Decrypt(header, ciphertext, ad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))

	// Output:
	// pq-hello
}

// ExampleInitAliceTripleRatchet demonstrates the Triple Ratchet (spec §6).
// EC and PQ keys are combined via KDF_HYBRID so both must be compromised to break security.
func ExampleInitAliceTripleRatchet() {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	bobPriv, bobPub, err := doubleratchet.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	bobKeyPair := doubleratchet.KeyPair{PrivateKey: bobPriv, PublicKey: bobPub}

	aliceSCKA := &sckatest.MockSCKA{}
	bobSCKA := &sckatest.MockSCKA{}

	alice, err := doubleratchet.InitAliceTripleRatchet(sharedSecret, bobPub, aliceSCKA, nil)
	if err != nil {
		panic(err)
	}
	defer alice.Close()

	bob, err := doubleratchet.InitBobTripleRatchet(sharedSecret, bobKeyPair, bobSCKA, nil)
	if err != nil {
		panic(err)
	}
	defer bob.Close()

	ad := []byte("example-ad")

	msg, err := alice.Encrypt([]byte("hybrid-hello"), ad)
	if err != nil {
		panic(err)
	}

	plaintext, err := bob.Decrypt(msg, ad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))

	// Output:
	// hybrid-hello
}
