// Package doubleratchet provides typed message structures for the Double Ratchet.
package doubleratchet

// Header represents the base Double Ratchet message header.
type Header struct {
	// RatchetPublicKey is the sender's current ratchet public key.
	RatchetPublicKey [32]byte

	// PN is the number of messages in the previous sending chain.
	PN uint32

	// N is the current message number in the sending chain.
	N uint32
}

// Message represents an encrypted Double Ratchet message.
type Message struct {
	// Header is the message header.
	Header Header

	// Ciphertext is the encrypted payload.
	Ciphertext []byte
}