// Package doubleratchet provides header encryption types for the Double Ratchet.
package doubleratchet

import "doubleratchet/internal/crypto"

// HeaderKey represents a header encryption/decryption key with nonce counter.
// Alias for internal crypto HeaderKey for API exposure.
type HeaderKey = crypto.HeaderKey

// NextHeaderKey represents the next header key for the receiving side.
type NextHeaderKey = crypto.HeaderKey

// EncryptedHeader represents an encrypted message header.
type EncryptedHeader struct {
	// Ciphertext is the encrypted header bytes.
	Ciphertext []byte
}