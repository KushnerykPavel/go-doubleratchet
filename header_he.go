package doubleratchet

import (
	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
)

// HeaderKey represents a header encryption/decryption key with nonce counter.
// Alias for internal crypto HeaderKey for API exposure.
type HeaderKey = crypto.HeaderKey

// EncryptedHeader represents an encrypted message header.
type EncryptedHeader struct {
	// Ciphertext is the encrypted header bytes.
	Ciphertext []byte
}
