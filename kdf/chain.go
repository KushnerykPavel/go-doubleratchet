// Package kdf provides chain key derivation for the Double Ratchet.
package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
)

const (
	// ChainKeySize is the chain key output size (32 bytes).
	ChainKeySize = 32
)

// ChainKDF implements HMAC-SHA256-based chain key derivation.
// Uses distinct derivation constants per Signal spec.
type ChainKDF struct {
	masterKey []byte
}

var (
	// chainConstant is used in chain key derivation (Signal spec: 0x01).
	chainConstant = []byte{0x01}
	// messageKeyConstant is used to derive a message key from a chain key (Signal spec: 0x02).
	messageKeyConstant = []byte{0x02}
)

// NewChainKDF creates a ChainKDF with the given master chain key.
func NewChainKDF(masterKey []byte) *ChainKDF {
	return &ChainKDF{masterKey: masterKey}
}

// DeriveChainKey derives the next chain key from the current chain key.
// Returns new chain key (32 bytes).
func (c *ChainKDF) DeriveChainKey() ([]byte, error) {
	h := hmac.New(sha256.New, c.masterKey)
	h.Write(chainConstant)
	return h.Sum(nil), nil
}

// DeriveMessageKey derives a message key from a chain key.
// Returns 32-byte message key. The chain key is NOT consumed by this call.
// Use DeriveNextChainKey to advance the chain.
func DeriveMessageKey(chainKey []byte) ([]byte, error) {
	h := hmac.New(sha256.New, chainKey)
	h.Write(messageKeyConstant)
	return h.Sum(nil), nil
}

// DeriveNextChainKey derives the next chain key AND the message key in one step.
// Both are derived from the same input chainKey per the Signal spec:
//   - nextChainKey = HMAC(chainKey, 0x01)
//   - messageKey   = HMAC(chainKey, 0x02)
func DeriveNextChainKey(chainKey []byte) (nextChainKey, messageKey []byte, err error) {
	h := hmac.New(sha256.New, chainKey)
	h.Write(chainConstant)
	nextChainKey = h.Sum(nil)

	h = hmac.New(sha256.New, chainKey)
	h.Write(messageKeyConstant)
	messageKey = h.Sum(nil)

	return
}

// ChainKDFDerive performs chain KDF in one call.
// Takes current chain key, returns next chain key and message key.
func ChainKDFDerive(currentChainKey []byte) (nextChainKey, messageKey []byte, err error) {
	return DeriveNextChainKey(currentChainKey)
}
