package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
)

const (
	// ChainKeySize is the chain key output size (32 bytes).
	ChainKeySize = 32
)

var (
	// chainConstant is used in chain key derivation (Signal spec: 0x02).
	chainConstant = []byte{0x02}
	// messageKeyConstant is used to derive a message key from a chain key (Signal spec: 0x01).
	messageKeyConstant = []byte{0x01}
)

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
//   - messageKey   = HMAC(chainKey, 0x01)
//   - nextChainKey = HMAC(chainKey, 0x02)
func DeriveNextChainKey(chainKey []byte) (nextChainKey, messageKey []byte, err error) {
	h := hmac.New(sha256.New, chainKey)
	h.Write(chainConstant)
	nextChainKey = h.Sum(nil)

	h = hmac.New(sha256.New, chainKey)
	h.Write(messageKeyConstant)
	messageKey = h.Sum(nil)

	return nextChainKey, messageKey, nil
}
