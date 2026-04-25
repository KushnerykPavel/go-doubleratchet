// Package crypto provides header encryption primitives for the Double Ratchet.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

// HeaderKey represents a header encryption key with a per-key nonce counter.
type HeaderKey struct {
	// Key is the 32-byte header key.
	Key [32]byte
	// NonceCounter is the per-key nonce counter.
	NonceCounter uint64
}

const (
	// HeaderKeySize is the header key size (32 bytes).
	HeaderKeySize = 32
	// HeaderTagSize is the HMAC-SHA256 tag size.
	HeaderTagSize = 32
)

var (
	// headerKeyInfo is the HKDF info constant for header key derivation.
	headerKeyInfo = []byte("DoubleRatchetHeaderKey")
)

// ErrHeaderDecryptionFailed is returned when header decryption fails.
var ErrHeaderDecryptionFailed = errors.New("header decryption failed")

// ErrInvalidHeaderKey is returned when the header key is invalid.
var ErrInvalidHeaderKey = errors.New("invalid header key")

// ErrInvalidNonceCounter is returned when the nonce counter would overflow.
var ErrInvalidNonceCounter = errors.New("invalid nonce counter")

// HENCRYPT encrypts a header using AES-256-CBC + HMAC-SHA256.
//
// Per spec §4.2: HENCRYPT(hk, plaintext) — no associated data parameter.
// hk is the header key with a stateful nonce counter.
// header is the plaintext header bytes.
// Returns encrypted header: nonce (16 bytes) || AES-CBC ciphertext || HMAC tag (32 bytes).
// Increments hk.NonceCounter after use.
func HENCRYPT(hk *HeaderKey, header []byte) ([]byte, error) {
	if isZeroed(hk.Key[:]) {
		return nil, ErrInvalidHeaderKey
	}
	if hk.NonceCounter == math.MaxUint64 {
		return nil, ErrInvalidNonceCounter
	}

	// Build nonce from counter (big-endian) padded to 16 bytes.
	nonce := make([]byte, 16)
	binary.BigEndian.PutUint64(nonce[:8], hk.NonceCounter)

	aesKey, macKey := deriveHeaderKeys(hk.Key[:], headerKeyInfo)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(block, nonce)
	padded := pkcs7Pad(header, aes.BlockSize)
	ct := make([]byte, len(padded))
	cbc.CryptBlocks(ct, padded)

	// MAC covers nonce || ciphertext only (per spec: no AD in HENCRYPT).
	h := hmac.New(sha256.New, macKey)
	h.Write(nonce)
	h.Write(ct)
	tag := h.Sum(nil)

	hk.NonceCounter++

	result := make([]byte, 0, 16+len(ct)+HeaderTagSize)
	result = append(result, nonce...)
	result = append(result, ct...)
	result = append(result, tag...)
	return result, nil
}

// HDECRYPT decrypts an encrypted header.
//
// Per spec §4.2: HDECRYPT(hk, ciphertext) — no associated data parameter.
// hk is the 32-byte header key.
// ciphertext is the encrypted header from HENCRYPT.
// Returns (plaintext, true) on success, (nil, false) on failure or zeroed key.
func HDECRYPT(hk [32]byte, ciphertext []byte) ([]byte, bool) {
	if isZeroed(hk[:]) {
		return nil, false
	}
	if len(ciphertext) < 16+HeaderTagSize {
		return nil, false
	}

	nonce := ciphertext[:16]
	tagOffset := len(ciphertext) - HeaderTagSize
	ct := ciphertext[16:tagOffset]
	tag := ciphertext[tagOffset:]

	aesKey, macKey := deriveHeaderKeys(hk[:], headerKeyInfo)

	h := hmac.New(sha256.New, macKey)
	h.Write(nonce)
	h.Write(ct)
	expected := h.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return nil, false
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, false
	}
	cbc := cipher.NewCBCDecrypter(block, nonce)
	plaintext := make([]byte, len(ct))
	cbc.CryptBlocks(plaintext, ct)

	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, false
	}

	return plaintext, true
}

func deriveHeaderKeys(headerKey []byte, info []byte) ([]byte, []byte) {
	h := hmac.New(sha256.New, headerKey)
	h.Write(info)
	h.Write([]byte("aes"))
	aesKey := h.Sum(nil)

	h = hmac.New(sha256.New, headerKey)
	h.Write(info)
	h.Write([]byte("mac"))
	macKey := h.Sum(nil)

	return aesKey, macKey
}

func isZeroed(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("invalid block size")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding value")
		}
	}
	return data[:len(data)-padding], nil
}
