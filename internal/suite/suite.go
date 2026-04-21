// Package suite provides the internal AES-256-CBC + HMAC-SHA256 encryption suite.
package suite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
)

// NonceSize is the AES-CBC IV size.
const NonceSize = 16

// TagSize is the HMAC-SHA256 tag size.
const TagSize = 32

// KeySize is the total key size (32-byte AES key + 32-byte HMAC key).
const KeySize = 64

var errCiphertextShort = errors.New("ciphertext too short")

// Encrypt encrypts plaintext using AES-256-CBC and authenticates with HMAC-SHA256.
// key must be KeySize bytes: first 32 bytes for AES, next 32 for HMAC.
// ad is authenticated data (included in HMAC but not encrypted).
// Returns ciphertext: nonce (16 bytes) || AES-CBC ciphertext || HMAC tag (32 bytes).
func Encrypt(key, plaintext, ad []byte) ([]byte, error) {
	if len(key) < KeySize {
		return nil, fmt.Errorf("key too short: need %d bytes", KeySize)
	}
	aesKey := key[:32]
	macKey := key[32:64]

	// Generate random nonce.
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(block, nonce)

	// Pad plaintext using PKCS7.
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ct := make([]byte, len(padded))
	cbc.CryptBlocks(ct, padded)

	// Compute HMAC over nonce || ciphertext || ad.
	h := hmac.New(sha256.New, macKey)
	h.Write(nonce)
	h.Write(ct)
	h.Write(ad)
	tag := h.Sum(nil)

	// Output: nonce || ciphertext || tag.
	result := make([]byte, 0, NonceSize+len(ct)+TagSize)
	result = append(result, nonce...)
	result = append(result, ct...)
	result = append(result, tag...)
	return result, nil
}

// Decrypt decrypts and authenticates ciphertext produced by Encrypt.
// key must be KeySize bytes. ad is the associated data.
// Returns plaintext on success.
func Decrypt(key, ciphertext, ad []byte) ([]byte, error) {
	if len(key) < KeySize {
		return nil, fmt.Errorf("key too short: need %d bytes", KeySize)
	}
	if len(ciphertext) < NonceSize+TagSize {
		return nil, errCiphertextShort
	}
	aesKey := key[:32]
	macKey := key[32:64]

	nonce := ciphertext[:NonceSize]
	tagOffset := len(ciphertext) - TagSize
	ct := ciphertext[NonceSize:tagOffset]
	tag := ciphertext[tagOffset:]

	// Verify HMAC.
	h := hmac.New(sha256.New, macKey)
	h.Write(nonce)
	h.Write(ct)
	h.Write(ad)
	expected := h.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return nil, errors.New("authentication failed")
	}

	// Decrypt.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(block, nonce)
	plaintext := make([]byte, len(ct))
	cbc.CryptBlocks(plaintext, ct)

	// Unpad.
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// DeriveKeys derives AES and HMAC keys from a 32-byte master key using a context label.
func DeriveKeys(masterKey []byte, label string) (aesKey, macKey []byte) {
	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte(label))
	h.Write([]byte("aes"))
	aesKey = h.Sum(nil)

	h = hmac.New(sha256.New, masterKey)
	h.Write([]byte(label))
	h.Write([]byte("mac"))
	macKey = h.Sum(nil)

	return
}

// MAC computes HMAC-SHA256 with the given macKey over data.
func MAC(macKey, data []byte) []byte {
	h := hmac.New(sha256.New, macKey)
	h.Write(data)
	return h.Sum(nil)
}

// MACVerify checks that the provided mac equals the HMAC-SHA256 of data.
func MACVerify(macKey, data, mac []byte) bool {
	expected := MAC(macKey, data)
	return hmac.Equal(mac, expected)
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

// Hash returns a hash.Hash for the suite.
func Hash() hash.Hash {
	return sha256.New()
}
