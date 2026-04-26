// Package suite provides the AES-256-CBC + HMAC-SHA256 encryption suite.
// Key material (enc_key, auth_key, IV) is derived from the message key via HKDF-SHA256,
// following the recommended construction in the Signal Double Ratchet spec §7.
package suite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/KushnerykPavel/go-doubleratchet/internal/padding"
)

const (
	// TagSize is the HMAC-SHA256 authentication tag size in bytes.
	TagSize = 32
	// IVSize is the AES-CBC IV size in bytes.
	IVSize = 16
	// DerivedKeySize is the total HKDF output: 32 (enc) + 32 (auth) + 16 (IV) = 80 bytes.
	derivedKeySize = 80
)

var (
	errCiphertextShort      = errors.New("ciphertext too short")
	errCiphertextLenInvalid = errors.New("ciphertext length invalid")
	errAuthFailed           = errors.New("authentication failed")
)

// Encrypt encrypts plaintext using AES-256-CBC and authenticates with HMAC-SHA256.
//
// Per Signal spec §7 (CBC+HMAC approach):
//   - HKDF-SHA256(IKM=msgKey, salt=nil, info) derives enc_key(32) + auth_key(32) + IV(16)
//   - CBC-ciphertext = AES-256-CBC(enc_key, IV, PKCS7(plaintext))
//   - MAC = HMAC-SHA256(auth_key, ad || IV || CBC-ciphertext)
//   - Output: IV || CBC-ciphertext || MAC
//
// info is the application-specific HKDF info string (e.g. "DoubleRatchetEncrypt").
func Encrypt(msgKey, plaintext, ad, info []byte) ([]byte, error) {
	encKey, authKey, iv, err := deriveKeys(msgKey, info)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	padded := padding.PKCS7Pad(plaintext, aes.BlockSize)
	ct := make([]byte, len(padded))
	cbc.CryptBlocks(ct, padded)

	// MAC = HMAC-SHA256(auth_key, AD || IV || CBC-ciphertext)
	h := hmac.New(sha256.New, authKey)
	h.Write(ad)
	h.Write(iv)
	h.Write(ct)
	tag := h.Sum(nil)

	// Output: IV || CBC-ciphertext || MAC
	out := make([]byte, 0, IVSize+len(ct)+TagSize)
	out = append(out, iv...)
	out = append(out, ct...)
	out = append(out, tag...)
	return out, nil
}

// Decrypt decrypts and authenticates ciphertext produced by Encrypt.
// MsgKey, ad, and info must match those used during encryption.
// Ciphertext format: IV (16) || AES-CBC ciphertext || HMAC tag (32).
func Decrypt(msgKey, ciphertext, ad, info []byte) ([]byte, error) {
	if len(ciphertext) < IVSize+TagSize {
		return nil, errCiphertextShort
	}

	encKey, authKey, _, err := deriveKeys(msgKey, info)
	if err != nil {
		return nil, err
	}

	// Parse ciphertext: IV || CBC-ct || MAC
	iv := ciphertext[:IVSize]
	tagOffset := len(ciphertext) - TagSize
	ct := ciphertext[IVSize:tagOffset]
	tag := ciphertext[tagOffset:]

	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errCiphertextLenInvalid
	}

	// Verify MAC before decrypting.
	h := hmac.New(sha256.New, authKey)
	h.Write(ad)
	h.Write(iv)
	h.Write(ct)
	expected := h.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return nil, errAuthFailed
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ct))
	cbc.CryptBlocks(plaintext, ct)

	return padding.PKCS7Unpad(plaintext, aes.BlockSize)
}

// deriveKeys uses HKDF-SHA256 to derive enc_key, auth_key, and iv from msgKey.
// Nil salt per spec; info is application-specific.
func deriveKeys(msgKey, info []byte) (encKey, authKey, iv []byte, err error) {
	reader := hkdf.New(sha256.New, msgKey, nil, info)
	derived := make([]byte, derivedKeySize)
	if _, err := io.ReadFull(reader, derived); err != nil {
		return nil, nil, nil, err
	}
	return derived[:32], derived[32:64], derived[64:80], nil
}
