package kdf

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	spqrProtocolInfo = []byte("SPQR_PROTOCOL_INFO")
	chainStartInfo   = append(append([]byte(nil), spqrProtocolInfo...), []byte("Chain Start")...)
	chainAddInfo     = append(append([]byte(nil), spqrProtocolInfo...), []byte("Chain Add Epoch")...)
	messageKeysInfo  = append(append([]byte(nil), spqrProtocolInfo...), []byte("Message Keys")...)
)

// ErrInvalidInput is returned for invalid inputs.
var ErrInvalidInput = errors.New("invalid input")

// DeriveInitialChainsSPQR derives initial RK, CKs, CKr from SK.
// Returns (rk, cks, ckr) each 32 bytes.
func DeriveInitialChainsSPQR(sk []byte) (rk, cks, ckr []byte, err error) {
	if len(sk) < 32 {
		return nil, nil, nil, ErrInvalidInput
	}

	okm, err := hkdfExpand(make([]byte, 32), sk, chainStartInfo, 96)
	if err != nil {
		return nil, nil, nil, err
	}

	return splitTriple(okm)
}

// RatchetRootKeySPQR derives new RK, CKs, CKr from current RK and SCKA output.
func RatchetRootKeySPQR(rk, sckaOutput []byte) (newRK, cks, ckr []byte, err error) {
	if len(rk) < 32 || len(sckaOutput) < 32 {
		return nil, nil, nil, ErrInvalidInput
	}

	okm, err := hkdfExpand(rk, sckaOutput, chainAddInfo, 96)
	if err != nil {
		return nil, nil, nil, err
	}

	return splitTriple(okm)
}

// RatchetChainKeySPQR derives next chain key and message key from current chain key.
func RatchetChainKeySPQR(ck []byte, ctr uint32) (nextCK, mk []byte, err error) {
	if len(ck) < 32 {
		return nil, nil, ErrInvalidInput
	}

	info := make([]byte, len(messageKeysInfo)+4)
	copy(info, messageKeysInfo)
	info[len(messageKeysInfo)] = byte(ctr >> 24)
	info[len(messageKeysInfo)+1] = byte(ctr >> 16)
	info[len(messageKeysInfo)+2] = byte(ctr >> 8)
	info[len(messageKeysInfo)+3] = byte(ctr)

	okm, err := hkdfExpand(make([]byte, 32), ck, info, 64)
	if err != nil {
		return nil, nil, err
	}

	return append([]byte(nil), okm[:32]...), append([]byte(nil), okm[32:64]...), nil
}

func hkdfExpand(salt, ikm, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, err
	}
	return out, nil
}

func splitTriple(okm []byte) (rk, cks, ckr []byte, err error) {
	if len(okm) != 96 {
		return nil, nil, nil, ErrInvalidInput
	}
	return append([]byte(nil), okm[:32]...),
		append([]byte(nil), okm[32:64]...),
		append([]byte(nil), okm[64:96]...),
		nil
}
