package kdf

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Hybrid combines EC and PQ message keys for the Triple Ratchet per spec §6/§7.
//
// Per spec §7: HKDF-SHA256 with:
//   - pqKey as HKDF salt
//   - ecKey as HKDF IKM (input key material)
//   - info as application-specific label
//
// The PQ key as salt ensures that compromise of the EC component alone does not
// break the combined key. Returns a 32-byte combined message key.
func Hybrid(pqKey, ecKey, info []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, ecKey, pqKey, info)
	mk := make([]byte, 32)
	if _, err := io.ReadFull(reader, mk); err != nil {
		return nil, err
	}
	return mk, nil
}
