package doubleratchet

import (
	"errors"

	"github.com/KushnerykPavel/go-doubleratchet/internal/state"
)

var (
	// ErrConfigNil is returned when a nil config is validated.
	ErrConfigNil = errors.New("config is nil")
	// ErrConfigMaxSkipTooLarge is returned when MaxSkip exceeds the maximum allowed value.
	ErrConfigMaxSkipTooLarge = errors.New("config MaxSkip exceeds maximum allowed value")
	// ErrConfigIdentityKeysIncomplete is returned when only one identity key is set.
	ErrConfigIdentityKeysIncomplete = errors.New("config: both identity keys must be set or both zero")
)

// DefaultMaxSkip is the default maximum number of skipped message keys.
const DefaultMaxSkip = 1000

// Config holds session configuration options.
type Config struct {
	KDFInfo     []byte
	HEKDFInfo   []byte
	EncryptInfo []byte
	HybridInfo  []byte
	MaxSkip     uint32

	// LocalIdentityKey is the local party's stable identity public key (32 bytes).
	// When both LocalIdentityKey and RemoteIdentityKey are non-zero, they are
	// automatically prepended to the AD in every Encrypt/Decrypt call, binding
	// each MAC to the session's identity pair. This matches the libsignal MAC
	// construction and prevents cross-session replay of message key material.
	// Both must be set or both must be zero.
	LocalIdentityKey [32]byte

	// RemoteIdentityKey is the remote party's stable identity public key (32 bytes).
	// See LocalIdentityKey for details.
	RemoteIdentityKey [32]byte
}

// Validate checks that the configuration values are valid.
func (c *Config) Validate() error {
	if c == nil {
		return ErrConfigNil
	}
	if c.MaxSkip > state.MaxSkipMax {
		return ErrConfigMaxSkipTooLarge
	}
	localSet := c.LocalIdentityKey != [32]byte{}
	remoteSet := c.RemoteIdentityKey != [32]byte{}
	if localSet != remoteSet {
		return ErrConfigIdentityKeysIncomplete
	}
	return nil
}

// EffectiveMaxSkip returns the effective MaxSkip, using the default if unset.
func (c *Config) EffectiveMaxSkip() uint32 {
	if c == nil {
		return DefaultMaxSkip
	}
	if c.MaxSkip == 0 {
		return DefaultMaxSkip
	}
	return c.MaxSkip
}

// identityADPrefix returns the 64-byte identity binding prefix as
// sender_identity || receiver_identity, matching libsignal's MAC construction.
// When sending=true (encrypt), sender=local, receiver=remote.
// When sending=false (decrypt), sender=remote, receiver=local.
// Returns nil if both identity keys are zero.
func (c *Config) identityADPrefix(sending bool) []byte {
	if c == nil {
		return nil
	}
	if c.LocalIdentityKey == [32]byte{} && c.RemoteIdentityKey == [32]byte{} {
		return nil
	}
	out := make([]byte, 64)
	if sending {
		copy(out[:32], c.LocalIdentityKey[:])
		copy(out[32:], c.RemoteIdentityKey[:])
	} else {
		copy(out[:32], c.RemoteIdentityKey[:])
		copy(out[32:], c.LocalIdentityKey[:])
	}
	return out
}

// effectiveKDFInfo returns the HKDF info for KDF_RK.
func (c *Config) effectiveKDFInfo() []byte {
	if c != nil && len(c.KDFInfo) > 0 {
		return c.KDFInfo
	}
	return []byte("DoubleRatchet")
}

// effectiveHEKDFInfo returns the HKDF info for KDF_RK_HE.
func (c *Config) effectiveHEKDFInfo() []byte {
	if c != nil && len(c.HEKDFInfo) > 0 {
		return c.HEKDFInfo
	}
	return []byte("DoubleRatchetHE")
}

// effectiveEncryptInfo returns the HKDF info for ENCRYPT key expansion.
func (c *Config) effectiveEncryptInfo() []byte {
	if c != nil && len(c.EncryptInfo) > 0 {
		return c.EncryptInfo
	}
	return []byte("DoubleRatchetEncrypt")
}

// effectiveHybridInfo returns the HKDF info for KDF_HYBRID in the Triple Ratchet.
func (c *Config) effectiveHybridInfo() []byte {
	if c != nil && len(c.HybridInfo) > 0 {
		return c.HybridInfo
	}
	return []byte("DoubleRatchetHybrid")
}
