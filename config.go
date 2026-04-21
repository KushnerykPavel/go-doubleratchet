// Package doubleratchet provides configuration for Double Ratchet sessions.
package doubleratchet

import (
	"errors"

	"doubleratchet/internal/state"
)

// DefaultMaxSkip is the default maximum number of skipped message keys.
const DefaultMaxSkip = 1000

// Config holds session configuration options.
type Config struct {
	// MaxSkip is the maximum number of skipped message keys that may be stored
	// for a receive step. Must be non-negative.
	MaxSkip uint32

	// Suite is reserved for future use to support alternative cryptographic suites.
	// Currently unused; the default suite (AES-256-CBC + HMAC-SHA256) is always used.
	Suite interface{}
}

// Validate checks that the configuration values are valid.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.MaxSkip > state.MaxSkipMax {
		return errors.New("config MaxSkip exceeds maximum allowed value")
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
