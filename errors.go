// Package doubleratchet implements the base Signal Double Ratchet algorithm.
package doubleratchet

import (
	"errors"
)

// ErrInvalidInput is returned when inputs are malformed.
var ErrInvalidInput = errors.New("invalid input")

// ErrMaxSkipExceeded is returned when a message requires skipping beyond MaxSkip.
var ErrMaxSkipExceeded = errors.New("max skip exceeded")

// ErrSkippedKeyNotFound is returned when a skipped key is not found.
var ErrSkippedKeyNotFound = errors.New("skipped key not found")

// ErrAuthFailure is returned when authentication fails.
var ErrAuthFailure = errors.New("authentication failure")

// ErrInvalidTransition is returned when a state transition is invalid.
var ErrInvalidTransition = errors.New("invalid state transition")

// ErrSessionNotInitialized is returned when session methods are called on nil session.
var ErrSessionNotInitialized = errors.New("session not initialized")
