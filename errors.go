package doubleratchet

import (
	"errors"
)

// ErrInvalidInput is returned when inputs are malformed.
var ErrInvalidInput = errors.New("invalid input")

// ErrSharedSecretTooShort is returned when the shared secret is shorter than 32 bytes.
var ErrSharedSecretTooShort = errors.New("shared secret must be at least 32 bytes")

// ErrNilProvider is returned when a nil SCKA provider is passed.
var ErrNilProvider = errors.New("SCKA provider must not be nil")

// ErrNilSCKAHeader is returned when a nil SCKA header is encountered.
var ErrNilSCKAHeader = errors.New("SCKA header must not be nil")

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

// ErrEpochMismatch is returned when epoch advancement is inconsistent.
var ErrEpochMismatch = errors.New("epoch mismatch")
