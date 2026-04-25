// Package state provides session state management for the Double Ratchet.
package state

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
)

const (
	// MaxSkipMax is the maximum allowed MaxSkip value to prevent memory abuse.
	MaxSkipMax = 100000
)

// SkippedKeyEntry stores a skipped message key indexed by remote ratchet key and message number.
type SkippedKeyEntry struct {
	RemoteRatchetPK [32]byte
	MessageNumber   uint32
	MessageKey      [32]byte
}

// Storage implements bounded skipped-key storage.
type Storage struct {
	entries map[string]*SkippedKeyEntry
	order   []string
	mu      sync.Mutex
	maxSkip uint32
}

// Lock acquires the storage mutex.
func (s *Storage) Lock() {
	s.mu.Lock()
}

// Unlock releases the storage mutex.
func (s *Storage) Unlock() {
	s.mu.Unlock()
}

// HDECRYPTFunc is a function that attempts to decrypt an encrypted header.
// Per spec §4.2: HDECRYPT takes only (headerKey, ciphertext) — no AD.
type HDECRYPTFunc func(headerKey [32]byte, ciphertext []byte) ([]byte, bool)

// TryAllHeaderKeys iterates through all stored skipped keys and attempts
// header decryption with each. Returns the message key and true if found.
// The entry is deleted after successful decryption.
func (s *Storage) TryAllHeaderKeys(encHeader []byte, decryptFunc HDECRYPTFunc) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for storageKey, entry := range s.entries {
		var hk [32]byte
		copy(hk[:], entry.RemoteRatchetPK[:])

		// Try HDECRYPT with this header key.
		headerBytes, ok := decryptFunc(hk, encHeader)
		if !ok {
			continue
		}

		// Decode header to check n matches.
		if len(headerBytes) < 40 {
			continue
		}
		// Header format: dh (32 bytes) || pn (4 bytes) || n (4 bytes)
		n := binary.BigEndian.Uint32(headerBytes[36:40])

		// Check if message number matches.
		if n != entry.MessageNumber {
			continue
		}

		// Found matching skipped key.
		// Delete entry from MKSKIPPED.
		delete(s.entries, storageKey)

		// Remove from order list.
		for i, k := range s.order {
			if k == storageKey {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}

		// Copy key before zeroing.
		keyCopy := make([]byte, 32)
		copy(keyCopy, entry.MessageKey[:])

		// Zero the entry.
		for i := range entry.MessageKey {
			entry.MessageKey[i] = 0
		}

		return keyCopy, true
	}

	return nil, false
}

// NewStorage creates a new skipped-key storage with the given max skip limit.
func NewStorage(maxSkip uint32) (*Storage, error) {
	if maxSkip > MaxSkipMax {
		return nil, errors.New("max skip too large")
	}
	return &Storage{
		maxSkip: maxSkip,
		entries: make(map[string]*SkippedKeyEntry),
		order:   make([]string, 0, maxSkip),
	}, nil
}

// StorageKey generates a deterministic storage key for a skipped entry.
func StorageKey(remotePK [32]byte, messageNumber uint32) string {
	var key [32 + 4]byte
	copy(key[:32], remotePK[:])
	binary.BigEndian.PutUint32(key[32:], messageNumber)
	return string(key[:])
}

// Store stores a skipped message key. If the storage is at capacity, it evicts
// the oldest entry. Returns an error if maxSkip would be exceeded after the new entry.
func (s *Storage) Store(remotePK [32]byte, messageNumber uint32, messageKey [32]byte) error {
	return s.StoreHK(remotePK, messageNumber, messageKey)
}

// StoreHK stores a skipped message key indexed by header key.
// If the storage is at capacity, it evicts the oldest entry.
func (s *Storage) StoreHK(headerKey [32]byte, messageNumber uint32, messageKey [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.maxSkip == 0 {
		return nil // No storage allowed
	}

	storageKey := StorageKeyHK(headerKey, messageNumber)

	// If key already exists, don't store (shouldn't happen in practice).
	if _, exists := s.entries[storageKey]; !exists {
		// Evict oldest if at capacity.
		if uint32(len(s.entries)) >= s.maxSkip {
			evictKey := s.order[0]
			delete(s.entries, evictKey)
			s.order = s.order[1:]
		}
		entry := &SkippedKeyEntry{
			MessageNumber: messageNumber,
			MessageKey:    messageKey,
		}
		copy(entry.RemoteRatchetPK[:], headerKey[:])
		s.entries[storageKey] = entry
		s.order = append(s.order, storageKey)
	}
	return nil
}

// StorageKeyHK generates a deterministic storage key for a skipped entry using header key.
func StorageKeyHK(headerKey [32]byte, messageNumber uint32) string {
	return StorageKey(headerKey, messageNumber)
}

// Get retrieves and deletes a skipped message key.
// Returns the key and true if found, or nil and false if not found.
// The entry is deleted after retrieval (one-time use).
func (s *Storage) Get(remotePK [32]byte, messageNumber uint32) ([]byte, bool) {
	return s.GetHK(remotePK, messageNumber)
}

// GetHK retrieves and deletes a skipped message key using header key index.
// Returns the key and true if found, or nil and false if not found.
// The entry is deleted after retrieval (one-time use).
// The key is zeroed after copying (secure deletion).
func (s *Storage) GetHK(headerKey [32]byte, messageNumber uint32) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	storageKey := StorageKeyHK(headerKey, messageNumber)
	entry, found := s.entries[storageKey]
	if !found {
		return nil, false
	}

	// Copy key to return buffer BEFORE zeroing original.
	keyCopy := make([]byte, 32)
	copy(keyCopy, entry.MessageKey[:])

	// Zero original storage (secure deletion).
	for i := range entry.MessageKey {
		entry.MessageKey[i] = 0
	}

	// Delete entry (consume).
	delete(s.entries, storageKey)
	for i, k := range s.order {
		if k == storageKey {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}

	return keyCopy, true
}

// Len returns the number of stored skipped keys.
func (s *Storage) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Clear zeros all key material and removes all entries.
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, entry := range s.entries {
		for i := range entry.MessageKey {
			entry.MessageKey[i] = 0
		}
		delete(s.entries, k)
	}
	s.order = s.order[:0]
}

// Clone creates a deep copy of the storage.
func (s *Storage) Clone() *Storage {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := make(map[string]*SkippedKeyEntry, len(s.entries))
	order := make([]string, len(s.order))
	copy(order, s.order)

	for k, v := range s.entries {
		entryCopy := &SkippedKeyEntry{
			RemoteRatchetPK: v.RemoteRatchetPK,
			MessageNumber:   v.MessageNumber,
			MessageKey:      v.MessageKey,
		}
		entries[k] = entryCopy
	}

	return &Storage{
		maxSkip: s.maxSkip,
		entries: entries,
		order:   order,
	}
}

// ConstantTimeCompare provides constant-time comparison for storage keys.
func ConstantTimeCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}
