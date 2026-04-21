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
	maxSkip uint32
	entries map[string]*SkippedKeyEntry
	order   []string // insertion order for eviction
	mu      sync.Mutex
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
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.maxSkip == 0 {
		return nil // No storage allowed
	}

	storageKey := StorageKey(remotePK, messageNumber)

	// If key already exists, don't store (shouldn't happen in practice).
	if _, exists := s.entries[storageKey]; !exists {
		// Evict oldest if at capacity.
		if uint32(len(s.entries)) >= s.maxSkip {
			evictKey := s.order[0]
			delete(s.entries, evictKey)
			s.order = s.order[1:]
		}
		s.entries[storageKey] = &SkippedKeyEntry{
			RemoteRatchetPK: remotePK,
			MessageNumber:   messageNumber,
			MessageKey:      messageKey,
		}
		s.order = append(s.order, storageKey)
	}
	return nil
}

// Get retrieves and deletes a skipped message key.
// Returns the key and true if found, or nil and false if not found.
// The entry is deleted after retrieval (one-time use).
func (s *Storage) Get(remotePK [32]byte, messageNumber uint32) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	storageKey := StorageKey(remotePK, messageNumber)
	entry, found := s.entries[storageKey]
	if !found {
		return nil, false
	}

	// Delete entry (consume).
	delete(s.entries, storageKey)
	for i, k := range s.order {
		if k == storageKey {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}

	// Best-effort secure deletion of the key material.
	copy(entry.MessageKey[:], make([]byte, 32))

	return entry.MessageKey[:], true
}

// Len returns the number of stored skipped keys.
func (s *Storage) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Clear removes all entries.
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.entries {
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