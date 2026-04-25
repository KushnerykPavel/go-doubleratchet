// Package scka provides a mock SCKA implementation for testing.
package scka

import (
	"crypto/hmac"
	"crypto/sha256"
)

// MockSCKA is a mock implementation of SCKAProvider for testing.
type MockSCKA struct {
	// SharedKey is the shared secret.
	SharedKey []byte

	// SendCount tracks number of Send() calls.
	SendCount int

	// ReceiveCount tracks number of Receive() calls.
	ReceiveCount int

	// SendEpoch is the epoch sent in each Send().
	SendEpoch uint32

	// KeyEpoch is the epoch for new key material.
	KeyEpoch uint32

	// OutputKey is the key material produced (nil to simulate no new key).
	OutputKey []byte

	// InitializedAs tracks initialization: "alice", "bob", or "".
	InitializedAs string

	// SkipBeforeKey if set, Send() returns nil outputKey for first N calls.
	SkipBeforeKey int
}

// mockSCKASnapshot holds a deep copy of MockSCKA state for rollback.
type mockSCKASnapshot struct {
	sharedKey     []byte
	sendCount     int
	receiveCount  int
	sendEpoch     uint32
	keyEpoch      uint32
	outputKey     []byte
	initializedAs string
	skipBeforeKey int
}

// InitAlice initializes the mock SCKA for Alice.
func (m *MockSCKA) InitAlice(sk []byte) error {
	m.SharedKey = make([]byte, len(sk))
	copy(m.SharedKey, sk)
	m.InitializedAs = "alice"
	m.SendCount = 0
	m.ReceiveCount = 0
	m.SendEpoch = 0
	m.KeyEpoch = 1
	return nil
}

// InitBob initializes the mock SCKA for Bob.
func (m *MockSCKA) InitBob(sk []byte) error {
	m.SharedKey = make([]byte, len(sk))
	copy(m.SharedKey, sk)
	m.InitializedAs = "bob"
	m.SendCount = 0
	m.ReceiveCount = 0
	m.SendEpoch = 0
	m.KeyEpoch = 1
	return nil
}

// Send produces an SCKA message and potentially a new key.
func (m *MockSCKA) Send() (msg []byte, sendingEpoch uint32, outputKey []byte, keyEpoch uint32, err error) {
	m.SendCount++

	// Build a mock message from shared key and send count.
	msg = make([]byte, 32)
	h := hmac.New(sha256.New, m.SharedKey)
	h.Write([]byte("send"))
	h.Write([]byte{byte(m.SendCount)})
	copy(msg, h.Sum(nil)[:32])

	sendingEpoch = m.SendEpoch

	// Simulate key generation after SkipBeforeKey calls.
	if m.SkipBeforeKey > 0 && m.SendCount <= m.SkipBeforeKey {
		return msg, sendingEpoch, nil, 0, nil
	}

	// Generate output key if configured.
	if m.OutputKey != nil {
		// Derive a consistent key based on KeyEpoch.
		h = hmac.New(sha256.New, m.OutputKey)
		h.Write([]byte("key"))
		h.Write([]byte{byte(m.KeyEpoch)})
		outputKey = make([]byte, 32)
		copy(outputKey, h.Sum(nil)[:32])
		keyEpoch = m.KeyEpoch
	}

	return msg, sendingEpoch, outputKey, keyEpoch, nil
}

// Receive processes an incoming SCKA message.
func (m *MockSCKA) Receive(msg []byte) (receivingEpoch uint32, outputKey []byte, keyEpoch uint32, err error) {
	m.ReceiveCount++

	receivingEpoch = m.SendEpoch // The epoch when msg was created.

	// Simulate key generation after SkipBeforeKey calls.
	if m.SkipBeforeKey > 0 && m.ReceiveCount <= m.SkipBeforeKey {
		return receivingEpoch, nil, 0, nil
	}

	// Generate output key if configured.
	if m.OutputKey != nil {
		h := hmac.New(sha256.New, m.OutputKey)
		h.Write([]byte("key"))
		h.Write([]byte{byte(m.KeyEpoch)})
		outputKey = make([]byte, 32)
		copy(outputKey, h.Sum(nil)[:32])
		keyEpoch = m.KeyEpoch
	}

	return receivingEpoch, outputKey, keyEpoch, nil
}

// Snapshot captures the current MockSCKA state for rollback.
func (m *MockSCKA) Snapshot() interface{} {
	snap := &mockSCKASnapshot{
		sendCount:     m.SendCount,
		receiveCount:  m.ReceiveCount,
		sendEpoch:     m.SendEpoch,
		keyEpoch:      m.KeyEpoch,
		initializedAs: m.InitializedAs,
		skipBeforeKey: m.SkipBeforeKey,
	}
	if m.SharedKey != nil {
		snap.sharedKey = append([]byte(nil), m.SharedKey...)
	}
	if m.OutputKey != nil {
		snap.outputKey = append([]byte(nil), m.OutputKey...)
	}
	return snap
}

// Restore reverts MockSCKA state to a previously captured snapshot.
func (m *MockSCKA) Restore(snapshot interface{}) {
	snap := snapshot.(*mockSCKASnapshot)
	m.SharedKey = snap.sharedKey
	m.SendCount = snap.sendCount
	m.ReceiveCount = snap.receiveCount
	m.SendEpoch = snap.sendEpoch
	m.KeyEpoch = snap.keyEpoch
	m.OutputKey = snap.outputKey
	m.InitializedAs = snap.initializedAs
	m.SkipBeforeKey = snap.skipBeforeKey
}

// SetOutputKey configures the mock to produce a specific output key.
func (m *MockSCKA) SetOutputKey(key []byte) {
	m.OutputKey = key
}

// SetKeyEpoch sets the epoch for new key material.
func (m *MockSCKA) SetKeyEpoch(epoch uint32) {
	m.KeyEpoch = epoch
}

// Close zeros all key material in the mock SCKA provider.
func (m *MockSCKA) Close() error {
	for i := range m.SharedKey {
		m.SharedKey[i] = 0
	}
	for i := range m.OutputKey {
		m.OutputKey[i] = 0
	}
	m.SharedKey = nil
	m.OutputKey = nil
	m.SendCount = 0
	m.ReceiveCount = 0
	return nil
}

// SetSendEpoch sets the sending epoch.
func (m *MockSCKA) SetSendEpoch(epoch uint32) {
	m.SendEpoch = epoch
}
