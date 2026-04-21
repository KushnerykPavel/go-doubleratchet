// Package state provides session state management for the Double Ratchet.
package state

import (
	"crypto/subtle"
	"errors"
)

// ErrInvariantViolation is returned when an invariant check fails.
var ErrInvariantViolation = errors.New("invariant violation")

// Invariants defines the state invariants for a Double Ratchet session.
type Invariants struct {
	// Track previous values for rollback validation.
	prevNs        uint32
	prevNr        uint32
	prevPN        uint32
	prevRK        []byte
	prevDHs       [32]byte
	prevDHr       [32]byte
	prevCKs       []byte
	prevCKr       []byte
	prevMKSKIPPED *Storage
}

// NewInvariants creates an Invariants tracker for a session.
func NewInvariants() *Invariants {
	return &Invariants{}
}

// Record records the current state values before a potential state change.
func (inv *Invariants) Record(ns, nr, pn uint32, rk []byte, dhs, dhr [32]byte, cks, ckr []byte, mkskipped *Storage) {
	inv.prevNs = ns
	inv.prevNr = nr
	inv.prevPN = pn
	inv.prevRK = copyBytes(rk)
	inv.prevDHs = dhs
	inv.prevDHr = dhr
	inv.prevCKs = copyBytes(cks)
	inv.prevCKr = copyBytes(ckr)
	inv.prevMKSKIPPED = mkskipped.Clone()
}

// PrevState holds the previous state values for rollback.
type PrevState struct {
	Ns        uint32
	Nr        uint32
	PN        uint32
	RK        []byte
	DHs       [32]byte
	DHr       [32]byte
	CKs       []byte
	CKr       []byte
	MKSKIPPED *Storage
}

// GetPrevState returns the previous state values for rollback.
func (inv *Invariants) GetPrevState() PrevState {
	return PrevState{
		Ns:        inv.prevNs,
		Nr:        inv.prevNr,
		PN:        inv.prevPN,
		RK:        copyBytes(inv.prevRK),
		DHs:       inv.prevDHs,
		DHr:       inv.prevDHr,
		CKs:       copyBytes(inv.prevCKs),
		CKr:       inv.prevCKr,
		MKSKIPPED: inv.prevMKSKIPPED,
	}
}

// VerifySend verifies that Ns was incremented correctly after deriving a message key.
func (inv *Invariants) VerifySend(ns uint32, expectedPrevNs uint32) error {
	if ns != expectedPrevNs+1 {
		return ErrInvariantViolation
	}
	return nil
}

// VerifyRecv verifies that Nr was incremented correctly after deriving a receive message key.
func (inv *Invariants) VerifyRecv(nr uint32, expectedPrevNr uint32) error {
	if nr != expectedPrevNr+1 {
		return ErrInvariantViolation
	}
	return nil
}

// VerifyPN verifies that PN was updated correctly after a DH ratchet step.
func (inv *Invariants) VerifyPN(pn uint32, expectedPrevPN uint32) error {
	if pn != expectedPrevPN {
		// PN should equal previous Ns after a DH ratchet step.
		return ErrInvariantViolation
	}
	return nil
}

// VerifyDHTransition verifies that DH keys were updated correctly.
func (inv *Invariants) VerifyDHTransition(dhr [32]byte, newRemotePK [32]byte) error {
	// DHr should equal the new remote public key after a ratchet step.
	if subtle.ConstantTimeCompare(dhr[:], newRemotePK[:]) != 1 {
		return ErrInvariantViolation
	}
	return nil
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}