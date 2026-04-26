package state

import (
	"crypto/subtle"
	"errors"

	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
)

// ErrInvariantViolation is returned when an invariant check fails.
var ErrInvariantViolation = errors.New("invariant violation")

// Invariants tracks previous session state for rollback on authentication failure.
type Invariants struct {
	prevMKSKIPPED  *Storage
	prevRecvChains *ReceiverChains
	prevRK         []byte
	prevCKs        []byte
	prevNs         uint32
	prevPN         uint32
	prevDHs        [32]byte
	prevDHr        [32]byte
	prevDhRSet     bool
}

// NewInvariants creates an Invariants tracker for a session.
func NewInvariants() *Invariants {
	return &Invariants{}
}

// Record snapshots the current state before a potential state change.
// Must be called before any mutation that Decrypt may need to roll back.
func (inv *Invariants) Record(ns, pn uint32, rk []byte, dhs, dhr [32]byte, cks []byte, recvChains *ReceiverChains, mkskipped *Storage, dhRSet bool) {
	inv.prevNs = ns
	inv.prevPN = pn
	inv.prevRK = copyBytes(rk)
	inv.prevDHs = dhs
	inv.prevDHr = dhr
	inv.prevCKs = copyBytes(cks)
	inv.prevRecvChains = recvChains.Clone()
	inv.prevMKSKIPPED = mkskipped.Clone()
	inv.prevDhRSet = dhRSet
}

// PrevState holds the previous state values for rollback.
type PrevState struct {
	MKSKIPPED  *Storage
	RecvChains *ReceiverChains
	RK         []byte
	CKs        []byte
	Ns         uint32
	PN         uint32
	DHs        [32]byte
	DHr        [32]byte
	DhRSet     bool
}

// GetPrevState returns a copy of the previously recorded state.
func (inv *Invariants) GetPrevState() PrevState {
	return PrevState{
		Ns:         inv.prevNs,
		PN:         inv.prevPN,
		RK:         copyBytes(inv.prevRK),
		DHs:        inv.prevDHs,
		DHr:        inv.prevDHr,
		CKs:        copyBytes(inv.prevCKs),
		RecvChains: inv.prevRecvChains,
		MKSKIPPED:  inv.prevMKSKIPPED,
		DhRSet:     inv.prevDhRSet,
	}
}

// Clear zeros all key material stored in the invariants snapshot.
func (inv *Invariants) Clear() {
	crypto.ZeroBytes(inv.prevRK)
	crypto.ZeroBytes(inv.prevCKs)
	for i := range inv.prevDHs {
		inv.prevDHs[i] = 0
	}
	for i := range inv.prevDHr {
		inv.prevDHr[i] = 0
	}
	if inv.prevRecvChains != nil {
		inv.prevRecvChains.Clear()
		inv.prevRecvChains = nil
	}
	if inv.prevMKSKIPPED != nil {
		inv.prevMKSKIPPED.Clear()
		inv.prevMKSKIPPED = nil
	}
	inv.prevDhRSet = false
}

// VerifySend verifies that Ns was incremented correctly after deriving a message key.
func (inv *Invariants) VerifySend(ns, expectedPrevNs uint32) error {
	if ns != expectedPrevNs+1 {
		return ErrInvariantViolation
	}
	return nil
}

// VerifyPN verifies that PN was updated correctly after a DH ratchet step.
func (inv *Invariants) VerifyPN(pn, expectedPrevPN uint32) error {
	if pn != expectedPrevPN {
		return ErrInvariantViolation
	}
	return nil
}

// VerifyDHTransition verifies that DH keys were updated correctly.
func (inv *Invariants) VerifyDHTransition(dhr, newRemotePK [32]byte) error {
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

