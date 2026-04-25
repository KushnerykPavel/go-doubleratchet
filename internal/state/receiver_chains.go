package state

import "crypto/subtle"

// ReceiverChainsMax is the maximum number of receiver chains retained.
// Matches libsignal's MAX_RECEIVER_CHAINS = 5.
const ReceiverChainsMax = 5

// ReceiverChain holds receive-side chain state for one DH epoch.
type ReceiverChain struct {
	CK        []byte
	Nr        uint32
	RatchetPK [32]byte
}

// ReceiverChains is a fixed-capacity circular buffer of receiver chains,
// one per remote DH ratchet epoch. Oldest chain is evicted when full.
type ReceiverChains struct {
	chains [ReceiverChainsMax]ReceiverChain
	// head is the index of the oldest valid entry (used for eviction).
	head  int
	count int
}

// NewReceiverChains returns an empty ReceiverChains buffer.
func NewReceiverChains() *ReceiverChains {
	return &ReceiverChains{}
}

// Push adds a new receiver chain for pk with the given chain key.
// If the buffer is at capacity, the oldest entry is evicted and its CK is zeroed.
func (r *ReceiverChains) Push(pk [32]byte, ck []byte) {
	if r.count == ReceiverChainsMax {
		// Evict oldest: zero its CK then overwrite.
		zeroSlice(r.chains[r.head].CK)
		r.chains[r.head] = ReceiverChain{}
		r.head = (r.head + 1) % ReceiverChainsMax
		r.count--
	}
	idx := (r.head + r.count) % ReceiverChainsMax
	r.chains[idx] = ReceiverChain{
		RatchetPK: pk,
		CK:        copyBytes(ck),
		Nr:        0,
	}
	r.count++
}

// Get returns a pointer to the chain for pk, or nil if not found.
// The pointer is into the buffer; callers may mutate CK and Nr in place.
func (r *ReceiverChains) Get(pk [32]byte) *ReceiverChain {
	for i := range r.count {
		idx := (r.head + i) % ReceiverChainsMax
		if subtle.ConstantTimeCompare(r.chains[idx].RatchetPK[:], pk[:]) == 1 {
			return &r.chains[idx]
		}
	}
	return nil
}

// Has reports whether a chain for pk exists in the buffer.
func (r *ReceiverChains) Has(pk [32]byte) bool {
	return r.Get(pk) != nil
}

// Clone returns a deep copy of the buffer suitable for rollback snapshots.
func (r *ReceiverChains) Clone() *ReceiverChains {
	c := &ReceiverChains{
		head:  r.head,
		count: r.count,
	}
	for i := range ReceiverChainsMax {
		src := &r.chains[i]
		c.chains[i] = ReceiverChain{
			RatchetPK: src.RatchetPK,
			CK:        copyBytes(src.CK),
			Nr:        src.Nr,
		}
	}
	return c
}

// Clear zeros all CK material and resets the buffer to empty.
func (r *ReceiverChains) Clear() {
	for i := range ReceiverChainsMax {
		zeroSlice(r.chains[i].CK)
		r.chains[i] = ReceiverChain{}
	}
	r.head = 0
	r.count = 0
}
