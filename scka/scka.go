// Package scka provides the Sparse Continuous Key Agreement interface.
package scka

// Provider abstracts the SCKA protocol for SPQR.
// Implementations handle post-quantum key agreement.
type Provider interface {
	// InitInitiator initializes the Initiator's SCKA state with shared secret.
	InitInitiator(sk []byte) error

	// InitResponder initializes the Responder's SCKA state with shared secret.
	InitResponder(sk []byte) error

	// Send produces the next SCKA message and potentially a new key.
	// Returns:
	//   msg: opaque message for transport
	//   sendingEpoch: latest epoch guaranteed known by receiver
	//   outputKey: nil or new key material for keyEpoch
	//   keyEpoch: epoch of outputKey (0 if outputKey is nil)
	Send() (msg []byte, sendingEpoch uint32, outputKey []byte, keyEpoch uint32, err error)

	// Receive processes an incoming SCKA message.
	// Returns:
	//   receivingEpoch: epoch emitted when msg was generated
	//   outputKey: nil or new key material for keyEpoch
	//   keyEpoch: epoch of outputKey (0 if outputKey is nil)
	Receive(msg []byte) (receivingEpoch uint32, outputKey []byte, keyEpoch uint32, err error)

	// Snapshot captures the current SCKA state for rollback.
	// The returned value is opaque; pass it unchanged to Restore.
	//
	// IMPLEMENTATION CONTRACT: the snapshot must be a deep copy of ALL mutable
	// state including key material. SPQRSession calls Snapshot before each Decrypt
	// and calls Restore on authentication failure. If Snapshot is shallow or
	// Restore is incomplete, post-failure session state will be corrupt. The
	// MockSCKA in this package provides a reference implementation.
	Snapshot() any

	// Restore reverts SCKA state to a previously captured snapshot.
	// Must fully replace all state with the values captured by Snapshot,
	// including all key material. Called by SPQRSession on authentication
	// failure to roll back any epoch advancement made during the failed Decrypt.
	Restore(snapshot any)

	// Close zeros all key material held by the SCKA provider.
	// Callers must not use the provider after Close returns.
	Close() error
}
