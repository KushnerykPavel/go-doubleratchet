// Package scka provides the Sparse Continuous Key Agreement interface.
package scka

// SCKAProvider abstracts the SCKA protocol for SPQR.
// Implementations handle post-quantum key agreement.
type SCKAProvider interface {
	// InitAlice initializes Alice's SCKA state with shared secret.
	InitAlice(sk []byte) error

	// InitBob initializes Bob's SCKA state with shared secret.
	InitBob(sk []byte) error

	// Send produces the next SCKA message and potentially a new key.
	// Returns:
	//   msg: opaque message for transport
	//   sendingEpoch: latest epoch guaranteed known by receiver
	//   outputKey: nil or (keyEpoch, key) tuple
	//   keyEpoch: epoch of outputKey (0 if outputKey is nil)
	Send() (msg []byte, sendingEpoch uint32, outputKey []byte, keyEpoch uint32, err error)

	// Receive processes an incoming SCKA message.
	// Returns:
	//   receivingEpoch: epoch emitted when msg was generated
	//   outputKey: nil or (keyEpoch, key) tuple
	//   keyEpoch: epoch of outputKey (0 if outputKey is nil)
	Receive(msg []byte) (receivingEpoch uint32, outputKey []byte, keyEpoch uint32, err error)
}
