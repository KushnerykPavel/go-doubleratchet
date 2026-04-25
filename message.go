package doubleratchet

// Header represents the base Double Ratchet message header.
type Header struct {
	// RatchetPublicKey is the sender's current ratchet public key.
	RatchetPublicKey [32]byte

	// PN is the number of messages in the previous sending chain.
	PN uint32

	// N is the current message number in the sending chain.
	N uint32
}

// Message represents an encrypted Double Ratchet message.
type Message struct {
	Ciphertext []byte
	Header     Header
}

// SCKAHeader represents the SPQR message header.
type SCKAHeader struct {
	// Msg is the opaque SCKA message data.
	Msg []byte
	// N is the message number in the sending chain.
	N uint32
}

// TripleRatchetHeader contains both the EC (Double Ratchet) and PQ (SCKA) header components.
// Used by the Triple Ratchet to carry state for both protocol components.
type TripleRatchetHeader struct {
	SCKA *SCKAHeader
	EC   Header
}

// TripleRatchetMessage is a ciphertext produced by the Triple Ratchet.
type TripleRatchetMessage struct {
	// Ciphertext is the authenticated-encrypted payload.
	Ciphertext []byte
	// Header contains both EC and PQ routing information.
	Header TripleRatchetHeader
}
