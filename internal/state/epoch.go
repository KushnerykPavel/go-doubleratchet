package state

// Direction indicates the message flow direction.
type Direction uint8

const (
	// DirectionA2B indicates Alice to Bob.
	DirectionA2B Direction = iota
	// DirectionB2A indicates Bob to Alice.
	DirectionB2A
)

// KDFChain holds a chain key and message counter.
type KDFChain struct {
	// CK is the 32-byte chain key.
	CK []byte
	// N is the message counter.
	N uint32
}

// KDFChainPair holds send and receive chains for an epoch.
type KDFChainPair struct {
	// Send is the sending chain.
	Send *KDFChain
	// Receive is the receiving chain.
	Receive *KDFChain
}
