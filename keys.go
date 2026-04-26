package doubleratchet

import (
	"github.com/KushnerykPavel/go-doubleratchet/internal/crypto"
	"github.com/KushnerykPavel/go-doubleratchet/scka"
)

// KeyPair represents an X25519 key pair used for the Double Ratchet.
// Use GenerateKeyPair to create one.
type KeyPair = crypto.KeyPair

// GenerateKeyPair generates a new X25519 key pair for use with InitBob,
// InitBobHE, and InitBobTripleRatchet.
func GenerateKeyPair() (privateKey, publicKey [32]byte, err error) {
	return crypto.GenerateKeyPair()
}

// InitAlice is an alias for InitInitiator.
// Follows Signal spec naming where Alice is the initiator.
func InitAlice(sharedSecret []byte, bobRatchetPK [32]byte, cfg *Config) (*Session, error) {
	return InitInitiator(sharedSecret, bobRatchetPK, cfg)
}

// InitBob is an alias for InitResponder.
// Follows Signal spec naming where Bob is the responder.
func InitBob(sharedSecret []byte, bobKeyPair crypto.KeyPair, cfg *Config) (*Session, error) {
	return InitResponder(sharedSecret, bobKeyPair, cfg)
}

// InitAliceHE is an alias for InitInitiatorHE.
// Follows Signal spec naming where Alice is the initiator.
func InitAliceHE(sharedSecret []byte, bobRatchetPK, sharedHKA, sharedNHKB [32]byte, cfg *Config) (*HESession, error) {
	return InitInitiatorHE(sharedSecret, bobRatchetPK, sharedHKA, sharedNHKB, cfg)
}

// InitBobHE is an alias for InitResponderHE.
//
// Follows Signal spec naming where Bob is the responder.
func InitBobHE(sharedSecret []byte, bobKeyPair crypto.KeyPair, sharedHKA, sharedNHKB [32]byte, cfg *Config) (*HESession, error) {
	return InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, cfg)
}

// InitAliceSCKA is an alias for InitInitiatorSCKA.
//
// Follows Signal spec naming where Alice is the initiator.
func InitAliceSCKA(sk []byte, sckaProvider scka.Provider, cfg *Config) (*SPQRSession, error) {
	return InitInitiatorSCKA(sk, sckaProvider, cfg)
}

// InitBobSCKA is an alias for InitResponderSCKA.
//
// Follows Signal spec naming where Bob is the responder.
func InitBobSCKA(sk []byte, sckaProvider scka.Provider, cfg *Config) (*SPQRSession, error) {
	return InitResponderSCKA(sk, sckaProvider, cfg)
}

// InitAliceTripleRatchet is an alias for InitInitiatorTripleRatchet.
//
// Follows Signal spec naming where Alice is the initiator.
func InitAliceTripleRatchet(sharedSecret []byte, bobDRPK [32]byte, sckaProvider scka.Provider, cfg *Config) (*TripleRatchetSession, error) {
	return InitInitiatorTripleRatchet(sharedSecret, bobDRPK, sckaProvider, cfg)
}

// InitBobTripleRatchet is an alias for InitResponderTripleRatchet.
//
// Deprecated: Use InitResponderTripleRatchet instead.
func InitBobTripleRatchet(sharedSecret []byte, bobKeyPair crypto.KeyPair, sckaProvider scka.Provider, cfg *Config) (*TripleRatchetSession, error) {
	return InitResponderTripleRatchet(sharedSecret, bobKeyPair, sckaProvider, cfg)
}
