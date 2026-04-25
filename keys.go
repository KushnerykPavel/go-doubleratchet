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
func InitAlice(sharedSecret []byte, bobRatchetPK [32]byte, cfg *Config) (*Session, error) {
	return InitInitiator(sharedSecret, bobRatchetPK, cfg)
}

// InitBob is an alias for InitResponder.
func InitBob(sharedSecret []byte, bobKeyPair crypto.KeyPair, cfg *Config) (*Session, error) {
	return InitResponder(sharedSecret, bobKeyPair, cfg)
}

// InitAliceHE is an alias for InitInitiatorHE.
func InitAliceHE(sharedSecret []byte, bobRatchetPK, sharedHKA, sharedNHKB [32]byte, cfg *Config) (*HESession, error) {
	return InitInitiatorHE(sharedSecret, bobRatchetPK, sharedHKA, sharedNHKB, cfg)
}

// InitBobHE is an alias for InitResponderHE.
func InitBobHE(sharedSecret []byte, bobKeyPair crypto.KeyPair, sharedHKA, sharedNHKB [32]byte, cfg *Config) (*HESession, error) {
	return InitResponderHE(sharedSecret, bobKeyPair, sharedHKA, sharedNHKB, cfg)
}

// InitAliceSCKA is an alias for InitInitiatorSCKA.
func InitAliceSCKA(sk []byte, sckaProvider scka.Provider, cfg *Config) (*SPQRSession, error) {
	return InitInitiatorSCKA(sk, sckaProvider, cfg)
}

// InitBobSCKA is an alias for InitResponderSCKA.
func InitBobSCKA(sk []byte, sckaProvider scka.Provider, cfg *Config) (*SPQRSession, error) {
	return InitResponderSCKA(sk, sckaProvider, cfg)
}

// InitAliceTripleRatchet is an alias for InitInitiatorTripleRatchet.
func InitAliceTripleRatchet(sharedSecret []byte, bobDRPK [32]byte, sckaProvider scka.Provider, cfg *Config) (*TripleRatchetSession, error) {
	return InitInitiatorTripleRatchet(sharedSecret, bobDRPK, sckaProvider, cfg)
}

// InitBobTripleRatchet is an alias for InitResponderTripleRatchet.
func InitBobTripleRatchet(sharedSecret []byte, bobKeyPair crypto.KeyPair, sckaProvider scka.Provider, cfg *Config) (*TripleRatchetSession, error) {
	return InitResponderTripleRatchet(sharedSecret, bobKeyPair, sckaProvider, cfg)
}
