package x3dh_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	doubleratchet "github.com/KushnerykPavel/go-doubleratchet"
	"github.com/KushnerykPavel/go-doubleratchet/x3dh"
)

// bobKeys bundles the key material Bob needs for tests.
type bobKeys struct {
	ik  x3dh.IdentityKey
	spk x3dh.SignedPreKey
	opk x3dh.OneTimePreKey
}

func generateBobKeys(t *testing.T) bobKeys {
	t.Helper()
	ik, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)
	spk, err := x3dh.GenerateSPK(ik, 1)
	require.NoError(t, err)
	opk, err := x3dh.GenerateOPK(1)
	require.NoError(t, err)
	return bobKeys{ik: ik, spk: spk, opk: opk}
}

func TestX3DH_RoundTrip_WithOPK(t *testing.T) {
	bob := generateBobKeys(t)
	bundle := &x3dh.PrekeyBundle{
		IdentityKey:   bob.ik.PublicKey,
		SignedPreKey:  bob.spk.PublicKey,
		SPKID:         bob.spk.KeyID,
		SPKSignature:  bob.spk.Signature,
		OneTimePreKey: &bob.opk.PublicKey,
		OPKID:         &bob.opk.KeyID,
	}

	aliceIK, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := x3dh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	bobResult, err := x3dh.ReceiveHandshake(bob.ik, &bob.spk, &bob.opk, initMsg)
	require.NoError(t, err)

	require.Equal(t, aliceResult.SharedSecret, bobResult.SharedSecret, "SK must match")
	require.True(t, bytes.Equal(aliceResult.AD, bobResult.AD), "AD must match")
}

func TestX3DH_RoundTrip_WithoutOPK(t *testing.T) {
	bobIK, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)
	bobSPK, err := x3dh.GenerateSPK(bobIK, 2)
	require.NoError(t, err)

	bundle := &x3dh.PrekeyBundle{
		IdentityKey:  bobIK.PublicKey,
		SignedPreKey: bobSPK.PublicKey,
		SPKID:        bobSPK.KeyID,
		SPKSignature: bobSPK.Signature,
		// No OPK
	}

	aliceIK, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := x3dh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	bobResult, err := x3dh.ReceiveHandshake(bobIK, &bobSPK, nil, initMsg)
	require.NoError(t, err)

	require.Equal(t, aliceResult.SharedSecret, bobResult.SharedSecret, "SK must match without OPK")
	require.True(t, bytes.Equal(aliceResult.AD, bobResult.AD), "AD must match without OPK")
}

func TestX3DH_InvalidSPKSignature(t *testing.T) {
	bobIK, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)
	bobSPK, err := x3dh.GenerateSPK(bobIK, 1)
	require.NoError(t, err)

	// Corrupt every byte of the signature; each must trigger a verification failure.
	for i := range 64 {
		badSig := bobSPK.Signature
		badSig[i] ^= 0x01

		bundle := &x3dh.PrekeyBundle{
			IdentityKey:  bobIK.PublicKey,
			SignedPreKey: bobSPK.PublicKey,
			SPKID:        bobSPK.KeyID,
			SPKSignature: badSig,
		}

		aliceIK, err := x3dh.GenerateIdentityKey()
		require.NoError(t, err)
		_, _, err = x3dh.SendHandshake(aliceIK, bundle)
		require.ErrorIs(t, err, x3dh.ErrInvalidSPKSignature, "byte %d: expected signature failure", i)
	}
}

func TestX3DH_WrongSPKPrivKey_SKMismatch(t *testing.T) {
	bobIK, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)
	bobSPK, err := x3dh.GenerateSPK(bobIK, 1)
	require.NoError(t, err)

	bundle := &x3dh.PrekeyBundle{
		IdentityKey:  bobIK.PublicKey,
		SignedPreKey: bobSPK.PublicKey,
		SPKID:        bobSPK.KeyID,
		SPKSignature: bobSPK.Signature,
	}

	aliceIK, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)
	aliceResult, initMsg, err := x3dh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	// Bob uses a different (wrong) SPK private key.
	wrongSPK, err := x3dh.GenerateSPK(bobIK, 99)
	require.NoError(t, err)

	bobResult, err := x3dh.ReceiveHandshake(bobIK, &wrongSPK, nil, initMsg)
	require.NoError(t, err) // No error — Bob can compute, but SK will differ.

	require.NotEqual(t, aliceResult.SharedSecret, bobResult.SharedSecret, "SK must NOT match with wrong SPK")
}

func TestX3DH_XEdDSA_SignVerify(t *testing.T) {
	// Verify that GenerateSPK produces a valid XEdDSA signature by running
	// 50 random key pairs through sign-and-verify.
	for range 50 {
		ik, err := x3dh.GenerateIdentityKey()
		require.NoError(t, err)
		spk, err := x3dh.GenerateSPK(ik, 0)
		require.NoError(t, err)

		// The handshake internally calls xeddsaVerify; a successful SendHandshake
		// proves sign→verify roundtrip.
		bundle := &x3dh.PrekeyBundle{
			IdentityKey:  ik.PublicKey,
			SignedPreKey: spk.PublicKey,
			SPKID:        spk.KeyID,
			SPKSignature: spk.Signature,
		}
		aliceIK, err := x3dh.GenerateIdentityKey()
		require.NoError(t, err)
		_, _, err = x3dh.SendHandshake(aliceIK, bundle)
		require.NoError(t, err, "XEdDSA sign/verify roundtrip failed")
	}
}

func TestX3DH_IntegrationWithDoubleRatchet(t *testing.T) {
	// Full Signal Protocol flow: X3DH → Double Ratchet encrypt/decrypt.
	//
	// The SPK serves as Bob's initial DR ratchet key pair, which is the
	// standard practice in the Signal Protocol.

	bobIK, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)
	bobSPK, err := x3dh.GenerateSPK(bobIK, 1)
	require.NoError(t, err)
	bobOPK, err := x3dh.GenerateOPK(1)
	require.NoError(t, err)

	bundle := &x3dh.PrekeyBundle{
		IdentityKey:   bobIK.PublicKey,
		SignedPreKey:  bobSPK.PublicKey,
		SPKID:         bobSPK.KeyID,
		SPKSignature:  bobSPK.Signature,
		OneTimePreKey: &bobOPK.PublicKey,
		OPKID:         &bobOPK.KeyID,
	}

	aliceIK, err := x3dh.GenerateIdentityKey()
	require.NoError(t, err)

	// X3DH handshake.
	aliceResult, initMsg, err := x3dh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)
	bobResult, err := x3dh.ReceiveHandshake(bobIK, &bobSPK, &bobOPK, initMsg)
	require.NoError(t, err)
	require.Equal(t, aliceResult.SharedSecret, bobResult.SharedSecret)

	// Bob's SPK is also his initial DR ratchet key pair (Signal convention).
	bobRatchetKP := doubleratchet.KeyPair{
		PrivateKey: bobSPK.PrivateKey,
		PublicKey:  bobSPK.PublicKey,
	}

	// Initialize DR sessions with the X3DH shared secret.
	aliceSess, err := doubleratchet.InitAlice(aliceResult.SharedSecret[:], bobSPK.PublicKey, nil)
	require.NoError(t, err)
	defer aliceSess.Close()

	bobSess, err := doubleratchet.InitBob(bobResult.SharedSecret[:], bobRatchetKP, nil)
	require.NoError(t, err)
	defer bobSess.Close()

	ad := aliceResult.AD // IKA_pub ‖ IKB_pub

	// Alice → Bob.
	msg, err := aliceSess.Encrypt([]byte("hello from alice"), ad)
	require.NoError(t, err)
	plaintext, err := bobSess.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello from alice"), plaintext)

	// Bob → Alice (triggers DH ratchet on both sides).
	reply, err := bobSess.Encrypt([]byte("hi alice!"), ad)
	require.NoError(t, err)
	replyPT, err := aliceSess.Decrypt(reply, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hi alice!"), replyPT)
}
