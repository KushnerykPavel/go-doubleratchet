package pqxdh_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	doubleratchet "github.com/KushnerykPavel/go-doubleratchet"
	"github.com/KushnerykPavel/go-doubleratchet/pqxdh"
)

type bobKeys struct {
	pqspk pqxdh.KEMSignedPreKey
	spk   pqxdh.SignedPreKey
	ik    pqxdh.IdentityKey
	opk   pqxdh.OneTimePreKey
}

func generateBobKeys(t *testing.T, params pqxdh.KEMParams) bobKeys {
	t.Helper()
	ik, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)
	spk, err := pqxdh.GenerateSPK(ik, 1)
	require.NoError(t, err)
	opk, err := pqxdh.GenerateOPK(1)
	require.NoError(t, err)
	pqspk, err := pqxdh.GenerateKEMSPK(ik, 1, params)
	require.NoError(t, err)
	return bobKeys{ik: ik, spk: spk, opk: opk, pqspk: pqspk}
}

func bundleWithOPK(bob bobKeys) *pqxdh.PrekeyBundle {
	return &pqxdh.PrekeyBundle{
		IdentityKey:       bob.ik.PublicKey,
		SignedPreKey:      bob.spk.PublicKey,
		SPKID:             bob.spk.KeyID,
		SPKSignature:      bob.spk.Signature,
		OneTimePreKey:     &bob.opk.PublicKey,
		OPKID:             &bob.opk.KeyID,
		PQPreKey:          bob.pqspk.EncapsulationKey,
		PQPreKeyID:        bob.pqspk.KeyID,
		PQPreKeySignature: bob.pqspk.Signature,
		PQParams:          bob.pqspk.Params,
	}
}

func bundleWithoutOPK(bob bobKeys) *pqxdh.PrekeyBundle {
	return &pqxdh.PrekeyBundle{
		IdentityKey:       bob.ik.PublicKey,
		SignedPreKey:      bob.spk.PublicKey,
		SPKID:             bob.spk.KeyID,
		SPKSignature:      bob.spk.Signature,
		PQPreKey:          bob.pqspk.EncapsulationKey,
		PQPreKeyID:        bob.pqspk.KeyID,
		PQPreKeySignature: bob.pqspk.Signature,
		PQParams:          bob.pqspk.Params,
	}
}

func TestPQXDH_RoundTrip_WithOPK(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)
	bundle := bundleWithOPK(bob)

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	bobResult, err := pqxdh.ReceiveHandshake(bob.ik, &bob.spk, &bob.opk, bob.pqspk.DecapsKey(), &initMsg)
	require.NoError(t, err)

	require.Equal(t, aliceResult.RootKey, bobResult.RootKey, "RootKey must match")
	require.Equal(t, aliceResult.ChainKey, bobResult.ChainKey, "ChainKey must match")
	require.Equal(t, aliceResult.PQRKey, bobResult.PQRKey, "PQRKey must match")
	require.True(t, bytes.Equal(aliceResult.AD, bobResult.AD), "AD must match")
}

func TestPQXDH_RoundTrip_WithoutOPK(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)
	bundle := bundleWithoutOPK(bob)

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	bobResult, err := pqxdh.ReceiveHandshake(bob.ik, &bob.spk, nil, bob.pqspk.DecapsKey(), &initMsg)
	require.NoError(t, err)

	require.Equal(t, aliceResult.RootKey, bobResult.RootKey, "RootKey must match without OPK")
	require.Equal(t, aliceResult.ChainKey, bobResult.ChainKey, "ChainKey must match without OPK")
	require.Equal(t, aliceResult.PQRKey, bobResult.PQRKey, "PQRKey must match without OPK")
	require.True(t, bytes.Equal(aliceResult.AD, bobResult.AD), "AD must match without OPK")
}

func TestPQXDH_InvalidSPKSignature(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)

	for i := range 64 {
		badSig := bob.spk.Signature
		badSig[i] ^= 0x01

		bundle := &pqxdh.PrekeyBundle{
			IdentityKey:       bob.ik.PublicKey,
			SignedPreKey:      bob.spk.PublicKey,
			SPKID:             bob.spk.KeyID,
			SPKSignature:      badSig,
			PQPreKey:          bob.pqspk.EncapsulationKey,
			PQPreKeyID:        bob.pqspk.KeyID,
			PQPreKeySignature: bob.pqspk.Signature,
			PQParams:          bob.pqspk.Params,
		}

		aliceIK, err := pqxdh.GenerateIdentityKey()
		require.NoError(t, err)
		_, _, err = pqxdh.SendHandshake(aliceIK, bundle)
		require.ErrorIs(t, err, pqxdh.ErrInvalidSPKSignature, "byte %d: expected SPK signature failure", i)
	}
}

func TestPQXDH_InvalidPQSignature(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)

	for i := range 64 {
		badSig := bob.pqspk.Signature
		badSig[i] ^= 0x01

		bundle := &pqxdh.PrekeyBundle{
			IdentityKey:       bob.ik.PublicKey,
			SignedPreKey:      bob.spk.PublicKey,
			SPKID:             bob.spk.KeyID,
			SPKSignature:      bob.spk.Signature,
			PQPreKey:          bob.pqspk.EncapsulationKey,
			PQPreKeyID:        bob.pqspk.KeyID,
			PQPreKeySignature: badSig,
			PQParams:          bob.pqspk.Params,
		}

		aliceIK, err := pqxdh.GenerateIdentityKey()
		require.NoError(t, err)
		_, _, err = pqxdh.SendHandshake(aliceIK, bundle)
		require.ErrorIs(t, err, pqxdh.ErrInvalidPQPreKeySignature, "byte %d: expected PQ signature failure", i)
	}
}

func TestPQXDH_WrongKEMKey_SKMismatch(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)
	bundle := bundleWithoutOPK(bob)

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	// Bob uses a different KEM seed (wrong key, same params).
	wrongPQSPK, err := pqxdh.GenerateKEMSPK(bob.ik, 99, pqxdh.MLKEM1024)
	require.NoError(t, err)

	bobResult, err := pqxdh.ReceiveHandshake(bob.ik, &bob.spk, nil, wrongPQSPK.DecapsKey(), &initMsg)
	// ML-KEM is IND-CCA2 — decapsulation always produces output, but SK will differ.
	require.NoError(t, err)
	require.NotEqual(t, aliceResult.RootKey, bobResult.RootKey, "RootKey must NOT match with wrong KEM key")
}

func TestPQXDH_KEMParamsMismatch_ReturnsError(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)
	bundle := bundleWithoutOPK(bob)

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	_, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	// Bob tries to decapsulate with a MLKEM768 key but the message says MLKEM1024.
	wrongParamKey := pqxdh.KEMPreKey{Seed: bob.pqspk.Seed, Params: pqxdh.MLKEM768}
	_, err = pqxdh.ReceiveHandshake(bob.ik, &bob.spk, nil, wrongParamKey, &initMsg)
	require.Error(t, err, "params mismatch must return error")
}

func TestPQXDH_WrongSPKPrivKey_SKMismatch(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)
	bundle := bundleWithoutOPK(bob)

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)
	aliceResult, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	// Bob uses a different (wrong) SPK private key.
	wrongSPK, err := pqxdh.GenerateSPK(bob.ik, 99)
	require.NoError(t, err)

	bobResult, err := pqxdh.ReceiveHandshake(bob.ik, &wrongSPK, nil, bob.pqspk.DecapsKey(), &initMsg)
	require.NoError(t, err)
	require.NotEqual(t, aliceResult.RootKey, bobResult.RootKey, "RootKey must NOT match with wrong SPK")
}

func TestPQXDH_MissingOPK_ReturnsError(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)
	bundle := bundleWithOPK(bob) // OPK present → OPKID set in initMsg

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	_, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)
	require.NotNil(t, initMsg.OPKID, "OPKID must be set when OPK is in bundle")

	// Bob does not supply the OPK — should fail.
	_, err = pqxdh.ReceiveHandshake(bob.ik, &bob.spk, nil, bob.pqspk.DecapsKey(), &initMsg)
	require.Error(t, err, "missing OPK must return error")
}

func TestPQXDH_MLKEM768(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM768)
	bundle := bundleWithOPK(bob)

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	bobResult, err := pqxdh.ReceiveHandshake(bob.ik, &bob.spk, &bob.opk, bob.pqspk.DecapsKey(), &initMsg)
	require.NoError(t, err)

	require.Equal(t, aliceResult.RootKey, bobResult.RootKey, "ML-KEM-768: RootKey must match")
	require.Equal(t, aliceResult.ChainKey, bobResult.ChainKey, "ML-KEM-768: ChainKey must match")
	require.Equal(t, aliceResult.PQRKey, bobResult.PQRKey, "ML-KEM-768: PQRKey must match")
}

func TestPQXDH_MLKEM1024(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)
	bundle := bundleWithOPK(bob)

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	bobResult, err := pqxdh.ReceiveHandshake(bob.ik, &bob.spk, &bob.opk, bob.pqspk.DecapsKey(), &initMsg)
	require.NoError(t, err)

	require.Equal(t, aliceResult.RootKey, bobResult.RootKey, "ML-KEM-1024: RootKey must match")
	require.Equal(t, aliceResult.ChainKey, bobResult.ChainKey, "ML-KEM-1024: ChainKey must match")
	require.Equal(t, aliceResult.PQRKey, bobResult.PQRKey, "ML-KEM-1024: PQRKey must match")
}

func TestPQXDH_XEdDSA_SignVerify(t *testing.T) {
	for range 50 {
		ik, err := pqxdh.GenerateIdentityKey()
		require.NoError(t, err)
		spk, err := pqxdh.GenerateSPK(ik, 0)
		require.NoError(t, err)
		pqspk, err := pqxdh.GenerateKEMSPK(ik, 0, pqxdh.MLKEM1024)
		require.NoError(t, err)

		bundle := &pqxdh.PrekeyBundle{
			IdentityKey:       ik.PublicKey,
			SignedPreKey:      spk.PublicKey,
			SPKID:             spk.KeyID,
			SPKSignature:      spk.Signature,
			PQPreKey:          pqspk.EncapsulationKey,
			PQPreKeyID:        pqspk.KeyID,
			PQPreKeySignature: pqspk.Signature,
			PQParams:          pqspk.Params,
		}

		aliceIK, err := pqxdh.GenerateIdentityKey()
		require.NoError(t, err)
		_, _, err = pqxdh.SendHandshake(aliceIK, bundle)
		require.NoError(t, err, "XEdDSA sign/verify roundtrip failed")
	}
}

func TestPQXDH_KEMOneTimePreKey(t *testing.T) {
	bobIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)
	bobSPK, err := pqxdh.GenerateSPK(bobIK, 1)
	require.NoError(t, err)

	// Use a one-time KEM prekey instead of last-resort.
	pqopk, err := pqxdh.GenerateKEMOPK(bobIK, 42, pqxdh.MLKEM1024)
	require.NoError(t, err)

	bundle := &pqxdh.PrekeyBundle{
		IdentityKey:       bobIK.PublicKey,
		SignedPreKey:      bobSPK.PublicKey,
		SPKID:             bobSPK.KeyID,
		SPKSignature:      bobSPK.Signature,
		PQPreKey:          pqopk.EncapsulationKey,
		PQPreKeyID:        pqopk.KeyID,
		PQPreKeySignature: pqopk.Signature,
		PQParams:          pqopk.Params,
	}

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)

	bobResult, err := pqxdh.ReceiveHandshake(bobIK, &bobSPK, nil, pqopk.DecapsKey(), &initMsg)
	require.NoError(t, err)

	require.Equal(t, aliceResult.RootKey, bobResult.RootKey)
	require.Equal(t, aliceResult.ChainKey, bobResult.ChainKey)
	require.Equal(t, aliceResult.PQRKey, bobResult.PQRKey)
}

func TestPQXDH_IntegrationWithDoubleRatchet(t *testing.T) {
	bob := generateBobKeys(t, pqxdh.MLKEM1024)
	bundle := bundleWithOPK(bob)

	aliceIK, err := pqxdh.GenerateIdentityKey()
	require.NoError(t, err)

	aliceResult, initMsg, err := pqxdh.SendHandshake(aliceIK, bundle)
	require.NoError(t, err)
	bobResult, err := pqxdh.ReceiveHandshake(bob.ik, &bob.spk, &bob.opk, bob.pqspk.DecapsKey(), &initMsg)
	require.NoError(t, err)
	require.Equal(t, aliceResult.RootKey, bobResult.RootKey)

	// Bob's SPK is his initial DR ratchet key pair (Signal convention).
	bobRatchetKP := doubleratchet.KeyPair{
		PrivateKey: bob.spk.PrivateKey,
		PublicKey:  bob.spk.PublicKey,
	}

	// Initialize DR sessions with the PQXDH root key.
	aliceSess, err := doubleratchet.InitAlice(aliceResult.RootKey[:], bob.spk.PublicKey, nil)
	require.NoError(t, err)
	defer aliceSess.Close()

	bobSess, err := doubleratchet.InitBob(bobResult.RootKey[:], bobRatchetKP, nil)
	require.NoError(t, err)
	defer bobSess.Close()

	ad := aliceResult.AD

	// Alice → Bob.
	msg, err := aliceSess.Encrypt([]byte("hello from alice via PQXDH"), ad)
	require.NoError(t, err)
	plaintext, err := bobSess.Decrypt(msg, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hello from alice via PQXDH"), plaintext)

	// Bob → Alice.
	reply, err := bobSess.Encrypt([]byte("hi alice, post-quantum!"), ad)
	require.NoError(t, err)
	replyPT, err := aliceSess.Decrypt(reply, ad)
	require.NoError(t, err)
	require.Equal(t, []byte("hi alice, post-quantum!"), replyPT)
}
