package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	require.NoError(t, err)
	require.True(t, VerifyPrivateKey(priv))
	require.True(t, VerifyPublicKey(pub))
}

func TestSharedSecretSymmetric(t *testing.T) {
	privA, pubA, err := GenerateKeyPair()
	require.NoError(t, err)
	privB, pubB, err := GenerateKeyPair()
	require.NoError(t, err)

	ssAB, err := SharedSecret(privA, pubB)
	require.NoError(t, err)
	ssBA, err := SharedSecret(privB, pubA)
	require.NoError(t, err)

	require.Equal(t, ssAB, ssBA)
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _, err := GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSharedSecret(b *testing.B) {
	b.ReportAllocs()
	privA, _, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	_, pubB, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		_, err := SharedSecret(privA, pubB)
		if err != nil {
			b.Fatal(err)
		}
	}
}
