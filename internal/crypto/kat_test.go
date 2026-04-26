package crypto

// Known-answer tests (KATs) for the crypto package.
//
// X25519 vectors: BoringSSL-generated, cross-verified against Go's
// golang.org/x/crypto/curve25519 test suite. These prove that SharedSecret
// and PublicKeyFromPrivate produce the correct curve arithmetic.
//
// EncryptHeader/DecryptHeader vectors: frozen regression baseline computed from this
// implementation and cross-verified against a standalone Go script. Any change
// to the cipher suite (KDF labels, padding, MAC construction) will break these
// tests intentionally.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex string or panics; used only in test init.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex in KAT: " + err.Error())
	}
	return b
}

// ----------------------------------------------------------------------------
// X25519 — SharedSecret KATs (BoringSSL vectors, via Go x/crypto test suite)
//
// Format: SharedSecret(scalar, point) == result
// Equivalent to curve25519.X25519(scalar, point).
// ----------------------------------------------------------------------------

var x25519DHVectors = []struct {
	name   string
	scalar string
	point  string
	result string
}{
	{
		name:   "boringssl-1",
		scalar: "668fb9f76ad971c81ac900071a1560bce2ca00cac7e67af99348913761434014",
		point:  "db5f32b7f841e7a1a00968effded12735fc47a3eb13b579aacadeae80939a7dd",
		result: "090d85e599ea8e2beeb61304d37be10ec5c905f9927d32f42a9a0afb3e0b4074",
	},
	{
		name:   "boringssl-2",
		scalar: "636695e34f75b9a279c8706fad1289f2c0b1e22e16f8b8861729c10a582958af",
		point:  "090d0701f8fde28f70043b83f2346225419b18a7f27e9e3d2bfd04e10f3d213e",
		result: "bf26ec7ec413061733d44070ea67cab02a85dc1be8cfe1ff73d541cc08325506",
	},
	{
		name:   "boringssl-3",
		scalar: "734181cd1a9406522a56fe25e43ecbf0295db5ddd0609b3c2b4e79c06f8bd46d",
		point:  "f8a8421c7d21a92db3ede979e1fa6acb062b56b1885c71c51153ccb880ac7315",
		result: "1176d01681f2cf929da2c7a3df66b5d7729fd422226fd6374216bf7e02fd0f62",
	},
}

func TestSharedSecretKnownAnswer(t *testing.T) {
	for _, v := range x25519DHVectors {
		t.Run(v.name, func(t *testing.T) {
			scalarBytes := mustHex(v.scalar)
			pointBytes := mustHex(v.point)
			want := mustHex(v.result)

			var scalar, point [KeySize]byte
			copy(scalar[:], scalarBytes)
			copy(point[:], pointBytes)

			got, err := SharedSecret(scalar, point)
			if err != nil {
				t.Fatalf("SharedSecret error: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("SharedSecret mismatch\ngot:  %x\nwant: %x", got, want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// X25519 — PublicKeyFromPrivate KATs (scalar * basepoint)
//
// These vectors are: PublicKeyFromPrivate(scalar) == curve25519.X25519(scalar, basepoint)
// ----------------------------------------------------------------------------

var x25519BasepointVectors = []struct {
	name   string
	scalar string
	pub    string
}{
	{
		// scalar = BoringSSL vector 1 In
		name:   "boringssl-scalar-1",
		scalar: "668fb9f76ad971c81ac900071a1560bce2ca00cac7e67af99348913761434014",
		pub:    "f7a64b085ad4ab4732187f679aaf8d550b94d5955267fb4e657f4ee114ec251d",
	},
	{
		// scalar = BoringSSL vector 2 In
		name:   "boringssl-scalar-2",
		scalar: "636695e34f75b9a279c8706fad1289f2c0b1e22e16f8b8861729c10a582958af",
		pub:    "bf030f973307a25667abd1284ec0ac88d2e80758eb08516ada0bf1a84b56cb08",
	},
}

func TestPublicKeyFromPrivateKnownAnswer(t *testing.T) {
	for _, v := range x25519BasepointVectors {
		t.Run(v.name, func(t *testing.T) {
			scalarBytes := mustHex(v.scalar)
			want := mustHex(v.pub)

			var priv [KeySize]byte
			copy(priv[:], scalarBytes)

			got, err := PublicKeyFromPrivate(priv)
			if err != nil {
				t.Fatalf("PublicKeyFromPrivate error: %v", err)
			}
			if !bytes.Equal(got[:], want) {
				t.Fatalf("public key mismatch\ngot:  %x\nwant: %x", got, want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// EncryptHeader / DecryptHeader — frozen regression vectors
//
// Derived subkeys (for auditing against independent implementations):
//   key    = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
//   info   = "DoubleRatchetHeaderKey"
//   aesKey = HMAC-SHA256(key, info||"aes")
//          = 8d01661a852e8e3e794e56cda9ddb9847aa1f9dfe85d3bfee22c457792ff8d3d
//   macKey = HMAC-SHA256(key, info||"mac")
//          = 5398e8b2901a2666d1eb7ecf27a8d2b4c4bef9e69bf6c329b7bc40ebae22cb1d
//
// Ciphertext layout: nonce(16) || AES-CBC-ciphertext || HMAC-SHA256-tag(32)
// Nonce layout:      BigEndian(counter, 8 bytes) || 0x00*8
// ----------------------------------------------------------------------------

var hencryptKATKey = [32]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

var hencryptKATVectors = []struct { //nolint:govet // test-vector struct; field order reflects protocol, not alignment
	counter uint64
	name    string
	header  string // hex; empty string = empty plaintext
	ct      string // hex: nonce || ciphertext || tag
}{
	{
		// 4-byte header, counter=0 → nonce all-zeros
		name:    "4byte-header-counter0",
		counter: 0,
		header:  "a1b2c3d4",
		ct:      "00000000000000000000000000000000d150765c13c8cd49ecc56f443041f997fffd1778cd0581c22e74e2176257c6e157b082b23a2e7fe548b383916250116e",
	},
	{
		// 40-byte header, counter=1 → nonce has counter in first 8 bytes
		name:    "40byte-header-counter1",
		counter: 1,
		header:  "dead00000000000000000000000000000000000000000000000000000000000000000000000000ff",
		ct:      "000000000000000100000000000000000969b041cd514caedbac239e4dfbf3ec59ffb87fb0a3066000aba9a2149d82713de47b0311f6ef6f48c9b30ab446e17f2ae940c9b9705ee98470807cc7bc93667c19a264c6d8c4e24877019c0b9ecb98",
	},
	{
		// empty header — exercises all-padding PKCS7 block
		name:    "empty-header-counter0",
		counter: 0,
		header:  "",
		ct:      "000000000000000000000000000000002146e0baa694ba1f8cdc9b9f68dfeb51ffc42019cb16a7c8989b8b4ec8f178702ad414e5d204e4f5343d14ab3d7e3901",
	},
}

func TestEncryptHeaderKnownAnswer(t *testing.T) {
	for _, v := range hencryptKATVectors {
		t.Run(v.name, func(t *testing.T) {
			var header []byte
			if v.header != "" {
				header = mustHex(v.header)
			}
			wantCT := mustHex(v.ct)

			hk := HeaderKey{Key: hencryptKATKey, NonceCounter: v.counter}
			got, err := EncryptHeader(&hk, header)
			if err != nil {
				t.Fatalf("EncryptHeader error: %v", err)
			}
			if !bytes.Equal(got, wantCT) {
				t.Fatalf("EncryptHeader ciphertext mismatch\ngot:  %x\nwant: %x", got, wantCT)
			}
		})
	}
}

func TestDecryptHeaderKnownAnswer(t *testing.T) {
	for _, v := range hencryptKATVectors {
		t.Run(v.name, func(t *testing.T) {
			var wantHeader []byte
			if v.header != "" {
				wantHeader = mustHex(v.header)
			} else {
				wantHeader = []byte{}
			}
			ct := mustHex(v.ct)

			got, ok := DecryptHeader(hencryptKATKey, ct)
			if !ok {
				t.Fatal("DecryptHeader failed on KAT ciphertext")
			}
			if !bytes.Equal(got, wantHeader) {
				t.Fatalf("DecryptHeader plaintext mismatch\ngot:  %x\nwant: %x", got, wantHeader)
			}
		})
	}
}
